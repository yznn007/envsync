//! 基于 Git 远端的后端实现。
//!
//! ## 为什么把 EnvSync 的对象放进 Git tree
//!
//! Git 远端（GitHub、GitLab、Gitea、裸仓库）已经提供了 EnvSync 需要的两样东西：内容寻址
//! 的对象存储，以及**服务端强制的 fast-forward 检查**。后者正是 CAS 发布所需要的原子性。
//! 因此本实现不发明新协议，只把 [`LocalBackend`](crate::LocalBackend) 的磁盘布局原样映射
//! 进一棵 Git tree：
//!
//! ```text
//! .envsync/
//!   format                          # "envsync-git-format=1\n"
//!   objects/ab/cdef….blob           # 与 LocalBackend 逐字节相同的对象内容
//!   refs/<workspace-uuid>.cbor      # canonical CBOR 编码的 WorkspaceRef
//! ```
//!
//! 对象文件名保留 `.<种类>` 扩展名，理由与本地后端一致：`ObjectId` = 种类 + 摘要，而摘要
//! 本身不携带种类，扩展名让 [`GitBackend::list_objects`] 能还原完整标识。扩展名只是路径层
//! 元数据，**不参与摘要计算**，所以同一份内容在 Local 与 Git 后端之间可以直接搬运。
//!
//! ## 写入流程
//!
//! 每次写入都是「fetch → 在内存 index 上构造新 tree → commit → 非 force push」：
//!
//! 1. 从**受信的**远端分支（配置里的那一个，不是 `HEAD`，也不是别的分支）取回当前提交；
//! 2. 以该提交的 tree 为基线，在一棵内存 index 上放入新内容；
//! 3. 用固定身份与固定时间戳提交（见下）；
//! 4. 以 `<local-oid>:refs/heads/<branch>` push，**没有前导 `+`**，也就是永远不 force。
//!
//! ## 提交是确定性的
//!
//! author 与 committer 固定为 `EnvSync <envsync@localhost>`，时间戳固定为 Unix 纪元
//! （`0`，时区偏移 `0`）。于是「相同父提交 + 相同 tree + 相同 message」必然产生相同的
//! commit OID。这带来两个实际好处：重放同一次发布不会污染历史；不同设备算出的提交可以
//! 逐字节比对。代价是 `git log` 的时间列没有意义——发布时间本来就记录在 EnvSync 自己的
//! journal 里，Git 提交时间只会泄漏用户的作息，不记为好。
//!
//! ## 提交信息不含任何本机信息
//!
//! Ref 提交的 message 只有工作区 UUID、revision 和 Snapshot ID；对象提交只有一个计数。
//! 没有路径、没有主机名、没有用户名、没有凭据。

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use envsync_domain::{CborCodec, ObjectId, WorkspaceId, WorkspaceRef};
use git2::{
    AutotagOption, Commit, Cred, CredentialType, ErrorCode, FetchOptions, FetchPrune, Index,
    IndexEntry, IndexTime, Oid, PushOptions, RemoteCallbacks, Repository, Signature, Time, Tree,
};

use crate::git_auth::{redacted_remote, remote_host, scrub, validate_remote_url, GitAuth};
use crate::local::{escape_marker, is_lower_hex, parse_object_name, validate_prefix};
use crate::{Backend, BackendDescriptor, BackendError};

/// Git 布局的格式标记文件内容。
///
/// 打开后端时逐字节比较；不一致一律拒绝，绝不静默升级或降级。它与本地后端的标记**故意
/// 不同**：两种布局虽然对象字节相同，但目录结构和一致性保证不同，混用必须被发现。
pub const FORMAT_MARKER: &str = "envsync-git-format=1\n";

/// 未显式配置时使用的分支名。
pub const DEFAULT_BRANCH: &str = "envsync";

/// EnvSync 数据在 Git tree 中的根目录。
const ROOT_DIR: &str = ".envsync";
/// 格式标记在 tree 中的路径。
const FORMAT_PATH: &str = ".envsync/format";
/// 对象目录在 tree 中的路径。
const OBJECTS_DIR: &str = ".envsync/objects";
/// Ref 目录在 tree 中的路径。
const REFS_DIR: &str = ".envsync/refs";
/// tree 路径长度上限。
const MAX_TREE_PATH_LEN: usize = 512;
/// 分支名长度上限。
const MAX_BRANCH_LEN: usize = 255;

/// 提交署名，固定不变，不含任何用户信息。
const COMMIT_AUTHOR_NAME: &str = "EnvSync";
/// 提交邮箱，固定不变，不解析本机主机名。
const COMMIT_AUTHOR_EMAIL: &str = "envsync@localhost";

/// 对象推送在遇到并发竞争时的最大重试次数。
///
/// 对象写入是可交换的（内容寻址，谁先写都一样），因此被抢先时重试是安全的；Ref 的 CAS
/// **绝不**重试，冲突必须原样报告给调用方。
const MAX_OBJECT_PUSH_ATTEMPTS: u32 = 8;

/// 私有 cache clone 中远端分支的镜像位置。
///
/// 用 `refs/remotes/envsync/…` 而不是 `refs/heads/…`，是为了让「远端说了什么」和「我们
/// 本地造了什么」在仓库里一眼可分。
const TRACKING_PREFIX: &str = "refs/remotes/envsync";

/// Git 后端配置。
///
/// 该结构会被写入配置文件并出现在诊断输出里，因此它的 `Debug` 实现是**手写**的：远端 URL
/// 经过脱敏，cache 目录（绝对路径，属于本机信息）不打印。
#[derive(Clone)]
pub struct GitConfig {
    /// 远端 URL。必须通过
    /// [`validate_remote_url`](crate::git_auth::validate_remote_url)：不能含 userinfo，
    /// 也不能带查询串。
    pub remote_url: String,
    /// EnvSync 使用的分支名，默认 [`DEFAULT_BRANCH`]。
    ///
    /// 只有这一个分支是**受信来源**：读取和 CAS 都只看它，远端 `HEAD` 指向哪里无关紧要。
    pub branch: String,
    /// 私有 cache clone 的位置。
    ///
    /// 这是一个 bare 仓库，只有 EnvSync 使用；在 Unix 上会被设为 `0700`。
    pub cache_dir: PathBuf,
    /// 认证方式。
    pub auth: GitAuth,
}

impl GitConfig {
    /// 用默认分支构造配置。
    pub fn new(
        remote_url: impl Into<String>,
        cache_dir: impl Into<PathBuf>,
        auth: GitAuth,
    ) -> Self {
        GitConfig {
            remote_url: remote_url.into(),
            branch: DEFAULT_BRANCH.to_owned(),
            cache_dir: cache_dir.into(),
            auth,
        }
    }

    /// 覆盖分支名。
    pub fn with_branch(mut self, branch: impl Into<String>) -> Self {
        self.branch = branch.into();
        self
    }
}

impl std::fmt::Debug for GitConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitConfig")
            .field("remote_url", &redacted_remote(&self.remote_url))
            .field("branch", &self.branch)
            .field("cache_dir", &"<private>")
            .field("auth", &self.auth)
            .finish()
    }
}

/// 私有 cache clone 的可变状态。
struct Cache {
    /// bare 仓库句柄。
    repo: Repository,
    /// 最近一次已知的远端分支提交；`None` 表示远端还没有这个分支。
    head: Option<Oid>,
}

/// 一次 push 的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PushOutcome {
    /// 远端接受了这次更新。
    Accepted,
    /// 远端以「非 fast-forward」为由拒绝：期间有别人推进了分支。
    NonFastForward,
}

/// 待写入 Git tree 的一条内容。
struct Entry {
    /// tree 内路径，必须通过 [`validate_tree_path`]。
    path: String,
    /// 文件内容。
    bytes: Vec<u8>,
}

/// 基于 Git 远端的后端。
///
/// 通过一个私有的 bare cache clone 与远端交互；所有读写都以配置的分支为唯一受信来源。
///
/// # 并发与线程安全
///
/// [`git2::Repository`] 不是 `Sync`，因此内部用 `Mutex` 串行化。这同时把「fetch → 构造
/// commit → push」变成进程内的临界区，避免同一进程的两个线程互相制造无谓的 CAS 冲突。
pub struct GitBackend {
    /// 后端配置。
    config: GitConfig,
    /// 私有 cache clone。
    cache: Mutex<Cache>,
}

impl std::fmt::Debug for GitBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitBackend")
            .field("remote", &redacted_remote(&self.config.remote_url))
            .field("branch", &self.config.branch)
            .finish()
    }
}

impl GitBackend {
    /// 打开（必要时初始化）一个 Git 后端。
    ///
    /// 步骤：校验配置 → 准备私有 cache clone → 从远端分支取回当前状态 → 校验格式标记。
    /// 远端还不存在该分支时视为「空后端」，第一次写入会连同格式标记一起创建它。
    ///
    /// # 错误
    ///
    /// * [`BackendError::Unsupported`]：URL、分支名或认证配置不合法；
    /// * [`BackendError::FormatMismatch`]：远端分支上的格式标记与本实现不符（包括分支
    ///   存在但根本不是 EnvSync 布局的情况）；
    /// * [`BackendError::Io`]：cache 目录不可用，或与远端通信失败。
    pub fn open(config: GitConfig) -> Result<Self, BackendError> {
        validate_remote_url(&config.remote_url)?;
        validate_branch(&config.branch)?;
        config.auth.validate()?;

        let repo = open_cache_repo(&config.cache_dir)?;
        let backend = GitBackend {
            config,
            cache: Mutex::new(Cache { repo, head: None }),
        };
        {
            let mut cache = backend.locked();
            backend.refresh(&mut cache)?;
            backend.verify_format(&cache)?;
        }
        tracing::debug!(
            host = %remote_host(&backend.config.remote_url),
            branch = %backend.config.branch,
            "已打开 Git 后端"
        );
        Ok(backend)
    }

    /// 取得 cache 的独占访问。
    ///
    /// 锁中毒说明某个线程在持锁时 panic 了。cache 只是远端状态的镜像，没有需要维护的
    /// 不变量（真正的权威在远端），因此直接接管内容继续用，比让整个后端不可用更合理。
    fn locked(&self) -> MutexGuard<'_, Cache> {
        self.cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// 远端分支的完整 ref 名。
    fn branch_ref(&self) -> String {
        format!("refs/heads/{}", self.config.branch)
    }

    /// 本地镜像 ref 名。
    fn tracking_ref(&self) -> String {
        format!("{TRACKING_PREFIX}/{}", self.config.branch)
    }

    /// 构造带认证回调的 remote callbacks。
    fn callbacks(&self) -> RemoteCallbacks<'static> {
        let auth = self.config.auth.clone();
        let mut callbacks = RemoteCallbacks::new();
        callbacks
            .credentials(move |url, username, allowed| credential(&auth, url, username, allowed));
        callbacks
    }

    /// 把 git2 错误转成不泄漏凭据的 [`BackendError::Io`]。
    ///
    /// context 只包含操作名、远端 host 和分支名；底层错误文本先过一遍
    /// [`scrub`](crate::git_auth::scrub)。
    fn git_error(&self, operation: &str, err: &git2::Error) -> BackendError {
        BackendError::Io {
            context: format!(
                "git {operation}（host={}, branch={}）",
                remote_host(&self.config.remote_url),
                self.config.branch
            ),
            source: io::Error::other(scrub(err.message())),
        }
    }

    /// 从远端刷新 cache。
    ///
    /// 只取受信分支这一条 refspec，并打开 prune：远端分支被删除时本地镜像随之消失，
    /// 于是 `head` 归零。**绝不**用陈旧镜像冒充远端状态——那会让 CAS 基于过期 revision
    /// 做判断。
    fn refresh(&self, cache: &mut Cache) -> Result<(), BackendError> {
        self.fetch_branch(&cache.repo)?;
        cache.head = match cache.repo.refname_to_id(&self.tracking_ref()) {
            Ok(oid) => Some(oid),
            // 远端还没有这个分支（或刚被删除）：视为空后端。
            Err(err) if err.code() == ErrorCode::NotFound => None,
            Err(err) => return Err(self.git_error("read tracking ref", &err)),
        };
        Ok(())
    }

    /// 把受信分支下载到本地镜像 ref。
    ///
    /// 远端没有该分支时 fetch 正常返回，只是镜像 ref 不会被创建——调用方据此判断「空后端」。
    fn fetch_branch(&self, repo: &Repository) -> Result<(), BackendError> {
        // 匿名 remote：URL 不会被写进仓库 config，凭据相关配置也就不会落盘。
        let mut remote = repo
            .remote_anonymous(&self.config.remote_url)
            .map_err(|err| self.git_error("open remote", &err))?;
        let mut options = FetchOptions::new();
        options.remote_callbacks(self.callbacks());
        // 只要这一个分支：不下载 tag，也不碰远端的其他分支。
        options.download_tags(AutotagOption::None);
        // prune 让「远端分支被删除」立刻反映到本地，而不是留下一个骗人的旧镜像。
        options.prune(FetchPrune::On);
        let refspec = format!("+{}:{}", self.branch_ref(), self.tracking_ref());
        remote
            .fetch(&[refspec], Some(&mut options), None)
            .map_err(|err| self.git_error("fetch", &err))?;
        tracing::trace!(
            host = %remote_host(&self.config.remote_url),
            branch = %self.config.branch,
            "已从远端分支取回更新"
        );
        Ok(())
    }

    /// 校验远端分支上的格式标记。
    ///
    /// 远端还没有该分支时视为空后端，直接通过：第一次写入会创建标记。
    fn verify_format(&self, cache: &Cache) -> Result<(), BackendError> {
        if cache.head.is_none() {
            return Ok(());
        }
        let found = self.read_blob(cache, FORMAT_PATH)?;
        match found {
            Some(bytes) if bytes == FORMAT_MARKER.as_bytes() => Ok(()),
            Some(bytes) => Err(BackendError::FormatMismatch {
                expected: escape_marker(FORMAT_MARKER),
                found: escape_marker(&String::from_utf8_lossy(&bytes)),
            }),
            // 分支存在却没有标记：这是别人的分支，绝不在上面追加提交。
            None => Err(BackendError::FormatMismatch {
                expected: escape_marker(FORMAT_MARKER),
                found: String::new(),
            }),
        }
    }

    /// 从当前 head 的 tree 中读取一个文件；不存在返回 `Ok(None)`。
    fn read_blob(&self, cache: &Cache, path: &str) -> Result<Option<Vec<u8>>, BackendError> {
        let Some(head) = cache.head else {
            return Ok(None);
        };
        let repo = &cache.repo;
        let tree = self.head_tree(repo, head)?;
        let entry = match tree.get_path(Path::new(path)) {
            Ok(entry) => entry,
            Err(err) if err.code() == ErrorCode::NotFound => return Ok(None),
            Err(err) => return Err(self.git_error("read tree entry", &err)),
        };
        let object = entry
            .to_object(repo)
            .map_err(|err| self.git_error("read blob", &err))?;
        match object.as_blob() {
            Some(blob) => Ok(Some(blob.content().to_vec())),
            // 该路径在远端被换成了目录或 submodule：布局已被破坏，不猜测语义。
            None => Err(BackendError::Unsupported(
                "远端布局非法：EnvSync 路径下出现了非文件对象",
            )),
        }
    }

    /// 取出 head 提交的 tree。
    fn head_tree<'repo>(
        &self,
        repo: &'repo Repository,
        head: Oid,
    ) -> Result<Tree<'repo>, BackendError> {
        repo.find_commit(head)
            .and_then(|commit| commit.tree())
            .map_err(|err| self.git_error("read commit", &err))
    }

    /// 读取工作区 Ref；不存在返回 `Ok(None)`。
    fn read_workspace_ref(
        &self,
        cache: &Cache,
        workspace: WorkspaceId,
    ) -> Result<Option<WorkspaceRef>, BackendError> {
        let Some(bytes) = self.read_blob(cache, &ref_path(workspace))? else {
            return Ok(None);
        };
        // canonical 解码顺带完成结构校验；非 canonical 编码在这里就被拒绝。
        let reference = WorkspaceRef::from_canonical_slice(&bytes)?;
        if reference.workspace != workspace {
            return Err(BackendError::InvalidRef {
                workspace,
                detail: format!("远端记录的工作区是 {}，与请求不符", reference.workspace),
            });
        }
        Ok(Some(reference))
    }

    /// 在当前 head 之上构造一个新提交。
    ///
    /// 返回 `Ok(None)` 表示新 tree 与基线完全相同，没有任何东西需要推送。
    fn stage(
        &self,
        cache: &Cache,
        entries: &[Entry],
        message: &str,
    ) -> Result<Option<Oid>, BackendError> {
        let repo = &cache.repo;
        let parent: Option<Commit<'_>> = match cache.head {
            Some(head) => Some(
                repo.find_commit(head)
                    .map_err(|err| self.git_error("read commit", &err))?,
            ),
            None => None,
        };
        let base_tree = match &parent {
            Some(commit) => Some(
                commit
                    .tree()
                    .map_err(|err| self.git_error("read tree", &err))?,
            ),
            None => None,
        };

        // 内存 index：不落盘、不依赖工作区，天然适合 bare 仓库。
        let mut index = Index::new().map_err(|err| self.git_error("create index", &err))?;
        if let Some(tree) = &base_tree {
            index
                .read_tree(tree)
                .map_err(|err| self.git_error("load tree", &err))?;
        }

        // 每个提交都保证格式标记在位：第一次写入创建它，之后从基线继承。
        let has_format = match &base_tree {
            Some(tree) => tree.get_path(Path::new(FORMAT_PATH)).is_ok(),
            None => false,
        };
        if !has_format {
            self.put_entry(repo, &mut index, FORMAT_PATH, FORMAT_MARKER.as_bytes())?;
        }
        for entry in entries {
            self.put_entry(repo, &mut index, &entry.path, &entry.bytes)?;
        }

        let tree_oid = index
            .write_tree_to(repo)
            .map_err(|err| self.git_error("write tree", &err))?;
        if base_tree.as_ref().map(Tree::id) == Some(tree_oid) {
            return Ok(None);
        }
        let tree = repo
            .find_tree(tree_oid)
            .map_err(|err| self.git_error("read tree", &err))?;
        let signature = self.signature()?;
        let parents: Vec<&Commit<'_>> = parent.iter().collect();
        let commit = repo
            .commit(None, &signature, &signature, message, &tree, &parents)
            .map_err(|err| self.git_error("create commit", &err))?;
        Ok(Some(commit))
    }

    /// 把一条内容写进 index。
    fn put_entry(
        &self,
        repo: &Repository,
        index: &mut Index,
        path: &str,
        bytes: &[u8],
    ) -> Result<(), BackendError> {
        // 路径穿越必须在写 blob 之前被拦下。
        validate_tree_path(path)?;
        let oid = repo
            .blob(bytes)
            .map_err(|err| self.git_error("write blob", &err))?;
        index
            .add(&index_entry(path, oid, bytes.len()))
            .map_err(|err| self.git_error("add index entry", &err))
    }

    /// 固定的提交署名。见模块文档「提交是确定性的」。
    fn signature(&self) -> Result<Signature<'static>, BackendError> {
        Signature::new(COMMIT_AUTHOR_NAME, COMMIT_AUTHOR_EMAIL, &Time::new(0, 0))
            .map_err(|err| self.git_error("build signature", &err))
    }

    /// 把提交推到受信分支。
    ///
    /// refspec 没有前导 `+`，因此**永远不是 force push**：远端一旦发现更新不是
    /// fast-forward 就会拒绝，我们把它翻译成 [`PushOutcome::NonFastForward`]。
    fn publish(&self, cache: &mut Cache, commit: Oid) -> Result<PushOutcome, BackendError> {
        let outcome = {
            let repo = &cache.repo;
            let mut remote = repo
                .remote_anonymous(&self.config.remote_url)
                .map_err(|err| self.git_error("open remote", &err))?;

            // 有些传输层不把拒绝当作错误返回，而是通过该回调逐条报告。
            let rejection: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
            let mut callbacks = self.callbacks();
            let sink = Arc::clone(&rejection);
            callbacks.push_update_reference(move |_reference, status| {
                if let Some(status) = status {
                    let mut slot = sink.lock().unwrap_or_else(|err| err.into_inner());
                    *slot = Some(status.to_owned());
                }
                Ok(())
            });
            let mut options = PushOptions::new();
            options.remote_callbacks(callbacks);

            let refspec = format!("{}:{}", commit, self.branch_ref());
            match remote.push(&[refspec], Some(&mut options)) {
                Ok(()) => {}
                Err(err) if is_non_fast_forward(&err) => return Ok(PushOutcome::NonFastForward),
                Err(err) => return Err(self.git_error("push", &err)),
            }

            let rejection = rejection
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .take();
            match rejection {
                None => PushOutcome::Accepted,
                Some(status) if mentions_non_fast_forward(&status) => PushOutcome::NonFastForward,
                Some(status) => {
                    // 远端以别的理由拒绝（权限、钩子、协议能力缺失……）。绝不降级成
                    // 「最后写入获胜」，原样报错。
                    return Err(BackendError::Io {
                        context: format!(
                            "git push 被远端拒绝（host={}, branch={}）",
                            remote_host(&self.config.remote_url),
                            self.config.branch
                        ),
                        source: io::Error::other(scrub(&status)),
                    });
                }
            }
        };

        if outcome == PushOutcome::Accepted {
            // 本地镜像跟上，避免下一次 refresh 白白重新下载刚推上去的提交。
            cache
                .repo
                .reference(&self.tracking_ref(), commit, true, "envsync push")
                .map_err(|err| self.git_error("update tracking ref", &err))?;
            cache.head = Some(commit);
        }
        Ok(outcome)
    }

    /// push 成功后回读远端，确认它真的按 fast-forward 语义接受了我们的提交。
    ///
    /// 这一步把「远端会拒绝非 fast-forward 更新」从**假设**变成**可检测的事实**：远端
    /// 若把分支指向了一段不含本次提交的历史（说明它允许覆盖式更新，或有人 force
    /// push），Ref 发布的原子性就不成立了。这时返回 [`BackendError::Unsupported`]，
    /// 让上层拒绝把该远端用于多设备写入，而**绝不**默默降级成「最后写入获胜」。
    ///
    /// 代价是每次 Ref 发布多一次 fetch。对象写入不做这个检查——对象是内容寻址的，谁先
    /// 写都一样，丢了下次会重写。
    fn verify_published(&self, cache: &mut Cache, commit: Oid) -> Result<(), BackendError> {
        self.refresh(cache)?;
        let Some(head) = cache.head else {
            return Err(BackendError::Unsupported(
                "远端接受 push 后受信分支却不存在：该远端不提供 CAS 发布所需的引用保证",
            ));
        };
        if head == commit {
            return Ok(());
        }
        // 别的设备在我们之后继续推进是正常的，只要我们的提交仍在历史里。
        let incorporated = cache
            .repo
            .graph_descendant_of(head, commit)
            .map_err(|err| self.git_error("check ancestry", &err))?;
        if incorporated {
            Ok(())
        } else {
            Err(BackendError::Unsupported(
                "远端接受 push 后把受信分支指向了不含本次提交的历史：该远端未强制 fast-forward，无法提供强 CAS",
            ))
        }
    }

    /// 幂等写入的公共判断：已存在的内容相同则成功，不同则是内容寻址被破坏。
    fn reconcile_existing(id: ObjectId, existing: &[u8], bytes: &[u8]) -> Result<(), BackendError> {
        if existing == bytes {
            Ok(())
        } else {
            Err(BackendError::Corruption {
                id,
                detail: "远端已存在同标识但内容不同的对象".to_owned(),
            })
        }
    }
}

impl Backend for GitBackend {
    /// # `supports_strong_cas` 的前提
    ///
    /// 返回 `true`，但这个 `true` 有一个**外部前提**：远端必须拒绝非 fast-forward 的
    /// 引用更新。本实现能保证的部分是——
    ///
    /// * push 的 refspec 永远不带 `+`，也从不设置 force；
    /// * push 之前先 fetch，并把远端当前 revision 与调用方声明的 `expected_revision`
    ///   逐一比对，相当于一次显式的 lease 校验；
    /// * push 被拒绝时重新 fetch，把**真实**的 observed revision 带回
    ///   [`BackendError::CasConflict`]，绝不重试、绝不 force；
    /// * push 被接受后再回读一次，确认远端分支确实包含本次提交；不包含就说明该远端没有
    ///   强制 fast-forward，返回 [`BackendError::Unsupported`] 而**不是**默认成功。
    ///
    /// 本实现**无法**保证的部分是：如果远端被配置成允许 force / 允许非 fast-forward
    /// 更新（例如 `receive.denyNonFastForwards=false` 且有其他客户端 force push），那么
    /// 「至多一方成功」由远端而非 EnvSync 决定。所有主流 Git 服务端默认拒绝非
    /// fast-forward 更新，因此默认部署下强 CAS 成立。
    ///
    /// 一个已知的窄化情形：libgit2 的**本地文件传输**（`file://` 或裸路径）只在客户端做
    /// fast-forward 检查，服务端不复核。它只用于测试与可移动介质；真实网络远端走的是
    /// `receive-pack`，检查发生在服务端。即便在这种传输上出现真正的交错写入，push 后的
    /// 回读也会发现自己的提交不在历史里，从而报错而不是假装成功。
    fn describe(&self) -> BackendDescriptor {
        BackendDescriptor {
            kind: "git",
            supports_strong_cas: true,
        }
    }

    fn get_ref(&self, workspace: WorkspaceId) -> Result<WorkspaceRef, BackendError> {
        let mut cache = self.locked();
        // 读也要先刷新：陈旧镜像会让上层以为自己拿到了最新头。
        self.refresh(&mut cache)?;
        self.verify_format(&cache)?;
        self.read_workspace_ref(&cache, workspace)?
            .ok_or(BackendError::RefNotFound(workspace))
    }

    fn compare_and_swap_ref(
        &self,
        workspace: WorkspaceId,
        expected_revision: u64,
        next: &WorkspaceRef,
    ) -> Result<(), BackendError> {
        // 先做不依赖远端状态的校验，避免为必然失败的请求跑一趟网络。
        next.validate().map_err(|err| BackendError::InvalidRef {
            workspace,
            detail: err.to_string(),
        })?;
        if next.workspace != workspace {
            return Err(BackendError::InvalidRef {
                workspace,
                detail: format!("待写入 Ref 属于工作区 {}", next.workspace),
            });
        }

        let mut cache = self.locked();
        self.refresh(&mut cache)?;
        self.verify_format(&cache)?;

        let current = self.read_workspace_ref(&cache, workspace)?;
        let observed = current.as_ref().map_or(0, |reference| reference.revision);
        if observed != expected_revision {
            return Err(BackendError::CasConflict {
                expected: expected_revision,
                observed,
            });
        }

        // Ref 缺失时以「revision 0 的初始引用」为基准，同样要求严格递增。
        let base = current.unwrap_or_else(|| WorkspaceRef::initial(workspace));
        base.check_successor(next)
            .map_err(|err| BackendError::InvalidRef {
                workspace,
                detail: err.to_string(),
            })?;

        let entries = [Entry {
            path: ref_path(workspace),
            bytes: next.to_canonical_vec(),
        }];
        let commit = match self.stage(&cache, &entries, &ref_commit_message(next))? {
            Some(commit) => commit,
            // revision 一定变了，tree 不可能与基线相同；真出现只能是远端内容被外部改成
            // 了我们正要写的样子，按冲突处理最安全。
            None => {
                return Err(BackendError::CasConflict {
                    expected: expected_revision,
                    observed,
                })
            }
        };

        match self.publish(&mut cache, commit)? {
            PushOutcome::Accepted => {
                // 只有确认远端真的接受了这次提交，才敢对上层宣称发布成功。
                self.verify_published(&mut cache, commit)?;
                tracing::debug!(
                    %workspace,
                    from = observed,
                    to = next.revision,
                    host = %remote_host(&self.config.remote_url),
                    branch = %self.config.branch,
                    "已向 Git 远端发布新的工作区 Ref"
                );
                Ok(())
            }
            PushOutcome::NonFastForward => {
                // fetch 与 push 之间有人抢先。重新读取，把真实 revision 带回去。
                self.refresh(&mut cache)?;
                let observed = self
                    .read_workspace_ref(&cache, workspace)?
                    .map_or(0, |reference| reference.revision);
                Err(BackendError::CasConflict {
                    expected: expected_revision,
                    observed,
                })
            }
        }
    }

    fn get_object(&self, id: ObjectId) -> Result<Vec<u8>, BackendError> {
        let mut cache = self.locked();
        let path = object_path(id);
        let mut bytes = self.read_blob(&cache, &path)?;
        if bytes.is_none() {
            // 缓存里没有：可能是别的设备刚写上去的，刷新一次再判定不存在。
            self.refresh(&mut cache)?;
            bytes = self.read_blob(&cache, &path)?;
        }
        let bytes = bytes.ok_or(BackendError::ObjectNotFound(id))?;
        // 重算摘要：损坏的对象绝不返回内容。
        if !id.verifies(&bytes) {
            return Err(BackendError::Corruption {
                id,
                detail: format!("读出的 {} 字节重算摘要与对象标识不一致", bytes.len()),
            });
        }
        Ok(bytes)
    }

    fn put_object(&self, id: ObjectId, bytes: &[u8]) -> Result<(), BackendError> {
        if !id.verifies(bytes) {
            return Err(BackendError::Corruption {
                id,
                detail: "待写入内容的摘要与对象标识不一致".to_owned(),
            });
        }

        let mut cache = self.locked();
        let path = object_path(id);
        // 快路径：镜像里已经有了就不必联网。镜像只会来自远端广播或我们自己成功的 push，
        // 所以「镜像里有」蕴含「远端有」。
        if let Some(existing) = self.read_blob(&cache, &path)? {
            return Self::reconcile_existing(id, &existing, bytes);
        }

        for _ in 0..MAX_OBJECT_PUSH_ATTEMPTS {
            self.refresh(&mut cache)?;
            self.verify_format(&cache)?;
            if let Some(existing) = self.read_blob(&cache, &path)? {
                return Self::reconcile_existing(id, &existing, bytes);
            }

            let entries = [Entry {
                path: path.clone(),
                bytes: bytes.to_vec(),
            }];
            let Some(commit) = self.stage(&cache, &entries, OBJECT_COMMIT_MESSAGE)? else {
                return Ok(());
            };
            match self.publish(&mut cache, commit)? {
                PushOutcome::Accepted => return Ok(()),
                // 对象写入可交换：被抢先只需在新头上重放，不影响任何 CAS 语义。
                PushOutcome::NonFastForward => continue,
            }
        }

        Err(BackendError::Io {
            context: format!(
                "git push 对象连续 {MAX_OBJECT_PUSH_ATTEMPTS} 次被并发写入抢先（host={}, branch={}）",
                remote_host(&self.config.remote_url),
                self.config.branch
            ),
            source: io::Error::other("远端分支竞争过于激烈，请稍后重试"),
        })
    }

    fn has_object(&self, id: ObjectId) -> Result<bool, BackendError> {
        let mut cache = self.locked();
        let path = object_path(id);
        if self.read_blob(&cache, &path)?.is_some() {
            return Ok(true);
        }
        self.refresh(&mut cache)?;
        Ok(self.read_blob(&cache, &path)?.is_some())
    }

    fn list_objects(&self, prefix: &str) -> Result<Vec<ObjectId>, BackendError> {
        validate_prefix(prefix)?;
        let shard_prefix = &prefix[..prefix.len().min(2)];

        let mut cache = self.locked();
        self.refresh(&mut cache)?;

        let mut found = Vec::new();
        let Some(head) = cache.head else {
            return Ok(found);
        };
        let repo = &cache.repo;
        let root = self.head_tree(repo, head)?;
        let objects = match root.get_path(Path::new(OBJECTS_DIR)) {
            Ok(entry) => entry,
            Err(err) if err.code() == ErrorCode::NotFound => return Ok(found),
            Err(err) => return Err(self.git_error("read tree entry", &err)),
        };
        let objects = objects
            .to_object(repo)
            .map_err(|err| self.git_error("read tree", &err))?;
        let Some(objects) = objects.as_tree() else {
            return Err(BackendError::Unsupported(
                "远端布局非法：objects 不是一棵 tree",
            ));
        };

        for shard in objects.iter() {
            let Some(shard_name) = shard.name() else {
                continue;
            };
            // 分片目录名必须恰好是两位小写十六进制，其余一律忽略。
            if shard_name.len() != 2 || !is_lower_hex(shard_name) {
                continue;
            }
            if !shard_name.starts_with(shard_prefix) {
                continue;
            }
            let shard_name = shard_name.to_owned();
            let shard = shard
                .to_object(repo)
                .map_err(|err| self.git_error("read tree", &err))?;
            let Some(shard) = shard.as_tree() else {
                continue;
            };
            for file in shard.iter() {
                let Some(name) = file.name() else {
                    continue;
                };
                let Some(id) = parse_object_name(&shard_name, name) else {
                    continue;
                };
                if id.hex().starts_with(prefix) {
                    found.push(id);
                }
            }
        }

        // tree 条目本来就有序，这里再排一次以对齐 LocalBackend 的确定性输出。
        found.sort();
        Ok(found)
    }
}

/// 对象提交的信息：只有一个语义标签，不含路径、标识或本机信息。
const OBJECT_COMMIT_MESSAGE: &str = "envsync objects\n";

/// 对象在 Git tree 中的路径。
fn object_path(id: ObjectId) -> String {
    let (shard, rest) = id.storage_segments();
    format!("{OBJECTS_DIR}/{shard}/{rest}.{}", id.kind.as_str())
}

/// 工作区 Ref 在 Git tree 中的路径。
fn ref_path(workspace: WorkspaceId) -> String {
    format!("{REFS_DIR}/{workspace}.cbor")
}

/// Ref 提交的信息。
///
/// **只含**工作区、revision 和 Snapshot ID：没有路径、没有主机名、没有用户名、没有凭据。
fn ref_commit_message(next: &WorkspaceRef) -> String {
    let snapshot = match &next.head {
        Some(head) => head.to_hex(),
        None => String::from("-"),
    };
    format!(
        "envsync ref\n\nworkspace={}\nrevision={}\nsnapshot={}\n",
        next.workspace, next.revision, snapshot
    )
}

/// 校验一条 Git tree 路径。
///
/// EnvSync 写入的路径全部由已校验的标识拼出来，正常情况下不可能非法；这个函数是**纵深
/// 防御**：一旦有人在拼接逻辑里引入 `..`、绝对路径或空段，写入会在生成 blob 之前失败，
/// 而不是悄悄在远端仓库里写到 `.envsync/` 之外去。
///
/// 规则：必须位于 `.envsync/` 之下；不得以 `/` 开头或结尾；不得出现空段、`.`、`..`；
/// 不得出现 `.git` 段（避免在远端仓库里伪造 Git 元数据）；每段只能含 `A-Za-z0-9._-`；
/// 总长不超过 512 字节。
///
/// # 错误
///
/// 违反上述规则时返回 [`BackendError::InvalidPrefix`]——该变体的语义就是「调用方给出的
/// 路径片段含分隔符或点段」，这里复用它以保持错误码稳定（`invalid_prefix`）。
pub fn validate_tree_path(path: &str) -> Result<(), BackendError> {
    let reject = |detail: &str| BackendError::InvalidPrefix {
        prefix: path.chars().take(128).collect(),
        detail: detail.to_owned(),
    };
    if path.is_empty() {
        return Err(reject("路径不能为空"));
    }
    if path.len() > MAX_TREE_PATH_LEN {
        return Err(reject("路径超过 512 字节"));
    }
    if path.contains('\\') {
        return Err(reject("路径不能包含反斜杠"));
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err(reject("路径不能以 `/` 开头或结尾"));
    }
    let mut segments = path.split('/');
    match segments.next() {
        Some(first) if first == ROOT_DIR => {}
        _ => return Err(reject("路径必须位于 .envsync/ 之下")),
    }
    let mut has_leaf = false;
    for segment in segments {
        has_leaf = true;
        if segment.is_empty() {
            return Err(reject("路径不能包含空段"));
        }
        if segment == "." || segment == ".." {
            return Err(reject("路径不能包含 `.` 或 `..` 段"));
        }
        if segment.eq_ignore_ascii_case(".git") {
            return Err(reject("路径不能包含 `.git` 段"));
        }
        if !segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(reject("路径段只能包含字母、数字与 `.`、`_`、`-`"));
        }
    }
    if !has_leaf {
        return Err(reject("路径必须指向 .envsync/ 下的一个文件"));
    }
    Ok(())
}

/// 校验分支名。
///
/// 采用 git ref 命名规则的一个**保守子集**：只允许 `A-Za-z0-9._/-`。分支名会进入
/// `tracing`，收紧字符集顺带挡掉了控制字符和换行注入。
fn validate_branch(branch: &str) -> Result<(), BackendError> {
    if branch.is_empty() {
        return Err(BackendError::Unsupported("分支名不能为空"));
    }
    if branch.len() > MAX_BRANCH_LEN {
        return Err(BackendError::Unsupported("分支名过长（上限 255 字节）"));
    }
    if !branch
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
    {
        return Err(BackendError::Unsupported(
            "分支名只能包含字母、数字与 `.`、`_`、`-`、`/`",
        ));
    }
    if branch.starts_with('/')
        || branch.ends_with('/')
        || branch.starts_with('.')
        || branch.ends_with('.')
        || branch.contains("//")
        || branch.contains("..")
        || branch.ends_with(".lock")
    {
        return Err(BackendError::Unsupported("分支名不符合 git 引用命名规则"));
    }
    Ok(())
}

/// 打开（必要时初始化）私有 cache clone。
fn open_cache_repo(dir: &Path) -> Result<Repository, BackendError> {
    fs::create_dir_all(dir).map_err(|err| BackendError::io("cache 目录", err))?;
    restrict_permissions(dir)?;
    match Repository::open_bare(dir) {
        Ok(repo) => Ok(repo),
        Err(err) if err.code() == ErrorCode::NotFound => {
            Repository::init_bare(dir).map_err(|err| BackendError::Io {
                context: "初始化 cache 仓库".to_owned(),
                source: io::Error::other(scrub(err.message())),
            })
        }
        Err(err) => Err(BackendError::Io {
            context: "打开 cache 仓库".to_owned(),
            source: io::Error::other(scrub(err.message())),
        }),
    }
}

/// 在 Unix 上把 cache 目录收紧到 `0700`。
///
/// cache clone 里有用户的完整配置历史，不应对同机其他用户可读。
#[cfg(unix)]
fn restrict_permissions(dir: &Path) -> Result<(), BackendError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .map_err(|err| BackendError::io("cache 目录权限", err))
}

/// 非 Unix 平台依赖目录本身的继承权限。
#[cfg(not(unix))]
fn restrict_permissions(_dir: &Path) -> Result<(), BackendError> {
    Ok(())
}

/// 构造一条 index 记录。
///
/// 时间戳、uid/gid、dev/ino 一律填 0：它们不会进入 tree 对象，填真实值只会破坏确定性。
fn index_entry(path: &str, oid: Oid, len: usize) -> IndexEntry {
    IndexEntry {
        ctime: IndexTime::new(0, 0),
        mtime: IndexTime::new(0, 0),
        dev: 0,
        ino: 0,
        // 普通文件，非可执行：EnvSync 的对象与 Ref 都不需要执行位。
        mode: 0o100_644,
        uid: 0,
        gid: 0,
        // 仅供 index 自身使用；超过 4 GiB 时截断不影响写出的 tree。
        file_size: u32::try_from(len).unwrap_or(u32::MAX),
        id: oid,
        flags: 0,
        flags_extended: 0,
        path: path.as_bytes().to_vec(),
    }
}

/// 判断 git2 错误是否表示「非 fast-forward」。
fn is_non_fast_forward(err: &git2::Error) -> bool {
    err.code() == ErrorCode::NotFastForward || mentions_non_fast_forward(err.message())
}

/// 判断远端返回的拒绝理由是否表示「非 fast-forward」。
///
/// 不同服务端措辞不同（`non-fast-forward`、`fetch first`、`stale info`……），这里做保守
/// 匹配：认错了只会多报一次 CAS 冲突，不会导致覆盖。
fn mentions_non_fast_forward(message: &str) -> bool {
    let lowered = message.to_ascii_lowercase();
    [
        "non-fast-forward",
        "non-fastforward",
        "fast-forward",
        "fastforward",
        "fetch first",
        "stale info",
        "not present locally",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
}

/// 根据配置提供凭据。
///
/// EnvSync 自己不持有任何密钥：ssh 走 agent，https 走 credential helper，token 只保存
/// 引用且在 M2 之前不解析。
fn credential(
    auth: &GitAuth,
    url: &str,
    username: Option<&str>,
    allowed: CredentialType,
) -> Result<Cred, git2::Error> {
    // ssh 握手的第一步是询问用户名，与具体认证方式无关。
    if allowed.contains(CredentialType::USERNAME) {
        return Cred::username(username.unwrap_or("git"));
    }
    match auth {
        GitAuth::SshAgent => {
            if allowed.contains(CredentialType::SSH_KEY) {
                Cred::ssh_key_from_agent(username.unwrap_or("git"))
            } else {
                Err(git2::Error::from_str(
                    "远端要求的凭据类型不受 ssh-agent 支持",
                ))
            }
        }
        GitAuth::CredentialHelper => {
            if allowed.contains(CredentialType::USER_PASS_PLAINTEXT) {
                let config = git2::Config::open_default()?;
                Cred::credential_helper(&config, url, username)
            } else {
                Err(git2::Error::from_str(
                    "远端要求的凭据类型不受 credential helper 支持",
                ))
            }
        }
        GitAuth::TokenSecretRef { .. } => Err(git2::Error::from_str(
            "token secret 引用要到 M2 的 Vault 才会被解析，当前无法用于连接",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_paths_reject_traversal() {
        for path in [
            ".envsync/objects/../../etc/passwd",
            ".envsync/../secrets",
            "../.envsync/objects/aa/bb.blob",
            "/etc/passwd",
            ".envsync/",
            ".envsync",
            "objects/aa/bb.blob",
            ".envsync/objects//bb.blob",
            ".envsync/.git/config",
            ".envsync\\objects\\aa",
        ] {
            let err = validate_tree_path(path).expect_err(path);
            assert_eq!(err.code(), "backend.invalid_prefix", "{path}");
        }
    }

    #[test]
    fn tree_paths_accept_layout_paths() {
        validate_tree_path(FORMAT_PATH).unwrap();
        validate_tree_path(".envsync/objects/ab/cdef.blob").unwrap();
        validate_tree_path(".envsync/refs/2f5d0f0e-0000-4000-8000-000000000001.cbor").unwrap();
    }

    #[test]
    fn branch_names_are_restricted() {
        validate_branch("envsync").unwrap();
        validate_branch("team/envsync").unwrap();
        for branch in [
            "", "/x", "x/", ".x", "x.", "a//b", "a..b", "x.lock", "a b", "a\nb",
        ] {
            assert!(validate_branch(branch).is_err(), "{branch:?}");
        }
    }
}
