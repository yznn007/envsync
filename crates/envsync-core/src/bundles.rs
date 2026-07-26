//! Agent Bundle 的隔离、验签、审核、启用与撤销。
//!
//! 设计文档 §7 把 Agent Bundle 定义为**主动内容**：它一旦启用就会改变 AI 工具的提示、
//! 工具权限与 MCP 配置。因此它默认隔离，走一条与普通文件完全不同的路径：
//!
//! ```text
//! downloaded ──▶ inspected ──▶ approved ──▶ enabled
//!      │              │            │           │
//!      └──────────────┴────────────┴───────────┴──▶ blocked ──▶ revoked
//! ```
//!
//! # 三条硬约束
//!
//! 1. **落盘先失能。** 下载的内容只写进[不可执行的 quarantine 根](QuarantineRoot)：
//!    写入时无条件抹掉 execute bit（`& !0o111`），并且**全程不跟随链接**。即便验签、
//!    审核与策略三道关卡同时失守，落到磁盘上的也只是一堆不可执行的数据文件。
//! 2. **批准绑定四元组。** [`BundleApproval`] 记录的是
//!    `(manifest 摘要, 能力集, 目标 Profile, signer)`，不是「这个 Bundle 我信了」。
//!    升级后新增的能力**必须重新审核**，见 [`review_update`] 与
//!    [`BundleApproval::check_covers`]。
//! 3. **每一次迁移都过策略。** 所有迁移都用
//!    [`ResourceKind::AgentBundle`] + [`Operation::Enable`] 求值一次
//!    [`envsync_policy`]，决策与解释原样带进 [`BundleTransition`]。
//!
//! # 为什么「进 blocked / revoked」不受策略否决
//!
//! 策略对**前进方向**（inspect / approve / enable）是强制的：`Deny` 直接失败，
//! `RequireConfirmation` 必须拿到用户确认。但对**降级方向**（block / revoke）策略只被
//! 求值和记录，不被执行。
//!
//! 理由是它反过来会变成攻击面：block 与 revoke 是发现问题后的止损动作，如果一条
//! `deny` 规则能阻止它们，那么写下那条规则的人（或攻陷了策略文件的人）就能让一个已知
//! 恶意的 Bundle 无法被隔离。安全动作永远不需要许可。
//!
//! # 验签在哪里
//!
//! 签名验证一律走 [`envsync_crypto::device::verify`]：本模块**不实现任何密码学**，
//! 只负责定义「被签的字节是什么」（在
//! [`envsync_domain::agent_bundle::BundleManifest::signing_payload`] 里）以及
//! 「哪些公钥可信」（[`PublisherRegistry`]）。

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use envsync_crypto::device::{verify as verify_signature, DevicePublic, Signature};
use envsync_domain::agent_bundle::{
    bundle_file_digest, BundleEntryKind, BundleFileEntry, BundleId, BundleManifest,
    BundleManifestError, BundleSignature, BundleState, MAX_BUNDLE_TOTAL_BYTES,
};
use envsync_domain::id::{Digest32, ResourceId, WorkspaceId};
use envsync_domain::profile::DeviceProfile;
use envsync_domain::Risk;
use envsync_policy::{Decision, DecisionOutcome, Operation, PolicyFacts, PolicySet, ResourceKind};
use envsync_storage::bundles::BundleRecord;

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

/// 发布者签名的用途标签，传给 [`envsync_crypto::device::verify`]。
///
/// 它与成员事件（`membership-event`）、快照、邀请等用的标签互不相同，因此一枚为
/// Bundle 签出的签名不可能被当成任何别的东西的签名，反之亦然。
pub const BUNDLE_SIGNATURE_DOMAIN: &str = "agent-bundle";

/// 发布者公钥指纹的域标签。
pub const PUBLISHER_FINGERPRINT_DOMAIN: &str = "envsync:bundle-publisher:v1";

/// quarantine 根目录的权限（仅属主可读写执行）。
pub const QUARANTINE_DIR_MODE: u32 = 0o700;

/// quarantine 内文件写入时请求的权限。
///
/// 真正落盘的模式是 `strip_execute_bits(QUARANTINE_FILE_MODE)`：请求值与实际值分开
/// 写，是为了让「无条件抹掉 execute bit」这一步在代码里**看得见**，而不是靠常量恰好
/// 没有 `x` 位来保证。
pub const QUARANTINE_FILE_MODE: u32 = 0o644;

/// 一个 Bundle 允许包含的最大文件数（与 manifest 上限一致，这里再钉一次）。
const MAX_STAGED_FILES: usize = 4_096;

/// 抹掉一个 Unix 权限位里的全部 execute bit。
///
/// quarantine 里的东西是**别人写的主动内容**。它可以是提示词、Skill 文本、JSON 配置，
/// 但绝不应该是一个能被误双击、误 `./` 执行、或被某个工具当成 hook 脚本调用的可执行
/// 文件。抹掉 `x` 位不能阻止 `sh file` 这类显式解释执行，但它去掉了整整一类
/// 「不小心执行了」的路径。
pub const fn strip_execute_bits(mode: u32) -> u32 {
    mode & !0o111
}

/// 发布者签名所绑定的命名空间。
///
/// [`envsync_crypto::device::verify`] 的待签结构里有一个工作区槽位，用来阻断跨工作区
/// 重放。Bundle 签名是**工作区无关**的——发布者在发布时并不知道谁会安装它，不可能
/// 为每个工作区各签一次——因此这里固定使用全零 UUID 作为「发布命名空间」。
///
/// 这不会削弱隔离：真正把 Bundle 签名与设备签名分开的是用途标签
/// [`BUNDLE_SIGNATURE_DOMAIN`]，而全零 UUID 恰好是
/// [`WorkspaceId::generate`] 永远不会产生的取值，因此这个命名空间与任何真实工作区都
/// 不可能相撞。
pub fn publisher_namespace() -> WorkspaceId {
    static NAMESPACE: OnceLock<WorkspaceId> = OnceLock::new();
    *NAMESPACE.get_or_init(|| {
        "00000000-0000-0000-0000-000000000000"
            .parse()
            .expect("全零 UUID 是合法的 WorkspaceId")
    })
}

/// 发布者公钥的短指纹，用作 [`PolicyFacts::source_signer`]。
///
/// 用域分隔摘要而不是公钥本身：指纹会出现在策略规则、解释文本与日志里，短且不可逆的
/// 表示更适合被人读和被规则匹配。
pub fn publisher_fingerprint(publisher_key: &[u8; 32]) -> String {
    Digest32::domain_hash(PUBLISHER_FINGERPRINT_DOMAIN, publisher_key).short()
}

// ---------------------------------------------------------------------------
// 错误
// ---------------------------------------------------------------------------

/// Bundle 隔离流程的错误。
///
/// `Display` 输出不含本机绝对路径、不含文件正文、不含任何秘密值：quarantine 路径只以
/// 「Bundle 标识 + 相对路径」的形式出现。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BundleError {
    /// manifest 或载荷不合法。
    #[error(transparent)]
    Manifest(#[from] BundleManifestError),

    /// 密码学层错误（公钥非法、签名格式错误等）。
    #[error(transparent)]
    Crypto(#[from] envsync_crypto::CryptoError),

    /// 状态机不允许这次迁移。
    #[error("Bundle {bundle} 不能从 {from} 迁移到 {to}")]
    IllegalTransition {
        /// Bundle 标识。
        bundle: BundleId,
        /// 当前状态。
        from: BundleState,
        /// 目标状态。
        to: BundleState,
    },

    /// 策略拒绝了这次迁移。
    #[error("策略拒绝了 Bundle {bundle} 的 {to} 迁移：{explanation}")]
    PolicyDenied {
        /// Bundle 标识。
        bundle: BundleId,
        /// 目标状态。
        to: BundleState,
        /// 策略给出的完整解释（含命中规则标识与事实摘要）。
        explanation: String,
    },

    /// 策略要求用户确认，但调用方没有提供确认。
    #[error("Bundle {bundle} 的 {to} 迁移需要用户确认：{explanation}")]
    ConfirmationRequired {
        /// Bundle 标识。
        bundle: BundleId,
        /// 目标状态。
        to: BundleState,
        /// 策略给出的完整解释。
        explanation: String,
    },

    /// 已有批准不覆盖当前 manifest。
    #[error("Bundle {bundle} 的已有批准不覆盖当前版本：{gap}")]
    ApprovalStale {
        /// Bundle 标识。
        bundle: BundleId,
        /// 具体缺口。
        gap: ApprovalGap,
    },

    /// quarantine 目录已存在。
    #[error("Bundle {bundle} 的 quarantine 目录已存在；请先清理再重新解包")]
    AlreadyStaged {
        /// Bundle 标识。
        bundle: BundleId,
    },

    /// quarantine 路径上出现了符号链接或非目录。
    #[error("quarantine 路径分段 `{segment}` 不是普通目录（可能是符号链接）")]
    UnsafeQuarantinePath {
        /// 出问题的分段。
        segment: String,
    },

    /// 文件系统操作失败。
    #[error("quarantine 操作 `{operation}` 失败：{kind:?}")]
    Io {
        /// 操作名（静态字符串，不含路径）。
        operation: &'static str,
        /// 底层 I/O 错误类别。
        kind: std::io::ErrorKind,
    },
}

impl BundleError {
    /// 稳定的机器可读错误码，用于 CLI 的 JSON 契约与测试断言。
    pub fn code(&self) -> &'static str {
        match self {
            BundleError::Manifest(error) => error.code(),
            BundleError::Crypto(_) => "bundle.crypto",
            BundleError::IllegalTransition { .. } => "bundle.illegal_transition",
            BundleError::PolicyDenied { .. } => "bundle.policy_denied",
            BundleError::ConfirmationRequired { .. } => "bundle.confirmation_required",
            BundleError::ApprovalStale { .. } => "bundle.approval_stale",
            BundleError::AlreadyStaged { .. } => "bundle.already_staged",
            BundleError::UnsafeQuarantinePath { .. } => "bundle.unsafe_quarantine_path",
            BundleError::Io { .. } => "bundle.io",
        }
    }

    /// 把 I/O 错误收敛成不含路径的形式。
    fn io(operation: &'static str, error: &std::io::Error) -> Self {
        BundleError::Io {
            operation,
            kind: error.kind(),
        }
    }
}

// ---------------------------------------------------------------------------
// 发布者
// ---------------------------------------------------------------------------

/// 已知发布者与撤销名单。
///
/// 「未知 signer」与「已撤销 signer」是两件不同的事，但结论相同：两者都不能让 Bundle
/// 前进，都必须进 [`BundleState::Blocked`]。分开记录是为了让解释里说得清楚——
/// 「我不认识这把钥匙」和「这把钥匙被吊销了」对用户的下一步动作提示完全不同。
#[derive(Debug, Clone, Default)]
pub struct PublisherRegistry {
    trusted: BTreeMap<[u8; 32], String>,
    revoked: BTreeSet<[u8; 32]>,
}

/// 一把发布者公钥的信任状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublisherStatus {
    /// 在信任名单里且未被撤销。
    Trusted,
    /// 不在信任名单里。
    Unknown,
    /// 曾被信任，现已撤销。
    Revoked,
}

impl PublisherStatus {
    /// 稳定短名，用于诊断与阻断原因。
    pub const fn as_str(self) -> &'static str {
        match self {
            PublisherStatus::Trusted => "trusted",
            PublisherStatus::Unknown => "unknown",
            PublisherStatus::Revoked => "revoked",
        }
    }
}

impl PublisherRegistry {
    /// 空注册表：任何 signer 都是未知的。
    ///
    /// 这是刻意的默认值。内建策略里
    /// [`envsync_policy::BUILTIN_UNSIGNED_ACTIVE_CONTENT`] 会把「没有 signer」的主动
    /// 内容直接拒绝，因此一个没有配置过任何发布者的设备无法启用任何 Bundle。
    pub fn new() -> Self {
        PublisherRegistry::default()
    }

    /// 信任一把发布者公钥。
    ///
    /// `label` 只是展示名；判定只看公钥字节。已被撤销的公钥不会因为再次 `trust` 而
    /// 恢复——撤销是单向的，恢复必须是一次显式的、留痕的动作（先 `unrevoke` 再
    /// `trust`），这里刻意不提供 `unrevoke`。
    pub fn trust(&mut self, publisher_key: [u8; 32], label: impl Into<String>) -> &mut Self {
        self.trusted.insert(publisher_key, label.into());
        self
    }

    /// 撤销一把发布者公钥。
    pub fn revoke(&mut self, publisher_key: [u8; 32]) -> &mut Self {
        self.revoked.insert(publisher_key);
        self
    }

    /// 查询一把公钥的信任状态。
    pub fn status(&self, publisher_key: &[u8; 32]) -> PublisherStatus {
        if self.revoked.contains(publisher_key) {
            return PublisherStatus::Revoked;
        }
        if self.trusted.contains_key(publisher_key) {
            return PublisherStatus::Trusted;
        }
        PublisherStatus::Unknown
    }

    /// 展示名；未登记时返回 `None`。
    pub fn label(&self, publisher_key: &[u8; 32]) -> Option<&str> {
        self.trusted.get(publisher_key).map(String::as_str)
    }
}

/// 验证发布者签名。
///
/// 顺序刻意固定为「结构 → 信任 → 密码学」：
///
/// 1. [`BundleManifest::validate`] 与 [`BundleSignature::check_shape`] 先排除结构问题；
/// 2. 再查 [`PublisherRegistry`]——未知或已撤销的 signer 根本不值得做曲线运算；
/// 3. 最后调用 [`envsync_crypto::device::verify`] 对
///    [`BundleManifest::signing_payload`] 验签。
///
/// 待签字节同时覆盖 canonical manifest 摘要与**全部 file digest**，因此改动任意一个
/// 文件都会让这一步失败。
pub fn verify_bundle_signature(
    manifest: &BundleManifest,
    signature: &BundleSignature,
    publishers: &PublisherRegistry,
) -> Result<(), BundleError> {
    manifest.validate()?;
    signature.check_shape(manifest)?;
    match publishers.status(&manifest.publisher_key) {
        PublisherStatus::Trusted => {}
        PublisherStatus::Unknown => {
            return Err(BundleError::Crypto(
                envsync_crypto::CryptoError::SignatureInvalid,
            ))
        }
        PublisherStatus::Revoked => {
            return Err(BundleError::Crypto(
                envsync_crypto::CryptoError::SignatureInvalid,
            ))
        }
    }
    let public = publisher_public(&manifest.publisher_key);
    let mut raw = [0u8; BundleSignature::SIGNATURE_LEN];
    raw.copy_from_slice(&signature.signature);
    verify_signature(
        &public,
        BUNDLE_SIGNATURE_DOMAIN,
        publisher_namespace(),
        &manifest.signing_payload(),
        &Signature::from_bytes(raw),
    )?;
    Ok(())
}

/// 把发布者的 Ed25519 公钥包装成 [`DevicePublic`]。
///
/// [`envsync_crypto::device::verify`] 是本仓库**唯一**经过审查的 Ed25519 验签入口
/// （它做了 `verify_strict`、canonical 待签结构与域分隔），因此这里复用它而不是另开
/// 一条验签路径。`verify` 只读 [`DevicePublic::ed25519`] 字段；`x25519` 字段与签名
/// 验证完全无关，填零即可——发布者身份里本来也没有 HPKE 接收密钥这个概念。
fn publisher_public(publisher_key: &[u8; 32]) -> DevicePublic {
    DevicePublic {
        x25519: [0u8; 32],
        ed25519: *publisher_key,
    }
}

// ---------------------------------------------------------------------------
// quarantine
// ---------------------------------------------------------------------------

/// 已解包到 quarantine 的一个 Bundle。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedBundle {
    /// 该 Bundle 在 quarantine 根下的目录（绝对路径，只在本机有意义）。
    pub root: PathBuf,
    /// 实际落盘的条目，按路径升序。
    pub entries: Vec<BundleFileEntry>,
}

impl StagedBundle {
    /// 路径 -> 摘要的视图，可直接交给 [`envsync_storage::bundles::BundleStore::upsert`]。
    pub fn files(&self) -> BTreeMap<String, Digest32> {
        self.entries
            .iter()
            .map(|entry| (entry.path.clone(), entry.digest))
            .collect()
    }
}

/// 不可执行的 quarantine 根。
///
/// 这是**下载内容唯一被允许落地的地方**。它的三条性质各自对应一类攻击：
///
/// | 性质 | 挡住的攻击 |
/// |---|---|
/// | 写入时 `& !0o111` | 内容被当成脚本或 hook 直接执行 |
/// | 逐段 `symlink_metadata` + `create_new` | 用符号链接把写入重定向到家目录 |
/// | 写前先过 manifest 与载荷校验 | 路径穿越、未声明文件、体积炸弹 |
#[derive(Debug, Clone)]
pub struct QuarantineRoot {
    root: PathBuf,
}

impl QuarantineRoot {
    /// 打开（必要时创建）quarantine 根。
    ///
    /// 根目录必须是**真实目录**：如果它已经存在但是一个符号链接，直接拒绝——否则
    /// 「往 quarantine 里写」这句话就失去了全部意义。
    pub fn open(root: impl AsRef<Path>) -> Result<Self, BundleError> {
        let root = root.as_ref().to_path_buf();
        match fs::symlink_metadata(&root) {
            Ok(meta) => {
                if !meta.is_dir() {
                    return Err(BundleError::UnsafeQuarantinePath {
                        segment: display_tail(&root),
                    });
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(&root)
                    .map_err(|error| BundleError::io("create_root", &error))?;
            }
            Err(error) => return Err(BundleError::io("stat_root", &error)),
        }
        set_dir_mode(&root)?;
        Ok(QuarantineRoot { root })
    }

    /// quarantine 根路径。
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// 某个 Bundle 某个 manifest 摘要对应的隔离目录。
    ///
    /// 目录名里带摘要：同一个 Bundle 的两个版本互不覆盖，因此「已批准的旧版本」与
    /// 「待审核的新版本」可以并存，用户能真正对着 diff 做审核。
    pub fn bundle_dir(&self, bundle: &BundleId, manifest_digest: Digest32) -> PathBuf {
        self.root
            .join(bundle.to_directory_name())
            .join(manifest_digest.short())
    }

    /// 把一个 Bundle 的内容解包进 quarantine。
    ///
    /// 先校验、后写入：manifest 与载荷任何一项不过关，磁盘上都不会出现任何字节。
    ///
    /// 写入规则：
    ///
    /// * 目录逐级用 `create_dir` 创建；已存在的分段必须是**真实目录**
    ///   （`symlink_metadata` 判定），是符号链接就拒绝；
    /// * 文件用 `create_new`（`O_EXCL`）创建：目标已存在——哪怕只是一条悬空符号链接
    ///   ——都会失败，因此写入不可能被重定向；
    /// * 落盘后把权限设成 [`strip_execute_bits`] 之后的值。
    pub fn stage(
        &self,
        manifest: &BundleManifest,
        contents: &BTreeMap<String, Vec<u8>>,
    ) -> Result<StagedBundle, BundleError> {
        manifest.validate()?;
        if contents.len() > MAX_STAGED_FILES {
            return Err(BundleError::Manifest(BundleManifestError::TooManyEntries {
                field: "payload",
                actual: contents.len(),
                limit: MAX_STAGED_FILES,
            }));
        }

        let mut entries: Vec<BundleFileEntry> = Vec::with_capacity(contents.len());
        let mut total: u64 = 0;
        for (path, bytes) in contents {
            // 载荷路径与 manifest 路径受同一套规则约束：manifest 里没有的路径在
            // `check_payload` 里会被拒，但那之前它已经被当成路径处理过一次了。
            envsync_domain::agent_bundle::validate_bundle_path(path)?;
            total = total.saturating_add(bytes.len() as u64);
            if total > MAX_BUNDLE_TOTAL_BYTES {
                return Err(BundleError::Manifest(BundleManifestError::TooLarge {
                    actual: total,
                    limit: MAX_BUNDLE_TOTAL_BYTES,
                }));
            }
            entries.push(BundleFileEntry {
                path: path.clone(),
                kind: BundleEntryKind::File,
                digest: bundle_file_digest(bytes),
                bytes: bytes.len() as u64,
            });
        }
        manifest.check_payload(&entries)?;

        let dir = self.bundle_dir(&manifest.id, manifest.manifest_digest());
        if fs::symlink_metadata(&dir).is_ok() {
            return Err(BundleError::AlreadyStaged {
                bundle: manifest.id.clone(),
            });
        }
        create_dir_chain(&self.root, &dir)?;

        for (path, bytes) in contents {
            let target = dir.join(path);
            if let Some(parent) = target.parent() {
                create_dir_chain(&dir, parent)?;
            }
            write_non_executable(&target, bytes)?;
        }

        Ok(StagedBundle { root: dir, entries })
    }

    /// 删除一个 Bundle 某个版本的隔离目录。
    ///
    /// 只删 [`QuarantineRoot::bundle_dir`] 给出的那一级：路径完全由本模块构造，不接受
    /// 调用方传入的任意路径，因此不存在「删错目录」的入口。
    pub fn purge(&self, bundle: &BundleId, manifest_digest: Digest32) -> Result<bool, BundleError> {
        let dir = self.bundle_dir(bundle, manifest_digest);
        match fs::symlink_metadata(&dir) {
            Ok(meta) if meta.is_dir() => {
                fs::remove_dir_all(&dir).map_err(|error| BundleError::io("purge", &error))?;
                Ok(true)
            }
            Ok(_) => Err(BundleError::UnsafeQuarantinePath {
                segment: display_tail(&dir),
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(BundleError::io("stat_bundle_dir", &error)),
        }
    }
}

/// 从 `base`（含）向 `target` 逐级创建目录，全程不跟随链接。
fn create_dir_chain(base: &Path, target: &Path) -> Result<(), BundleError> {
    let relative = target.strip_prefix(base).unwrap_or(target);
    let mut current = base.to_path_buf();
    ensure_real_dir(&current)?;
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            // `stage` 之前已经校验过路径，这里再挡一次：任何 `..`、根、前缀分量都说明
            // 上游校验被绕过了，直接拒绝而不是尽力而为。
            return Err(BundleError::UnsafeQuarantinePath {
                segment: component.as_os_str().to_string_lossy().into_owned(),
            });
        };
        current.push(segment);
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                return Err(BundleError::UnsafeQuarantinePath {
                    segment: segment.to_string_lossy().into_owned(),
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|error| BundleError::io("create_dir", &error))?;
                set_dir_mode(&current)?;
            }
            Err(error) => return Err(BundleError::io("stat_dir", &error)),
        }
    }
    Ok(())
}

/// 确认一条路径是**真实目录**而不是符号链接。
fn ensure_real_dir(path: &Path) -> Result<(), BundleError> {
    let meta = fs::symlink_metadata(path).map_err(|error| BundleError::io("stat_dir", &error))?;
    if !meta.is_dir() {
        return Err(BundleError::UnsafeQuarantinePath {
            segment: display_tail(path),
        });
    }
    Ok(())
}

/// 以 `create_new` 写入一个不可执行的文件。
fn write_non_executable(path: &Path, bytes: &[u8]) -> Result<(), BundleError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // 创建时就带上最终权限，避免「先以默认权限创建、再 chmod」这段窗口。
        options.mode(strip_execute_bits(QUARANTINE_FILE_MODE));
    }
    let mut file = options
        .open(path)
        .map_err(|error| BundleError::io("create_file", &error))?;
    file.write_all(bytes)
        .map_err(|error| BundleError::io("write_file", &error))?;
    file.sync_all()
        .map_err(|error| BundleError::io("sync_file", &error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // umask 可能把创建时的 mode 削掉一部分（那是安全方向），但也可能有平台在
        // 别的方向上偏差。这里无条件再设一次最终权限：execute bit 必须是 0。
        let permissions = fs::Permissions::from_mode(strip_execute_bits(QUARANTINE_FILE_MODE));
        fs::set_permissions(path, permissions)
            .map_err(|error| BundleError::io("chmod_file", &error))?;
    }
    Ok(())
}

/// 把目录权限设成 [`QUARANTINE_DIR_MODE`]（仅 Unix 生效）。
fn set_dir_mode(path: &Path) -> Result<(), BundleError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::Permissions::from_mode(QUARANTINE_DIR_MODE);
        fs::set_permissions(path, permissions)
            .map_err(|error| BundleError::io("chmod_dir", &error))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// 只取路径的最后一段用于诊断：错误信息里不能出现本机绝对路径。
fn display_tail(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<root>".to_owned())
}

// ---------------------------------------------------------------------------
// 批准
// ---------------------------------------------------------------------------

/// 一次用户批准。
///
/// 它绑定四个东西，缺一不可：
///
/// * **manifest 摘要**——批准的是这份内容，不是这个名字；
/// * **能力集**——批准的是这些能力，新增的必须重新审核；
/// * **目标 Profile**——在工作机上批准的东西不自动在个人机上生效；
/// * **signer**——换了发布者就是另一条信任链。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleApproval {
    /// 被批准的 Bundle。
    pub bundle: BundleId,
    /// 批准时的 manifest 摘要。
    pub manifest_digest: Digest32,
    /// 批准时 manifest 声明的能力集合。
    pub capabilities: BTreeSet<String>,
    /// 目标 Profile 名。
    pub profile: String,
    /// 批准时的发布者公钥。
    pub signer: [u8; 32],
    /// 批准时刻（Unix 毫秒）。
    pub approved_at_unix_ms: u64,
}

/// 已有批准与当前 manifest 之间的缺口。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ApprovalGap {
    /// 批准属于另一个 Bundle。
    #[error("批准属于另一个 Bundle")]
    DifferentBundle,
    /// 发布者变了。
    #[error("发布者公钥已变更，信任链需要重新建立")]
    SignerChanged,
    /// 目标 Profile 变了。
    #[error("批准针对 Profile `{approved}`，当前是 `{current}`")]
    ProfileChanged {
        /// 批准时的 Profile。
        approved: String,
        /// 当前 Profile。
        current: String,
    },
    /// 内容变了（升级或被篡改）。
    #[error("manifest 摘要已变更，内容需要重新审核")]
    DigestChanged,
    /// 新版本多声明了能力。
    #[error("新增声明能力 {added:?} 未被批准，必须重新审核")]
    CapabilitiesExpanded {
        /// 新增的能力，按字典序。
        added: BTreeSet<String>,
    },
}

impl ApprovalGap {
    /// 稳定的机器可读缺口码。
    pub fn code(&self) -> &'static str {
        match self {
            ApprovalGap::DifferentBundle => "approval.different_bundle",
            ApprovalGap::SignerChanged => "approval.signer_changed",
            ApprovalGap::ProfileChanged { .. } => "approval.profile_changed",
            ApprovalGap::DigestChanged => "approval.digest_changed",
            ApprovalGap::CapabilitiesExpanded { .. } => "approval.capabilities_expanded",
        }
    }
}

impl BundleApproval {
    /// 这份批准是否覆盖 `manifest` 在 `profile` 上的启用。
    ///
    /// 检查顺序是「身份 → 信任 → 场景 → 内容 → 能力」。能力检查放在摘要检查之后不是
    /// 因为它次要，而是因为**摘要不变时能力必然不变**（能力是 manifest 的一部分，被
    /// 摘要覆盖）；这一条独立存在，是为了在调用方刻意忽略摘要变化时仍然兜住能力扩张。
    pub fn check_covers(
        &self,
        manifest: &BundleManifest,
        profile: &str,
    ) -> Result<(), ApprovalGap> {
        if self.bundle != manifest.id {
            return Err(ApprovalGap::DifferentBundle);
        }
        if self.signer != manifest.publisher_key {
            return Err(ApprovalGap::SignerChanged);
        }
        if self.profile != profile {
            return Err(ApprovalGap::ProfileChanged {
                approved: self.profile.clone(),
                current: profile.to_owned(),
            });
        }
        let added = self.added_capabilities(manifest);
        if !added.is_empty() {
            return Err(ApprovalGap::CapabilitiesExpanded { added });
        }
        if self.manifest_digest != manifest.manifest_digest() {
            return Err(ApprovalGap::DigestChanged);
        }
        Ok(())
    }

    /// `manifest` 相对本次批准**新增**的声明能力。
    ///
    /// 只算新增：能力变少不需要重新审核——用户批准过的权限范围本来就是上界。
    pub fn added_capabilities(&self, manifest: &BundleManifest) -> BTreeSet<String> {
        manifest
            .declared_capabilities
            .difference(&self.capabilities)
            .cloned()
            .collect()
    }
}

/// 一次升级审核的结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateReview {
    /// 内容摘要是否变化。
    pub digest_changed: bool,
    /// 发布者是否变化。
    pub signer_changed: bool,
    /// 新增的声明能力。
    pub added_capabilities: BTreeSet<String>,
    /// 移除的声明能力（仅供展示，不阻塞）。
    pub removed_capabilities: BTreeSet<String>,
}

impl UpdateReview {
    /// 是否必须重新走一遍批准流程。
    ///
    /// 内容变了就要重新审核——这不是保守，而是「批准的是内容」这句话的直接推论。
    pub fn requires_reapproval(&self) -> bool {
        self.digest_changed || self.signer_changed || !self.added_capabilities.is_empty()
    }

    /// 是否属于**能力扩张**：新版本要的权限比用户批准过的更多。
    ///
    /// 它比 [`UpdateReview::requires_reapproval`] 更严重：一次普通的内容更新只是需要
    /// 用户再看一眼 diff，而能力扩张意味着「同意装它」和「同意它读我的秘密」被偷偷
    /// 合并成了同一个动作。
    pub fn is_capability_expansion(&self) -> bool {
        !self.added_capabilities.is_empty()
    }
}

/// 比较一份已有批准与一个新版本 manifest。
pub fn review_update(approval: &BundleApproval, next: &BundleManifest) -> UpdateReview {
    UpdateReview {
        digest_changed: approval.manifest_digest != next.manifest_digest(),
        signer_changed: approval.signer != next.publisher_key,
        added_capabilities: approval.added_capabilities(next),
        removed_capabilities: approval
            .capabilities
            .difference(&next.declared_capabilities)
            .cloned()
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// 状态迁移
// ---------------------------------------------------------------------------

/// 一次迁移所需的全部上下文。
///
/// 字段全部是借用的**只读快照**：本模块不持有策略集、不持有 Profile，也无法在判定
/// 过程中改变它们。
#[derive(Debug, Clone, Copy)]
pub struct BundleContext<'a> {
    /// 生效的策略集。
    pub policy: &'a PolicySet,
    /// 本设备 Profile。
    pub profile: &'a DeviceProfile,
    /// 目标 Profile 名（批准四元组的一员）。
    pub profile_name: &'a str,
    /// 已知发布者与撤销名单。
    pub publishers: &'a PublisherRegistry,
    /// 用户是否已经对本次迁移给出确认。
    ///
    /// 它只影响 [`Decision::RequireConfirmation`]：`Deny` 不会因为「用户说好」而放行。
    pub confirmed: bool,
}

/// 一次迁移的结果。
#[derive(Debug, Clone)]
pub struct BundleTransition {
    /// 迁移前的状态。
    pub from: BundleState,
    /// 迁移后的状态。
    pub to: BundleState,
    /// 策略判定结果（含命中规则、事实摘要与解释）。
    ///
    /// 降级迁移也会带上它：策略被**求值并记录**，只是不被执行，见模块级文档。
    pub outcome: DecisionOutcome,
    /// 迁移后的记录。
    pub record: BundleRecord,
}

impl BundleTransition {
    /// 本次迁移是否把 Bundle 推向了生效方向。
    pub fn is_forward(&self) -> bool {
        !self.to.is_downgrade()
    }
}

/// 为一次迁移构造策略事实并求值。
///
/// 所有迁移共用 [`ResourceKind::AgentBundle`] + [`Operation::Enable`]：隔离状态机的
/// 每一步都是「让这份主动内容离生效更近一步」，它们属于同一条策略维度。具体是哪一步
/// 由 [`BundleTransition::to`] 与解释文本区分。
fn evaluate_policy(
    manifest: Option<&BundleManifest>,
    record: &BundleRecord,
    to: BundleState,
    ctx: &BundleContext<'_>,
    signer: Option<&str>,
) -> DecisionOutcome {
    let declared: BTreeSet<String> = manifest
        .map(|manifest| manifest.declared_capabilities.clone())
        .unwrap_or_else(|| record.approved_capabilities.clone());
    let secret_refs: Vec<String> = manifest
        .map(|manifest| manifest.secret_refs.iter().cloned().collect())
        .unwrap_or_default();
    // 资源标识用固定前缀 + Bundle 标识：`BundleId` 的字符集是 `ResourceId` 的子集，
    // 因此这次解析不可能失败；万一失败也只是退化成「不带资源维度的事实」。
    let resource = ResourceId::parse(&format!("agents/bundle/{}", record.bundle.as_str())).ok();

    let mut facts = PolicyFacts::new(
        ResourceKind::AgentBundle,
        Operation::Enable,
        transition_risk(to),
        ctx.profile.os,
    )
    .with_profile(ctx.profile)
    .with_declared_capabilities(&declared)
    .with_secret_refs(&secret_refs);
    if let Some(resource) = resource.as_ref() {
        facts = facts.with_resource(resource);
    }
    if let Some(signer) = signer {
        facts = facts.with_signer(signer);
    }
    ctx.policy.evaluate(&facts)
}

/// 一次迁移的风险等级。
///
/// 只有「启用」是 [`Risk::High`]：那是内容真正开始影响 AI 工具行为的一刻。前面的几步
/// 都还没有任何东西生效，降级更是止损动作。
fn transition_risk(to: BundleState) -> Risk {
    match to {
        BundleState::Enabled => Risk::High,
        BundleState::Approved => Risk::Medium,
        BundleState::Downloaded
        | BundleState::Inspected
        | BundleState::Blocked
        | BundleState::Revoked => Risk::Low,
    }
}

/// 把策略决策施加到一次**前进**迁移上。
fn enforce(
    bundle: &BundleId,
    to: BundleState,
    outcome: &DecisionOutcome,
    confirmed: bool,
) -> Result<(), BundleError> {
    match outcome.decision {
        Decision::Allow => Ok(()),
        Decision::Deny => Err(BundleError::PolicyDenied {
            bundle: bundle.clone(),
            to,
            explanation: outcome.explanation.clone(),
        }),
        Decision::RequireConfirmation if confirmed => Ok(()),
        Decision::RequireConfirmation => Err(BundleError::ConfirmationRequired {
            bundle: bundle.clone(),
            to,
            explanation: outcome.explanation.clone(),
        }),
    }
}

/// 检查状态机是否允许这次迁移。
fn check_edge(record: &BundleRecord, to: BundleState) -> Result<(), BundleError> {
    if !record.state.can_transition_to(to) {
        return Err(BundleError::IllegalTransition {
            bundle: record.bundle.clone(),
            from: record.state,
            to,
        });
    }
    Ok(())
}

/// `downloaded → inspected`：校验载荷、验签，并把结论写进记录。
///
/// # 返回值不是「成功/失败」，而是「去了哪个状态」
///
/// 载荷不符、签名无效、signer 未知或已撤销——这些都**不是** `Err`，而是一次通向
/// [`BundleState::Blocked`] 的合法迁移：它们描述的是「这个 Bundle 有问题」，而不是
/// 「这次调用有问题」。调用方要判断结果，看
/// [`BundleTransition::to`] 与 [`BundleRecord::blocked_reason`]。
///
/// 真正返回 `Err` 的只有两类：状态机不允许这次迁移，以及策略拒绝/要求确认。
pub fn inspect(
    record: &BundleRecord,
    manifest: &BundleManifest,
    signature: &BundleSignature,
    entries: &[BundleFileEntry],
    ctx: &BundleContext<'_>,
    now_unix_ms: u64,
) -> Result<BundleTransition, BundleError> {
    check_edge(record, BundleState::Inspected)?;

    // 先判定载荷与签名，因为 signer 是否可信直接决定策略事实里有没有 `source_signer`
    // ——「未签名的主动内容」在内建策略里是被直接拒绝的。
    let status = ctx.publishers.status(&manifest.publisher_key);
    let payload_ok = manifest
        .validate()
        .and_then(|()| manifest.check_payload(entries));
    let blocked_reason = match (&payload_ok, status) {
        (Err(error), _) => Some(format!("载荷校验失败：{error}")),
        (Ok(()), PublisherStatus::Unknown) => Some("发布者公钥未登记在信任名单中".to_owned()),
        (Ok(()), PublisherStatus::Revoked) => Some("发布者公钥已被撤销".to_owned()),
        (Ok(()), PublisherStatus::Trusted) => {
            match verify_bundle_signature(manifest, signature, ctx.publishers) {
                Ok(()) => None,
                Err(error) => Some(format!("签名验证失败：{}", error.code())),
            }
        }
    };

    let fingerprint = publisher_fingerprint(&manifest.publisher_key);
    let signer = blocked_reason.is_none().then_some(fingerprint.as_str());

    if let Some(reason) = blocked_reason {
        // 阻断是安全动作：策略被求值并记录，但不参与是否阻断的判断。
        let outcome = evaluate_policy(Some(manifest), record, BundleState::Blocked, ctx, None);
        return Ok(BundleTransition {
            from: record.state,
            to: BundleState::Blocked,
            outcome,
            record: BundleRecord {
                state: BundleState::Blocked,
                blocked_reason: Some(reason),
                updated_at_unix_ms: now_unix_ms,
                ..record.clone()
            },
        });
    }

    let outcome = evaluate_policy(Some(manifest), record, BundleState::Inspected, ctx, signer);
    enforce(
        &record.bundle,
        BundleState::Inspected,
        &outcome,
        ctx.confirmed,
    )?;
    Ok(BundleTransition {
        from: record.state,
        to: BundleState::Inspected,
        outcome,
        record: BundleRecord {
            version: manifest.version.clone(),
            manifest_digest: manifest.manifest_digest(),
            publisher_key: manifest.publisher_key,
            state: BundleState::Inspected,
            blocked_reason: None,
            updated_at_unix_ms: now_unix_ms,
            ..record.clone()
        },
    })
}

/// `inspected → approved`：记录一次绑定四元组的批准。
///
/// 批准**必须**在策略允许（或用户确认）之后才发生，因此 [`BundleContext::confirmed`]
/// 在这条路径上几乎总是必需的：内建策略里
/// [`envsync_policy::BUILTIN_AGENT_BUNDLE_ENABLE`] 对 Agent Bundle 要求确认。
pub fn approve(
    record: &BundleRecord,
    manifest: &BundleManifest,
    ctx: &BundleContext<'_>,
    now_unix_ms: u64,
) -> Result<(BundleTransition, BundleApproval), BundleError> {
    check_edge(record, BundleState::Approved)?;
    // `approve` 不重新做曲线运算：签名已经在 `inspect` 里验过，记录里的摘要与公钥
    // 就是那次验证的结论。这里要挡住的是另一件事——「验的是 A，批的是 B」：
    // 传进来的 manifest 必须与记录指向同一份内容、同一个发布者。
    if record.bundle != manifest.id {
        return Err(BundleError::ApprovalStale {
            bundle: record.bundle.clone(),
            gap: ApprovalGap::DifferentBundle,
        });
    }
    if record.publisher_key != manifest.publisher_key {
        return Err(BundleError::ApprovalStale {
            bundle: record.bundle.clone(),
            gap: ApprovalGap::SignerChanged,
        });
    }
    if record.manifest_digest != manifest.manifest_digest() {
        return Err(BundleError::ApprovalStale {
            bundle: record.bundle.clone(),
            gap: ApprovalGap::DigestChanged,
        });
    }

    let fingerprint = publisher_fingerprint(&manifest.publisher_key);
    let outcome = evaluate_policy(
        Some(manifest),
        record,
        BundleState::Approved,
        ctx,
        Some(fingerprint.as_str()),
    );
    enforce(
        &record.bundle,
        BundleState::Approved,
        &outcome,
        ctx.confirmed,
    )?;

    let approval = BundleApproval {
        bundle: manifest.id.clone(),
        manifest_digest: manifest.manifest_digest(),
        capabilities: manifest.declared_capabilities.clone(),
        profile: ctx.profile_name.to_owned(),
        signer: manifest.publisher_key,
        approved_at_unix_ms: now_unix_ms,
    };
    let transition = BundleTransition {
        from: record.state,
        to: BundleState::Approved,
        outcome,
        record: BundleRecord {
            state: BundleState::Approved,
            approved_capabilities: approval.capabilities.clone(),
            approved_at_unix_ms: Some(now_unix_ms),
            blocked_reason: None,
            updated_at_unix_ms: now_unix_ms,
            ..record.clone()
        },
    };
    Ok((transition, approval))
}

/// `approved → enabled`：在批准覆盖当前 manifest 的前提下启用。
///
/// 这里是「能力扩张必须重新审核」真正落地的地方：
/// [`BundleApproval::check_covers`] 一旦发现新增能力就返回
/// [`ApprovalGap::CapabilitiesExpanded`]，启用直接失败。老版本的批准**不会**自动
/// 继承到新版本。
pub fn enable(
    record: &BundleRecord,
    manifest: &BundleManifest,
    approval: &BundleApproval,
    ctx: &BundleContext<'_>,
    now_unix_ms: u64,
) -> Result<BundleTransition, BundleError> {
    check_edge(record, BundleState::Enabled)?;
    approval
        .check_covers(manifest, ctx.profile_name)
        .map_err(|gap| BundleError::ApprovalStale {
            bundle: record.bundle.clone(),
            gap,
        })?;

    // 启用前再查一次发布者状态：`inspect` 与 `enable` 之间可能已经发生了一次撤销。
    let status = ctx.publishers.status(&manifest.publisher_key);
    if status != PublisherStatus::Trusted {
        let outcome = evaluate_policy(Some(manifest), record, BundleState::Blocked, ctx, None);
        return Ok(BundleTransition {
            from: record.state,
            to: BundleState::Blocked,
            outcome,
            record: BundleRecord {
                state: BundleState::Blocked,
                blocked_reason: Some(format!("发布者状态为 {}", status.as_str())),
                updated_at_unix_ms: now_unix_ms,
                ..record.clone()
            },
        });
    }

    let fingerprint = publisher_fingerprint(&manifest.publisher_key);
    let outcome = evaluate_policy(
        Some(manifest),
        record,
        BundleState::Enabled,
        ctx,
        Some(fingerprint.as_str()),
    );
    enforce(
        &record.bundle,
        BundleState::Enabled,
        &outcome,
        ctx.confirmed,
    )?;
    Ok(BundleTransition {
        from: record.state,
        to: BundleState::Enabled,
        outcome,
        record: BundleRecord {
            state: BundleState::Enabled,
            blocked_reason: None,
            updated_at_unix_ms: now_unix_ms,
            ..record.clone()
        },
    })
}

/// 任意状态 → `blocked`。
///
/// 策略被求值并记录，但**不被执行**：见模块级文档「为什么进 blocked / revoked 不受
/// 策略否决」。
pub fn block(
    record: &BundleRecord,
    reason: impl Into<String>,
    ctx: &BundleContext<'_>,
    now_unix_ms: u64,
) -> Result<BundleTransition, BundleError> {
    check_edge(record, BundleState::Blocked)?;
    let outcome = evaluate_policy(None, record, BundleState::Blocked, ctx, None);
    Ok(BundleTransition {
        from: record.state,
        to: BundleState::Blocked,
        outcome,
        record: BundleRecord {
            state: BundleState::Blocked,
            blocked_reason: Some(reason.into()),
            updated_at_unix_ms: now_unix_ms,
            ..record.clone()
        },
    })
}

/// 任意状态 → `revoked`（吸收态）。
pub fn revoke(
    record: &BundleRecord,
    reason: impl Into<String>,
    ctx: &BundleContext<'_>,
    now_unix_ms: u64,
) -> Result<BundleTransition, BundleError> {
    check_edge(record, BundleState::Revoked)?;
    let outcome = evaluate_policy(None, record, BundleState::Revoked, ctx, None);
    Ok(BundleTransition {
        from: record.state,
        to: BundleState::Revoked,
        outcome,
        record: BundleRecord {
            state: BundleState::Revoked,
            blocked_reason: Some(reason.into()),
            updated_at_unix_ms: now_unix_ms,
            ..record.clone()
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_bits_are_always_stripped() {
        assert_eq!(strip_execute_bits(0o755), 0o644);
        assert_eq!(strip_execute_bits(0o777), 0o666);
        assert_eq!(strip_execute_bits(QUARANTINE_FILE_MODE) & 0o111, 0);
    }

    #[test]
    fn publisher_namespace_is_stable_and_never_generated() {
        assert_eq!(publisher_namespace(), publisher_namespace());
        assert_ne!(publisher_namespace(), WorkspaceId::generate());
    }

    #[test]
    fn fingerprints_differ_per_key() {
        assert_ne!(
            publisher_fingerprint(&[1u8; 32]),
            publisher_fingerprint(&[2u8; 32])
        );
    }
}
