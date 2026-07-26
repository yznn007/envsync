# Git 后端（M1）

Git 后端把 EnvSync 的内容寻址对象映射进一棵**普通的 Git tree**，用远端 branch head
做 CAS 发布。它不发明新协议，也不要求服务端安装任何东西：GitHub、GitLab、Gitea、
自建裸仓库都可以直接用。

选择 Git 的理由只有一条：**Git 远端已经提供了 EnvSync 需要的两样东西**——内容寻址的
对象存储，以及服务端强制的 fast-forward 检查。后者正是 CAS 发布所需要的原子性。

实现见 `crates/envsync-backend/src/git.rs`（对象映射与 CAS）与
`crates/envsync-backend/src/git_auth.rs`（认证与脱敏）。

---

## 1. Git tree 布局

```text
<受信分支>
└── .envsync/
    ├── format                                   "envsync-git-format=1\n"
    ├── objects/
    │   ├── ab/
    │   │   ├── cdef0123….blob                   Blob
    │   │   ├── 4455aabb….state_root             State Root
    │   │   ├── 7788ccdd….snapshot               Snapshot Body
    │   │   └── 99aabbcc….snapshot_signature     Snapshot 签名
    │   └── cd/
    │       └── …
    └── refs/
        └── 0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0.cbor   WorkspaceRef（canonical CBOR）
```

| 路径 | 内容 | 说明 |
|---|---|---|
| `.envsync/format` | 逐字节等于 `envsync-git-format=1\n` | 打开时逐字节比较，不一致一律拒绝 |
| `.envsync/objects/<前两位>/<其余摘要>.<种类>` | 与 Local 后端**逐字节相同**的对象内容 | 扩展名只是路径层元数据，**不参与摘要计算** |
| `.envsync/refs/<workspace-uuid>.cbor` | canonical CBOR 编码的 `WorkspaceRef` | 含 workspace、revision、head |

三条设计约束：

1. **对象字节与 Local 后端完全相同。** 同一份内容可以在 Local 与 Git 后端之间直接
   搬运，换后端不需要重算任何摘要。
2. **文件名保留 `.<种类>` 扩展名。** `ObjectId` = 种类 + 摘要，而摘要本身不携带种类；
   扩展名让 `list_objects` 能还原完整标识。
3. **格式标记与 Local 后端故意不同。** 两种布局的对象字节相同，但目录结构与一致性
   保证不同，混用必须被发现。

### 1.1 提交是确定性的

| 字段 | 取值 |
|---|---|
| author / committer 名 | `EnvSync` |
| author / committer 邮箱 | `envsync@localhost` |
| 时间戳 | Unix 纪元 `0`，时区偏移 `0` |
| 文件模式 | `0o100644`（普通文件，非可执行） |
| index 的 ctime/mtime/uid/gid/dev/ino | 全部为 `0` |

于是「相同父提交 + 相同 tree + 相同 message」必然产生相同的 commit OID：重放同一次
发布不会污染历史，不同设备算出的提交可以逐字节比对。

代价是 `git log` 的时间列没有意义。这是刻意的取舍：发布时间本来就记录在 EnvSync 自
己的 journal 里，Git 提交时间只会泄漏用户的作息。

### 1.2 提交信息不含任何本机信息

```text
# Ref 提交
envsync ref

workspace=0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0
revision=7
snapshot=5be47e77c1a2…

# 对象提交
envsync objects
```

没有路径、没有主机名、没有用户名、没有凭据。`snapshot` 在 Ref 的 `head` 为空时写
`-`。

### 1.3 tree 路径的纵深防御

EnvSync 写入的路径全部由已校验的标识拼出来，正常情况下不可能非法。`validate_tree_path`
仍然在生成 blob **之前**再挡一道：

| 规则 | 被拒绝的例子 |
|---|---|
| 必须位于 `.envsync/` 之下 | `objects/aa/bb.blob` |
| 不得以 `/` 开头或结尾 | `/etc/passwd`、`.envsync/` |
| 不得包含空段、`.`、`..` | `.envsync/objects//bb.blob`、`.envsync/../secrets` |
| 不得包含 `.git` 段（大小写不敏感） | `.envsync/.git/config` |
| 不得包含反斜杠 | `.envsync\objects\aa` |
| 每段只能含 `A-Za-z0-9._-` | 含空格或控制字符的段 |
| 总长 ≤ 512 字节 | 超长路径 |
| 必须指向 `.envsync/` 下的一个文件 | `.envsync` |

违规返回 `BackendError::InvalidPrefix`（错误码 `invalid_prefix`）。

---

## 2. CAS 语义：确切的保证与前提

`GitBackend::describe()` 返回 `supports_strong_cas: true`。这个 `true` 有一个**外部
前提**，必须写清楚。

### 2.1 EnvSync 自己保证的部分

```text
compare_and_swap_ref(workspace, expected_revision, next)
  │
  ├─ 1. 本地校验：next 自洽、workspace 相符、revision 严格递增
  │
  ├─ 2. fetch 受信分支（+refs/heads/<branch>:refs/remotes/envsync/<branch>，prune 开启）
  │
  ├─ 3. 校验 .envsync/format 逐字节相符
  │
  ├─ 4. **lease 校验**：读出远端当前 Ref 的 revision
  │        observed != expected_revision  ⟹  CasConflict{expected, observed}，立即返回
  │
  ├─ 5. 在远端 head 之上构造 tree + commit
  │
  ├─ 6. push  "<local-oid>:refs/heads/<branch>"
  │        ↑ 没有前导 `+`，也从不设置 force —— **永不 force push**
  │
  ├─ 7a. 被拒绝（非 fast-forward）
  │        ⟹ 重新 fetch，把**真实**的 observed revision 带回 CasConflict
  │        ⟹ **绝不重试、绝不 force**
  │
  └─ 7b. 被接受
           ⟹ **回读确认**：再 fetch 一次，检查受信分支的 head 是否
              == 本次提交，或 graph_descendant_of(head, commit)
           ⟹ 不满足 ⟹ BackendError::Unsupported，而**不是**默认成功
```

四条可以在代码里指着看的保证：

| 保证 | 位置 |
|---|---|
| push 的 refspec 永远不带 `+`，从不设置 force | `GitBackend::publish` |
| push 之前先 fetch，并把远端 revision 与 `expected_revision` 逐一比对（显式 lease） | `compare_and_swap_ref` 第 4 步 |
| push 被拒绝时重新 fetch，带回真实 observed revision，绝不重试绝不 force | `PushOutcome::NonFastForward` 分支 |
| push 被接受后再回读一次，确认远端分支确实包含本次提交 | `verify_published` |

远端以别的理由拒绝（权限、钩子、协议能力缺失……）时原样报错，**绝不降级成「最后写入
获胜」**。

### 2.2 前提：远端必须拒绝非 fast-forward 更新

EnvSync **无法**保证的部分是：如果远端被配置成允许非 fast-forward 更新
（`receive.denyNonFastForwards=false`，且有其他客户端 force push），那么「至多一方
成功」由**远端**而非 EnvSync 决定。

所有主流 Git 服务端默认拒绝非 fast-forward 更新，因此默认部署下强 CAS 成立。自建裸
仓库请确认：

```bash
# 在服务端的裸仓库里
git config receive.denyNonFastForwards true
git config receive.denyDeletes true
```

第 6 步的**发布后回读**把这条前提从「假设」变成了「可检测的事实」：远端若把分支指向
了一段不含本次提交的历史，回读就会发现，于是返回

```text
BackendError::Unsupported
  "远端接受 push 后把受信分支指向了不含本次提交的历史：该远端未强制 fast-forward，无法提供强 CAS"
```

上层据此拒绝把该远端用于多设备写入。代价是每次 Ref 发布多一次 fetch。

### 2.3 已知的窄化情形：libgit2 本地文件传输

libgit2 的**本地文件传输**（`file://` 或裸路径）只在**客户端**做 fast-forward 检查，
服务端不复核。

| 传输方式 | fast-forward 检查发生在 |
|---|---|
| `https://` / `ssh://` / `git@host:path` | **服务端**（`receive-pack`），强 CAS 成立 |
| `file:///…` / `/srv/backend.git` | **客户端**（libgit2 内部），仅用于测试与可移动介质 |

即便在这种传输上出现真正的交错写入，push 后的回读也会发现自己的提交不在历史里，从而
**报错而不是假装成功**。因此本地传输的失败模式是「误报冲突」而不是「静默覆盖」。

**结论：真实的多设备同步请使用网络远端；本地路径远端只用于测试和单机可移动介质。**

### 2.4 对象写入 vs Ref 写入

两者的重试策略刻意不同：

| | 冲突时的行为 | 理由 |
|---|---|---|
| `put_object` | 在新 head 上重放，最多 **8** 次（`MAX_OBJECT_PUSH_ATTEMPTS`） | 对象是内容寻址的，写入可交换：谁先写都一样 |
| `compare_and_swap_ref` | **绝不重试**，原样返回 `CasConflict` | Ref 的先后顺序就是语义本身，重试等于覆盖别人的决定 |

8 次仍被抢先时报 `BackendError::Io`（「远端分支竞争过于激烈，请稍后重试」）。

`put_object` 还有两条一致性检查：写入前校验内容摘要与 `ObjectId` 相符；远端已存在同
标识但内容不同的对象时报 `BackendError::Corruption`。`get_object` 读出后重算摘要，
不符则报 `Corruption` 而**不返回内容**。

---

## 3. 认证

### 3.1 三种被允许的方式

| `auth.kind` | 凭据在哪 | EnvSync 进程内有什么 | M1 可用 |
|---|---|---|---|
| `ssh-agent` | ssh-agent 持有私钥 | 只有签名结果，**拿不到私钥** | ✅ |
| `credential-helper` | git 的 credential helper 现取现用 | 只有一次性取回的凭据，不落盘 | ✅ |
| `token-secret-ref` | Vault（M2）中的逻辑 Secret | 只有一个**引用标识**，不解析 | ❌ 连接时报错 |

`GitAuth` 是一个**封闭枚举**：「用户名 + 密码」「URL 内嵌 token」「明文凭据文件」这些
形式在类型层面就无法表达。从字符串构造只有 `GitAuth::parse` 一条路，它拒绝未知种类。

`token-secret-ref` 在 M2 的 Vault 落地之前**不会被解析**，因此进程内不存在可被 dump
的 token。现在用它发起连接会得到：

```text
token secret 引用要到 M2 的 Vault 才会被解析，当前无法用于连接
```

`secret_id` 必须是**引用形态**：非空、≤128 字节、只含 `A-Za-z0-9._:-`。这条字符集限
制同时挡下了最常见的误用——把 token 原文（通常含 `/`、`+`、`=` 或空白）粘进 `secret_id`。

### 3.2 为什么 URL 里不能带 userinfo 与查询串

`validate_remote_url` 在**打开后端之前**执行，把凭据挡在配置边界外：

| 规则 | 被拒绝的例子 | 理由 |
|---|---|---|
| 非空、≤2048 字节 | 超长 URL | 避免把超长输入塞进日志 |
| 不含控制字符或空白 | `https://h\r\nX:` | 防 CRLF 注入进日志 |
| 不含片段（`#`） | `https://h/r.git#x` | git 远端不需要片段 |
| scheme 只允许 `https` / `ssh` / `file`，或无 scheme 的本地路径 / scp 风格 | `http://…`、`git://…` | `http` 与 `git` 协议**不加密**，凭据和内容都会明文过网 |
| **不得包含 userinfo** | `https://user:pass@git.example.com/r.git`、`https://user@git.example.com/r.git` | 配置文件会被同步、被备份、被 `cat` 到终端；写进去的凭据就再也收不回来了 |
| ssh 的例外 | `git@git.example.com:team/dotfiles.git` ✅ / `git:pass@…` ❌ | `git` 是 ssh **登录名**而不是凭据；userinfo 里一旦出现 `:` 立刻拒绝 |
| **不得携带查询串** | `https://git.example.com/r.git?access_token=…` | `?access_token=…` 是 token 泄漏的经典载体，而 git 远端从不需要查询参数——整段禁掉最简单也最安全 |
| 必须有主机名（`file://` 除外） | `https:///r.git` | — |

所有拒绝路径返回 `BackendError::Unsupported`，其载荷是 `&'static str`。这不是偷懒：
**静态字符串在类型层面就不可能插值进用户提供的 URL**，于是「错误信息泄漏凭据」这条
风险被编译器消除，而不是靠代码评审保证。

### 3.3 redaction 保证

| 函数 | 输出 | 用在哪 |
|---|---|---|
| `remote_host(url)` | 仅主机（可能带端口）；本地远端返回 `<local>` | **`tracing` 里唯一允许出现的远端标识** |
| `redacted_remote(url)` | userinfo → `***`，查询串 → `<redacted>`，本地路径 → `<local>` | `Debug` 实现、错误上下文 |
| `scrub(text)` | 把底层 git 错误文本里含 `://` 或 `@` 的词逐个替换成 `redacted_remote` 的输出 | 所有从 libgit2 冒上来的错误文本 |

```text
https://user:pass@git.example.com/team/dotfiles.git   →  https://***@git.example.com/team/dotfiles.git
https://git.example.com/r.git?access_token=abcdefgh   →  https://git.example.com/r.git?<redacted>
git@git.example.com:team/dotfiles.git                 →  ***@git.example.com:team/dotfiles.git
/home/YOUR_USER/envsync-remote.git                    →  <local>
file:///srv/YOUR_BACKEND/envsync.git                  →  file://<local>
```

**本地路径一律替换成 `<local>`**：`/home/<user>/…` 既暴露用户名又属于本机信息，不该
进日志。

`GitConfig` 与 `GitBackend` 都**手写** `Debug`：远端 URL 经过脱敏，`cache_dir`（绝对
路径）打印为 `<private>`，`GitAuth::TokenSecretRef` 的 `secret_id` 打印为 `***`。派生
实现会把这些原样打出来，一次 `tracing::debug!(?config)` 就够了。

CLI 的输出还会再过一遍 `envsync-cli` 的通用脱敏器（见 [命令行文档](../cli.md#5-脱敏)），
这是最后一道防线而不是唯一一道。

---

## 4. 配置

### 4.1 字段

```yaml
version: 2                 # Git 后端需要配置版本 2；写在 version: 1 里会被拒绝
backend:
  kind: git
  remote_url: "git@git.example.com:team/dotfiles.git"
  branch: "envsync"        # 可省略，默认 envsync
  cache_dir: ".envsync/git-cache"   # 可省略，默认 <state_dir>/git-cache
  auth:
    kind: ssh-agent        # ssh-agent | credential-helper | token-secret-ref
```

| 字段 | 必需 | 说明 |
|---|---|---|
| `remote_url` | 是 | 通过 `validate_remote_url`；写 `path` 会报「`path` 只属于 local 后端」 |
| `branch` | 否 | **唯一受信来源**；读取与 CAS 都只看它，远端 `HEAD` 指向哪里无关紧要 |
| `cache_dir` | 否 | 私有 bare cache clone 的位置 |
| `auth` | 是 | 缺失时错误信息会列出三个可选值 |

分支名采用 git ref 命名规则的一个**保守子集**：只允许 `A-Za-z0-9._/-`，≤255 字节，
不得以 `/` 或 `.` 开头/结尾，不得含 `//`、`..`，不得以 `.lock` 结尾。收紧字符集顺带
挡掉了控制字符和换行注入（分支名会进入 `tracing`）。

### 4.2 SSH 配置完整示例

**只用虚构凭据与占位主机。**

```yaml
# /home/YOUR_USER/.config/envsync/envsync.yaml
version: 2
workspace_id: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"

device:
  name: "laptop"
  seed_hex: "3a7f1c92b4de5068a1cf23947db6e50f8c41a2937be05d6c1f83a4b72e90cd15"

backend:
  kind: git
  # scp 风格：`git` 是 ssh 登录名，不是凭据。
  remote_url: "git@git.example.com:team/dotfiles.git"
  branch: "envsync"
  auth:
    kind: ssh-agent

state_dir: ".envsync"

roots:
  home: "/home/YOUR_USER"

profile:
  tags: ["work", "laptop"]

resources:
  - id: shell/zsh/main
    root: home
    target: .zshrc
    mode: managed_block
    disposition: managed
```

准备工作：

```bash
# 1) 确认 agent 里有可用私钥（EnvSync 不读磁盘上的私钥文件）
ssh-add -l

# 2) 确认能连上远端（这一步用系统 git，不经过 EnvSync）
ssh -T git@git.example.com

# 3) 远端仓库需要事先存在（可以是空仓库）；EnvSync 不会创建远端仓库。
#    分支不存在时视为「空后端」，第一次发布会连同格式标记一起创建它。

# 4) 体检
envsync doctor --config /home/YOUR_USER/.config/envsync/envsync.yaml
```

`ssh://` 形式也可以，同样不得带密码段：

```yaml
  remote_url: "ssh://git@git.example.com:2222/team/dotfiles.git"
```

### 4.3 HTTPS 配置完整示例

HTTPS 走 git 的 credential helper，凭据由 helper 现取现用，EnvSync 不接触也不保存。

```yaml
backend:
  kind: git
  # 注意：URL 里没有用户名、没有密码、没有 ?access_token=
  remote_url: "https://git.example.com/team/dotfiles.git"
  branch: "envsync"
  auth:
    kind: credential-helper
```

准备工作：

```bash
# 1) 配一个 helper（下面三种任选其一，都是系统 git 的能力，与 EnvSync 无关）
git config --global credential.helper store          # 明文文件，仅测试用
git config --global credential.helper osxkeychain    # macOS 钥匙串
git config --global credential.helper manager        # Windows Credential Manager

# 2) 先用系统 git 走一次，让 helper 把凭据存下来
git ls-remote https://git.example.com/team/dotfiles.git

# 3) 体检
envsync doctor --config /home/YOUR_USER/.config/envsync/envsync.yaml
```

**M2 之后**才可用的写法（现在配置能通过校验，但连接时会报错）：

```yaml
backend:
  kind: git
  remote_url: "https://git.example.com/team/dotfiles.git"
  auth:
    kind: token-secret-ref
    # 这里填的是 Vault 里的**逻辑标识**，不是凭据本身。
    secret_id: "envsync:git:example"
```

---

## 5. 私有 cache clone

| 项 | 值 |
|---|---|
| 位置 | `backend.cache_dir`，默认 `<state_dir>/git-cache` |
| 形态 | **bare 仓库**（`Repository::init_bare`） |
| Unix 权限 | 目录设为 `0700` |
| 远端配置 | **匿名 remote**：URL 不会被写进仓库 `config`，凭据相关配置也就不会落盘 |
| 远端分支镜像 | `refs/remotes/envsync/<branch>` |
| fetch refspec | `+refs/heads/<branch>:refs/remotes/envsync/<branch>`，`prune=on`，不下载 tag |

**作用**

1. 避免每次操作都全量下载：对象已经在镜像里时不必联网；
2. 把「远端说了什么」（`refs/remotes/envsync/…`）和「我们本地造了什么」在仓库里一眼
   分开；
3. 让 fetch → 构造 commit → push 这一段成为进程内的临界区（`Mutex`），避免同一进程的
   两个线程互相制造无谓的 CAS 冲突。

**为什么用 `refs/remotes/` 而不是 `refs/heads/`**：`refs/heads/` 是「本地分支」的语
义，把远端状态写进去会让「谁是权威」变得含糊。EnvSync 的权威永远是远端。

**为什么开 prune**：远端分支被删除时本地镜像随之消失，`head` 归零。绝不用陈旧镜像冒
充远端状态——那会让 CAS 基于过期 revision 做判断。

**cache 里有什么**：用户配置的**完整历史**。它不是缓存意义上的「可有可无」，而是包含
真实内容的 Git 仓库，因此权限收紧到 `0700`。

**清理方式**

```bash
# 1) 先确认没有未完成操作与未解决冲突
envsync status --config "$CFG" --json | jq '{state: .data.state, conflicts: .data.open_conflicts, unfinished: .data.unfinished}'

# 2) 直接删除整个 cache 目录（远端才是权威，cache 只是镜像）
rm -rf /home/YOUR_USER/.config/envsync/.envsync/git-cache

# 3) 下一次任何命令都会重新 init_bare 并 fetch
envsync fetch --config "$CFG"
```

删 cache 是**安全**的：它不含任何只存在于本地的事实。真正不能删的是
`<state_dir>/journal.db`（操作日志）、`<state_dir>/draft/`（草稿与冲突索引）和
`<state_dir>/backups/`。

---

## 6. 离线行为

Git 后端的每次读写都要联网，因此离线时的行为需要明确：

| 命令 | 离线时 | 说明 |
|---|---|---|
| `envsync fetch` | **失败**（`io`，退出码 1） | fetch 是显式的联网动作 |
| `envsync status` | **失败** | `status` 要读 `get_ref`，即先 fetch |
| `envsync plan` | **失败** | 计划要绑定后端 revision |
| `envsync sync` | **失败** | 发布必须联网 |
| `envsync merge` | 视情况 | 合并基与内容都在本地草稿库时可以完成；缺对象时报 `object.missing` |
| `envsync conflicts list/show/resolve` | **成功** | 只读写本地冲突索引与草稿库 |
| `envsync doctor` | 报告后端不可达，但命令本身退出码 0 | `doctor` 只报告不修改 |

结论：**离线时可以继续裁决冲突，但不能计划、不能发布。** 想在离线环境下继续工作，
先用 `envsync fetch` 把远端对象拉进草稿库，再断网。

错误信息里只会出现 `host=git.example.com, branch=envsync` 这样的上下文，不会出现 URL
全文、路径或凭据。

---

## 7. 换后端步骤

Local ↔ Git 之间搬迁是安全的：**对象字节完全相同**，只是布局不同。

```text
迁移前  →  确认没有未完成操作、没有未解决冲突、没有未发布草稿
        →  备份 <state_dir>（journal.db + draft/ + backups/）
        →  改 backend 段
        →  重新发布一次，让新后端拿到完整的对象闭包
```

### 7.1 Local → Git

```bash
CFG=/home/YOUR_USER/.config/envsync/envsync.yaml

# 1) 确认干净：state 必须是 clean，unfinished 为空，open_conflicts 为 0
envsync status --config "$CFG" --json | jq '{state:.data.state, head:.data.head, revision:.data.revision, conflicts:.data.open_conflicts, unfinished:.data.unfinished}'

# 2) 备份本地状态目录（换后端不改它，但出问题时这是唯一的回头路）
tar czf /home/YOUR_USER/envsync-state-backup.tgz \
    -C /home/YOUR_USER/.config/envsync .envsync

# 3) 在远端准备一个**空仓库**；EnvSync 不会替你创建它。

# 4) 编辑配置：把 backend 段整体换掉，并把 version 提升到 2
#      backend:
#        kind: git
#        remote_url: "git@git.example.com:team/dotfiles.git"
#        branch: "envsync"
#        auth:
#          kind: ssh-agent
#    注意 `path` 必须删掉——git 后端出现 `path` 会报 config.invalid_backend。

# 5) 体检（这一步会真正连一次远端并校验格式标记）
envsync doctor --config "$CFG"

# 6) 重新捕获 + 计划 + 发布：新后端从 revision 0 开始
envsync capture --config "$CFG"
envsync plan    --config "$CFG"
envsync sync    --config "$CFG" --plan <plan-id>

# 7) 确认
envsync status --config "$CFG"
```

**revision 会从 0 重新计数**：Ref 的 revision 是每个后端各自的单调计数器，不跨后端延
续。历史快照仍然可以通过 `parents` 链回溯，只要对象被上传到新后端。第 6 步的
`sync` 会上传目标快照的可达闭包；**更早的历史对象不会自动迁移**。需要完整历史时，先
在旧后端上 `list_objects` 导出，再逐个 `put_object` 到新后端。

### 7.2 Git → Local

步骤对称：先 `envsync fetch` 把远端对象全部拉进本地草稿库，再把 `backend` 换成
`kind: local` + `path`，然后 `capture` → `plan` → `sync`。

### 7.3 换分支

换 `branch` 等价于换了一个后端：新分支上没有格式标记，第一次发布会创建它，revision
从 0 开始。**不要**指望切分支能保留 revision。

---

## 8. 备份建议

| 对象 | 权威在哪 | 要不要备份 | 怎么备份 |
|---|---|---|---|
| Git 远端仓库 | 远端 | **要** | 服务端快照，或 `git clone --mirror` |
| `<state_dir>/journal.db` | 本机 | **要** | 停止 EnvSync 后整文件复制 |
| `<state_dir>/draft/` | 本机 | **要** | 含草稿对象与冲突索引 |
| `<state_dir>/backups/` | 本机 | **要** | 回滚收据依赖它 |
| `<state_dir>/git-cache/` | 远端的镜像 | **不用** | 删了会自动重建 |
| 配置文件 `envsync.yaml` | 本机 | **要** | 含 `device.seed_hex`（本机私有材料） |

三条要点：

1. **`device.seed_hex` 丢了就换了一台设备。** 它派生 `DeviceId`，而 `DeviceId` 是
   `device_overrides` 的键、`device` 谓词的取值、快照作者字段。丢失后所有针对这台机器
   的特例都会失效。它绝不会被上传到后端，所以只有本地备份能救它。
2. **远端仓库的镜像备份**：

   ```bash
   git clone --mirror git@git.example.com:team/dotfiles.git /srv/YOUR_BACKUP/dotfiles.git
   cd /srv/YOUR_BACKUP/dotfiles.git && git remote update
   ```

   镜像里就是完整的 `.envsync/` 布局，可以直接作为 `file://` 远端读出来做灾难恢复
   （注意 2.3 节：本地传输不提供服务端 fast-forward 检查，只适合只读恢复）。
3. **不要把一台设备的 `state_dir` 复制到另一台**：里面是本机的操作日志、草稿库和备
   份，跨设备复用会让崩溃恢复读到别人的历史。

---

## 9. 故障排查

| 现象 | 典型错误码 / 信息 | 原因 | 处理 |
|---|---|---|---|
| **认证失败** | `io`，`git fetch（host=git.example.com, branch=envsync）` | agent 里没有可用私钥；helper 没存过凭据；远端要求的凭据类型不受所配方式支持 | `ssh-add -l` 确认 agent；用系统 `git ls-remote <url>` 单独验证；HTTPS 换 `credential-helper` |
| 配置一保存就报错 | `config.invalid_backend`，「远端 URL 不能包含 userinfo」 | URL 里写了 `user:pass@` 或 `user@`（非 ssh） | 去掉 userinfo，凭据交给 agent / helper |
| 配置报错且提到查询串 | `config.invalid_backend`，「远端 URL 不能携带查询串」 | URL 带了 `?access_token=…` | 去掉查询串；M2 起用 `token-secret-ref` |
| 用了 `token-secret-ref` 就连不上 | `unsupported`，「token secret 引用要到 M2 的 Vault 才会被解析」 | 该方式在 M1 尚不可用 | 改用 `ssh-agent` 或 `credential-helper` |
| **非 fast-forward 被拒** | `cas_conflict`，退出码 **10** | 别的设备在你 fetch 之后先发布了 | 这是**正常**竞争：`envsync fetch` → `envsync merge` → `envsync plan` → `envsync sync`。**本地一个字节都没被写过** |
| 反复 `cas_conflict` | 同上 | 多台设备在同一秒发布，或某台设备在循环里重试 | 错开发布；检查是否有脚本在无退避地重试 |
| push 被接受但报 `unsupported` | 「远端接受 push 后把受信分支指向了不含本次提交的历史」 | 远端允许非 fast-forward 更新，或有人 force push 了受信分支 | 在服务端设 `receive.denyNonFastForwards=true`；查谁 force push 了 |
| push 被接受但分支不存在 | 「远端接受 push 后受信分支却不存在」 | 远端有钩子删除/改写了引用 | 检查服务端钩子；换一个干净的仓库 |
| 对象 push 一直失败 | `io`，「连续 8 次被并发写入抢先」 | 分支竞争过于激烈 | 稍后重试；减少同时发布的设备数 |
| **cache 损坏** | `io`，「打开 cache 仓库」/「初始化 cache 仓库」 | cache 目录被外部删了一半、磁盘写满、权限被改 | 直接 `rm -rf <cache_dir>`，再跑一次命令即可（见第 5 节）。cache 不含只存在于本地的事实 |
| cache 目录权限异常 | `io`，「cache 目录权限」 | Unix 上无法设为 `0700` | 检查文件系统是否支持权限位（例如挂载的 FAT/exFAT）；把 cache 换到本地磁盘 |
| **format 标记不匹配** | `format_mismatch`，`expected` 是 `envsync-git-format=1\n` | 受信分支上的 `.envsync/format` 内容不同 | 说明这个分支是**别的东西**：可能指向了普通代码分支，或来自未来版本的 EnvSync。**绝不在上面追加提交**——换一个空分支，或升级 EnvSync |
| format 标记为空 | `format_mismatch`，`found` 是空串 | 分支存在但根本没有 `.envsync/format` | 你把 `branch` 指到了一个普通分支上。改 `branch` |
| 布局被破坏 | `unsupported`，「EnvSync 路径下出现了非文件对象」 | 有人在 `.envsync/` 下放了目录或 submodule | 检查是谁往受信分支推了东西；受信分支只应由 EnvSync 写 |
| 对象读出来摘要不符 | `corruption` | 远端对象被改写 | 严重问题：远端不可信。换后端并从备份恢复 |
| 远端已有同标识不同内容的对象 | `corruption`，「远端已存在同标识但内容不同的对象」 | 内容寻址被破坏（几乎只可能是人为构造） | 同上 |

排查时的通用第一步：

```bash
# 后端可达性、格式标记、授权根、schema 版本一次看全；doctor 绝不修改任何东西
envsync doctor --config "$CFG" --json | jq '.data.findings'

# 想看 libgit2 的详细过程（日志固定写 stderr，且已过脱敏）
envsync fetch --config "$CFG" -vvv
```

---

## 10. 相关文档

- [命令行文档](../cli.md)：`fetch` / `merge` / `sync` 的参数、JSON 契约与退出码
- [冲突处理](../conflicts.md)：CAS 冲突（退出码 10）与合并冲突（退出码 13）的区别
- [设备 Profile 与投影](../profiles.md)：多设备下同一快照如何产生不同的本地计划
- [安全模型](../security-model.md)：信任边界与 M1 **不提供**的保证
- [M0 运维手册](../m0-operations.md)：备份、恢复与版本兼容策略
- [Git 后端配置示例](../../examples/workspace-git.yaml)
- ADR-0004（Backend 与适配器 trait 采用同步 I/O）：`docs/decisions/2026-07-26-synchronous-backend-trait.md`
