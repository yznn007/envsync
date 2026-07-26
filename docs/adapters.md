# 内建适配器（M1）

适配器回答三个问题：

1. **这台设备上有哪些资源应该被管理**（`discover`）；
2. **从一份原始文件里应该抽出哪些字节作为受管内容**（`capture`）；
3. **给定受管内容，目标文件最终应该长成什么样**（`render` / `verify`）。

实现见 `crates/envsync-adapters/`。

> **适配器怎么被用上**：CLI 通过两条命令消费 `envsync-adapters`——
>
> | 命令 | 作用 |
> |---|---|
> | `envsync adapters list [--all]` | 列出内建适配器（ID、展示名、版本、支持平台、所需 capability、目标资源），默认按本设备 Profile 过滤 |
> | `envsync adapters discover` | 对本设备跑一次 `discover_all`，输出**可直接粘贴进配置**的 `resources:` 片段 |
> | `envsync init --discover` | 初始化时直接把发现结果写进生成的配置 |
>
> 分工没有变：适配器只做**纯计算**（给定 Profile 与授权根，算出「这台设备上应该管哪些
> 文件」），真正的捕获与写入仍然由配置文件的 `resources` 列表驱动。`discover` 的产物
> 因此是**一段配置**，而不是一条绕过配置直接生效的旁路——用户始终看得到、改得动、
> 审阅得了自己在同步什么。
>
> 下表既是"内建适配器清单"，也是"手写配置时的推荐资源表"：照抄这些标识、路径、模式与
> 选择器，就能得到与 `adapters discover` 完全一致的结果。

---

## 1. 内建适配器清单

`AdapterRegistry::builtin()` 装载五个适配器，按 ID 字典序索引。

| 适配器 ID | 版本 | 展示名 | 支持平台 | 所需 capability | `default_mode` |
|---|---|---|---|---|---|
| `builtin.shell.bash` | 1 | Bash 启动文件 | macOS、Linux | 无 | `managed_block` |
| `builtin.shell.zsh` | 1 | Zsh 启动文件 | macOS、Linux | 无 | `managed_block` |
| `builtin.shell.powershell` | 1 | PowerShell Profile | macOS、Linux、Windows | **`pwsh`** | `managed_block` |
| `builtin.terminal.wezterm` | 1 | WezTerm 配置 | macOS、Linux、Windows | 无 | `generated_include` |
| `builtin.vcs.git` | 1 | Git 配置 | macOS、Linux、Windows | 无 | `structured_merge` |

**适配器 ID 跨版本不得更改**：它会进入日志、配置与诊断输出。语义变化请提升
`version`。注册表**拒绝重复 ID**——两个适配器声称管理同一批资源会让"谁的渲染结果生效"
变成不确定行为。

`default_mode` 只是**展示与诊断用的语义标签**，具体资源用的模式见下表。

### 1.1 资源清单

| 资源标识 | 授权根 | 目标路径 | 模式 | 结构化格式 | 处置 | 注释前缀 | 权限位 | 选择器 |
|---|---|---|---|---|---|---|---|---|
| `shell/bash/bashrc` | `home` | `.bashrc` | `managed_block` | — | `managed` | `# ` | `0644` | — |
| `shell/bash/bash_profile` | `home` | `.bash_profile` | `managed_block` | — | `managed` | `# ` | `0644` | — |
| `shell/zsh/zshrc` | `home` | `.zshrc` | `managed_block` | — | `managed` | `# ` | `0644` | — |
| `shell/zsh/zshenv` | `home` | `.zshenv` | `managed_block` | — | `managed` | `# ` | `0644` | — |
| `shell/powershell/profile-windows` | `home` | `Documents/PowerShell/Microsoft.PowerShell_profile.ps1` | `managed_block` | — | `managed` | `# ` | `0644` | `all[os=windows, capability=pwsh]` |
| `shell/powershell/profile-xdg` | `home` | `.config/powershell/Microsoft.PowerShell_profile.ps1` | `managed_block` | — | `managed` | `# ` | `0644` | `all[any[os=macos, os=linux], capability=pwsh]` |
| `terminal/wezterm/module` | `home` | `.config/wezterm/envsync.lua` | **`full_file`** | — | `managed` | `-- ` | `0644` | — |
| `terminal/wezterm/include` | `home` | `.wezterm.lua` | **`managed_block`** | — | `managed` | `-- ` | `0644` | — |
| `vcs/git/user` | `home` | `.gitconfig` | `structured_merge` | `git_config` | `managed` | `# ` | `0644` | — |
| `vcs/git/user-xdg` | `home` | `.config/git/config` | `structured_merge` | `git_config` | `managed` | `# ` | `0644` | `all[tag=git-xdg]` |
| `vcs/git/system` | **`system`** | `gitconfig` | `structured_merge` | `git_config` | **`unmanaged`** | `# ` | 不设置 | — |

两个约定的授权根别名：

| 常量 | 别名 | 用途 |
|---|---|---|
| `ROOT_HOME` | `home` | 用户主目录。`roots` 里缺失时退回 `AdapterContext::home_relative` |
| `ROOT_SYSTEM` | `system` | 系统级配置（POSIX 的 `/etc`）。**只用于观察**；宿主没有注册该别名时相关资源根本不会被发现 |

### 1.2 过滤发生在三层

`AdapterRegistry::discover_all` 的筛选顺序：

```text
① AdapterDescriptor::applies_to(profile)
     操作系统在 supported_os 内 ∧ required_capabilities 全部具备
              ↓ 通过
② Adapter::discover(ctx)
     适配器自身的判断，例如授权根缺失时**跳过**该资源（不是报错——
     宿主可能只授权了主目录，这属于正常配置而不是故障）
              ↓
③ DiscoveredResource::selector
     资源级选择器；先 validate 再 matches，校验失败保守判为「不匹配」
              ↓
     结果按资源标识排序
```

单个适配器出错**不会中断整体发现**：错误被记录到 `tracing` 后跳过该适配器——否则一个
适配器的边角问题会让整台设备无法同步。

### 1.3 内建适配器绝不产出 tombstone

`DiscoveredResource::disposition` 只会是 `managed` 或 `unmanaged`，**永远不会**是
`ensure_absent`。删除意图必须由用户在配置里显式表达，与 [投影层的规则](profiles.md#4-投影只能缩小或转换意图不能生成-tombstone)
是同一条约束在适配器层的落地。

---

## 2. 为什么 `Adapter` 是 sealed 的

`Adapter` 继承一个私有的 `sealed::Sealed`，因此**只有 `envsync-adapters` 内部的类型能
实现它**。

```rust
pub(crate) mod sealed {
    pub trait Sealed {}
}

pub trait Adapter: sealed::Sealed + Send + Sync { /* … */ }
```

### 2.1 理由

一个能被任意 crate 实现的 trait，等价于把**「在 EnvSync 进程内执行任意代码」**这一权限
开放给第三方——而适配器恰好负责决定**哪些文件会被读写**。把这两件事放在一起，安全模型
就没有边界可言了：一个第三方适配器可以在 `discover` 里返回任意路径，在 `render` 里返回
任意字节，而宿主没有任何结构性手段拦住它。

M1 因此刻意只允许**编译期内建**适配器。

### 2.2 适配器的最小权限

`AdapterContext` 的字段集合本身就是一条安全约束：

```rust
pub struct AdapterContext<'a> {
    pub profile: &'a DeviceProfile,          // 我是谁
    pub roots: &'a BTreeMap<String, String>, // 授权根别名 → 该根下的**相对前缀**
    pub home_relative: &'a str,              // roots["home"] 的便捷回退
}
```

**没有** Backend、**没有** Journal、**没有**文件系统句柄、**没有**绝对路径。适配器因此
在类型层面就不可能读写授权根之外的任何东西——它连表达一个绝对路径的手段都没有。
`DiscoveredResource::target` 永远是**相对授权根**的路径，且已通过
`envsync_platform::RelativeTarget` 校验。

四个方法**全部是纯函数**：不读文件系统、不取时钟、不用随机数、不发起网络请求，且**确
定性**——对同一输入连续调用两次必须返回逐字节相同的结果。计划阶段（预演）与应用阶段会
各调用一次 `render`，两次结果不同就意味着预演结果不可信。

真正的读、写、备份、回滚全部由宿主完成（`envsync-core` 的捕获与应用服务，配合
`envsync-platform` 的能力句柄）。

### 2.3 与 M4 插件 SDK 的关系

**M4 的插件 SDK 不会放开这个 trait。**

```text
M1（现在）                        M4（计划）
┌────────────────────┐           ┌────────────────────┐   ┌──────────────────┐
│ envsync 进程        │           │ envsync 进程        │   │ 插件子进程        │
│  ┌──────────────┐  │           │  ┌──────────────┐  │   │ ┌──────────────┐ │
│  │ 内建适配器    │  │           │  │ 内建适配器    │  │   │ │ 第三方适配器  │ │
│  │ (sealed trait)│  │           │  │ (sealed trait)│  │   │ └──────┬───────┘ │
│  └──────────────┘  │           │  └──────────────┘  │   │        │         │
└────────────────────┘           │        ▲            │   └────────┼─────────┘
                                 │        │  受限 IPC   │            │
                                 │        └────────────┼────────────┘
                                 │   宿主在边界上做      │
                                 │   能力裁剪 + 资源配额  │
                                 └────────────────────┘
```

插件运行在**单独的子进程**里，通过受限的 IPC 协议交换与本模块**同构**的消息
（descriptor / discover / capture / render / verify），由宿主在边界上做能力裁剪与资源
配额。

换句话说：**扩展点是协议，而不是 trait 实现。** 这样做的收益是——

| | sealed trait + IPC 插件 | 开放 trait |
|---|---|---|
| 插件崩溃 | 子进程死掉，宿主报错继续 | 整个进程一起挂 |
| 插件死循环 / 内存爆炸 | 宿主可以设超时与配额 | 无法约束 |
| 插件访问任意文件 | 宿主在 IPC 边界校验每个路径 | 插件与宿主同权限 |
| 消息格式演进 | 协议版本号，可拒绝未知版本 | ABI 兼容噩梦 |

内建适配器与插件共用同一套消息形状，因此这条演进路径不需要重构内建适配器。

---

## 3. WezTerm：Generated Include 为什么拆成两个资源

设计文档 §5 把 Generated Include 描述为「生成独立文件，再向主配置注入一个
include/source」。它在本质上就是**两件事**，而这两件事恰好各自对应一种已经实现且经过
测试的模式：

| 资源 | 模式 | 目标 | 作用 |
|---|---|---|---|
| `terminal/wezterm/module` | `full_file` | `.config/wezterm/envsync.lua` | EnvSync **独占**的生成文件 |
| `terminal/wezterm/include` | `managed_block` | `.wezterm.lua` | 向用户主配置注入 include 语句 |

### 3.1 收益

1. **不新增渲染模式。** `envsync-core::render` 只需要继续支持 Full File 与 Managed
   Block 两种模式。`FileMode::GeneratedInclude` 只出现在
   `AdapterDescriptor::default_mode` 里，作为对外的**语义标签**——它告诉用户"这个适配器
   采用生成+注入的组合"，而不是一种需要在渲染层特殊处理的模式。

   **少一种模式就少一套 marker 处理、少一套幂等判定、少一套回滚路径。** 用两个已有模式
   组合出一个新语义，比新增一条代码路径便宜得多，也安全得多。

2. **生成文件可以被整份覆盖与整份校验**，语义最简单，出错时可以直接重写。

3. **用户主配置只被注入一小段 marker 包裹的 include 语句**，块外的手写配置逐字保留；
   卸载 EnvSync 时只需移除该块。

### 3.2 注入的 Lua 语句

```lua
-- 这段内容由 EnvSync 生成，请勿手工编辑；块外的配置属于你自己。
package.path = require("wezterm").home_dir
  .. "/.config/wezterm/?.lua;"
  .. package.path
ENVSYNC = require("envsync")
```

它做三件事：把 `~/.config/wezterm` 加入 Lua 的 `package.path`；`require("envsync")`
加载生成模块；把结果绑定到全局变量 `ENVSYNC`，用户可以在受管块之外自由引用。

**这段文本里没有任何本机绝对路径**：路径在运行期由 WezTerm 自己的 `wezterm.home_dir`
拼出。因此同一段字节可以安全地同步到用户名、主目录完全不同的其他设备。

注释前缀是 `-- `（Lua 语法），不是默认的 `# `——注释语法不同的文件必须显式指定，否则
marker 行本身会成为语法错误。

---

## 4. 系统级 Git 配置：只观察，绝不写入

`vcs/git/system`（POSIX 上的 `/etc/gitconfig`）以 `DesiredDisposition::Unmanaged` 产出，
处置**恒为** `Unmanaged`，不受任何配置影响。

### 4.1 三条理由

1. **它需要提升权限才能写。** 资源位于授权根 `system` 下，写它意味着 EnvSync 要能以
   root 身份改文件——把这个能力引进来，就等于把整个安全模型的爆炸半径从"用户主目录"
   扩大到"整台机器"。
2. **它影响机器上的所有用户。** 跨设备同步它等于把一台机器的策略强加给另一台，也强加
   给那台机器上的其他用户。
3. **它经常由包管理器或企业策略托管。** EnvSync 覆写会与之打架：下一次
   `apt upgrade` 或策略推送就会把改动冲掉，然后 EnvSync 又改回来，无限循环。

### 4.2 "只观察"是代码强制的规则

`FileAdapter` 对 `Unmanaged` 资源有统一约束：

| 方法 | 行为 |
|---|---|
| `capture` | 返回 `None`——**只记录存在性，不采集内容** |
| `render` | 直接返回 `AdapterError::ObserveOnly`（错误码 `adapter.observe_only`） |

因此"只观察"不是一句注释，而是一条在代码里强制执行的规则：即使有人试图为该资源构造
写入动作，渲染阶段也会失败而不是写文件。

宿主没有注册 `system` 授权根时，该资源根本不会出现在 `discover` 的结果里——这是常见
情况，也是推荐配置。

**观察它有什么用**：`/etc/gitconfig` 里的设置会影响用户级配置的实际生效值。记录它的
存在性让 `doctor` 与诊断能解释"为什么这台机器上的 git 行为和别的机器不一样"，而不需要
获得写权限。

---

## 5. `~/.config/git/config` 为什么需要 `git-xdg` 标签

`vcs/git/user-xdg` 带一条选择器：

```rust
Selector::all([Predicate::Tag(TAG_XDG_GIT.to_owned())])   // TAG_XDG_GIT == "git-xdg"
```

### 5.1 原因：git 的查找顺序

**git 在 `~/.gitconfig` 存在时不会读取 XDG 路径下的 `~/.config/git/config`。**

```text
git 读用户级配置：
    ~/.gitconfig 存在？
        是 ──▶ 读它，**忽略** ~/.config/git/config
        否 ──▶ 读 $XDG_CONFIG_HOME/git/config（默认 ~/.config/git/config）
```

如果 EnvSync 默认把两者都设为受管，那么在一台同时有 `~/.gitconfig` 的机器上：

- EnvSync 认认真真地把内容写进了 `~/.config/git/config`；
- `envsync verify` 通过（文件内容确实与期望一致）；
- `envsync status` 显示 `clean`；
- **而 git 从头到尾没有读过这个文件。**

这是最糟糕的一类失败：**静默、可验证地错误**。工具的每一项自检都通过，用户的实际行为
却完全没变。而且两份内容会各自漂移——用户在一台机器上改 `~/.gitconfig`，在另一台改
`~/.config/git/config`，同步后互相覆盖。

### 5.2 因此：默认不下发，需要用户明确声明

`git-xdg` 标签的含义是「**这台设备使用 XDG 布局**」，必须由用户在设备的配置里写出来：

```yaml
profile:
  tags: ["git-xdg"]
```

没有这个标签时，`vcs/git/user-xdg` 在投影阶段被排除，诊断为 `excluded_by_selector`
（不是 `unsupported_capability`——这不是能力问题，是布局选择）。资源**不会被删除**，
只是本次不下发。

**用标签而不是自动探测**的理由：探测「有没有 `~/.gitconfig`」是一个会随时间变化的运行
期事实。今天没有、明天某个工具创建了一个，同步行为就会静默改变。标签是**用户的声明**，
它稳定、可审阅、可跨设备比较，也可以出现在 `envsync profile explain` 的输出里让用户
一眼看到。

### 5.3 建议

同一台设备**只**管理其中一个：

| 情况 | 配置 |
|---|---|
| 用传统布局（有 `~/.gitconfig`） | 不打 `git-xdg` 标签，管理 `vcs/git/user` |
| 用 XDG 布局（没有 `~/.gitconfig`） | 打 `git-xdg` 标签；同时**确认 `~/.gitconfig` 确实不存在** |

如果两者都存在且都想同步，请先在本机决定留哪一个、删掉另一个，再配置 EnvSync。

---

## 6. 三种模式的 capture / render 语义

| 模式 | `capture` | `render` |
|---|---|---|
| `full_file` | 整份文件即受管内容 | 期望内容即完整文件 |
| `managed_block` | 抽出 marker 之间的**块内**内容 | 只替换块内，**块外逐字保留** |
| `structured_merge` | 整份文件，并做一次结构化解析**校验** | 期望内容即完整文件 |

`capture` 返回 `Ok(None)` 表示「文件存在，但其中没有属于 EnvSync 的内容」（例如
Managed Block 尚未注入）。这与「文件不存在」是**不同的信号**，调用方不得把它当作删除
意图。

`render` 返回 `RenderedFile::Unchanged` 当且仅当渲染结果与 `existing` 逐字节相同，因此
本方法天然幂等。`verify` 的语义与 `render` 严格一致：verify 通过当且仅当以 `actual` 为
现状再渲染一次会得到 `Unchanged`。Managed Block 因此**只校验块内内容**，块外的用户内容
不参与比较。

### 6.1 Structured Merge 的职责边界

`FileMode::StructuredMerge` 描述的是**跨设备协调时用哪种语义去合并**，而不是「写盘时
怎么写」。

三方合并需要 base（上一次同步点的内容），而 `Adapter::render` 的签名里只有 `existing`
与 `desired`——**适配器没有 base，也不应该有**：它拿不到 Journal。因此分工是：

```text
跨设备三方合并    envsync-core::merge      有完整的 base/ours/theirs
                  按 StructuredFormat 选合并器

capture 校验      适配器复用**同一个**解析器，确认内容确实是合法的结构化配置，
                  避免把语法损坏的文件同步给其他设备

render 落盘       适配器只负责把合并后的权威字节写进文件
```

**复用同一个解析器**（而不是在适配器 crate 里再写一个）保证了「能被 capture 的内容一定
能被合并」——两侧不会出现解析口径漂移。

---

## 7. 怎么把这张表变成配置

### 7.1 让适配器替你写

```console
$ envsync adapters list --config envsync.yaml          # 先看清单
$ envsync adapters discover --config envsync.yaml      # 再要一段可粘贴的配置
```

`adapters discover` 输出的 `resources:` 片段由与 `WorkspaceConfig::to_yaml`
**同一套线格式类型**序列化，因此粘进配置文件之后一定能被解析回来。片段里取默认值的策略
字段（`max_bytes`、`line_ending`、`secret`）被省略——它们只会淹没真正要看的
`unix_mode` 与 `structured_format`，而解析时会取回同一个默认值。

初始化时想一步到位：

```console
$ envsync init --config envsync.yaml --backend-path backend --discover
```

两条命令都**按当前设备的 Profile 过滤**：缺少 `pwsh` 能力的机器不会看到 PowerShell 的
资源，没打 `git-xdg` 标签的机器不会看到 `~/.config/git/config`。`adapters list --all`
可以看全部（含本设备用不上的）。

配置里没有声明的授权根，其下的资源不会出现在结果里：没有 `system` 根时系统级 Git 配置
不会被列出（这是**推荐**配置，见第 4 节），命令会留一条 `adapters.system_root_not_declared`
的 info 诊断说明这件事。

### 7.2 手写时的两个注意点

1. **`mode: structured_merge` 已经可以直接写**（M1 起放开），但**必须同时声明**
   `policy.structured_format`，否则报 `config.structured_without_format`——声明了「按结构
   合并」却不说按哪种语法，是配置本身自相矛盾：

   ```yaml
   - id: vcs/git/user
     root: home
     target: .gitconfig
     mode: structured_merge
     disposition: managed
     policy:
       structured_format: git_config   # ← 必须有；决定用哪个合并器
       unix_mode: "0644"
   ```

   `mode` 与 `policy.structured_format` 的分工：前者声明**落盘语义**（Structured Merge 与
   Full File 一样，把权威字节整份写入），后者声明**跨设备协调时按哪种语法比较**。
   写成 `mode: full_file` + `structured_format: git_config` 同样能触发结构化合并，两种写法
   的行为一致；`structured_merge` 只是把意图写得更明白。

2. **`mode: generated_include` 仍然被拒绝**（`config.mode_not_supported`）。它不是一种
   渲染模式，而是「生成独立文件 + 向主配置注入 include」这两件事的组合，由适配器拆成
   **Full File + Managed Block 两个资源**实现（见第 3 节）。WezTerm 的两条资源可以原样
   照抄：

   ```yaml
   - id: terminal/wezterm/module
     root: home
     target: .config/wezterm/envsync.lua
     mode: full_file
     disposition: managed
     comment_prefix: "-- "
     policy:
       unix_mode: "0644"

   - id: terminal/wezterm/include
     root: home
     target: .wezterm.lua
     mode: managed_block
     disposition: managed
     comment_prefix: "-- "
     policy:
       unix_mode: "0644"
   ```

完整可解析的示例见 [`examples/workspace.yaml`](../examples/workspace.yaml) 与
[`examples/workspace-git.yaml`](../examples/workspace-git.yaml)。

---

## 8. 错误码速查

| 错误码 | 触发条件 |
|---|---|
| `adapter.duplicate_id` | 注册表中已存在同名适配器 |
| `adapter.unknown_resource` | 请求的资源不属于该适配器 |
| `adapter.invalid_target` | 授权根前缀与相对分段拼出的目标非法 |
| `adapter.render` | 渲染失败（marker 异常、非 UTF-8、超出字节上限等） |
| `adapter.structured` | 结构化内容解析失败；`detail` 只描述结构位置，**不含正文** |
| `adapter.observe_only` | 试图渲染一个 `unmanaged` 资源（例如系统级 Git 配置） |
| `adapter.verify_failed` | 目标文件与期望不符；`detail` 不含正文 |

所有变体的 `Display` 输出都**不含本机绝对路径**：只出现资源标识、授权根别名和相对
分段，可以直接写进日志或 JSON 诊断。

---

## 9. 相关文档

- [设备 Profile 与投影](profiles.md)：selector 语法、能力缺失的处理、`git-xdg` 这类标签怎么声明
- [合并规则](merge.md)：`structured_format` 各取值的合并规则与已知限制
- [冲突处理](conflicts.md)：合并冲突的裁决流程
- [命令行文档](cli.md)：命令、JSON 契约与退出码
- [配置示例](../examples/workspace.yaml)
- 系统设计 §5：`docs/superpowers/specs/2026-07-24-envsync-design.md`
- ADR-0004（Backend 与适配器 trait 采用同步 I/O）：`docs/decisions/2026-07-26-synchronous-backend-trait.md`
