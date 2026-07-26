# 设备 Profile 与投影（M1）

Workspace Snapshot 是**唯一**完整的期望状态，它描述「整个工作区应该是什么样」。
Profile Projection 负责把它收窄成「**这台**设备应该写什么」：

```text
StateRoot（全量期望状态）
        +  DeviceProfile（我是谁）
        +  ProjectionPolicy（我被允许做什么）
        +  ProjectionRules（配置层写的 selector / device_overrides）
        ↓
   DeviceView { state, notes }      ← 本机目标状态 + 逐资源可解释诊断
```

投影是**纯函数**：不读时钟、不读磁盘、不依赖迭代顺序。相同输入必然得到相同的
`DeviceView` 标识与相同顺序的诊断序列。

实现见 `crates/envsync-domain/src/profile.rs`（数据与选择器 AST）与
`crates/envsync-core/src/projection.rs`（投影算法）。

---

## 1. Profile 的组成

| 字段 | 类型 | 来源 | 参与投影的方式 |
|---|---|---|---|
| `os` | `macos` / `linux` / `windows` | **编译期探测** | `os` 谓词 |
| `arch` | `x86_64` / `aarch64` | **编译期探测** | `arch` 谓词 |
| `hostname` | 可选字符串 | 配置 `profile.hostname` | `hostname` 谓词（精确相等） |
| `tags` | 有序字符串集合 | 配置 `profile.tags` | `tag` 谓词 |
| `capabilities` | 有序字符串集合 | 配置 `profile.capabilities` ∩ 安全 policy | `capability` 谓词 |
| `device` | `DeviceId`（64 位小写十六进制） | 由 `device.seed_hex` 派生（ADR-0002） | `device` 谓词、`device_overrides` 的键 |

对应的配置片段（版本 2 起可用）：

```yaml
profile:
  hostname: "workstation"        # 可省略；省略时 hostname 为 null，不参与投影
  tags: ["work", "laptop"]
  capabilities: ["pwsh", "git-xdg"]
```

注意 `profile` 段里**没有** `os` 与 `arch`——这不是遗漏。

### 1.1 为什么 os / arch 必须由编译期探测

`envsync.yaml` 会随工作区同步到**所有**设备。如果平台可以在配置里自报，那么：

```yaml
# 假想的（被刻意禁止的）写法
profile:
  os: windows        # 在一台 Linux 机器上这样写……
```

就意味着任何一台设备都能声称自己是另一个平台，从而绕过所有按 `os` 编写的选择器，
把 Windows 专属的资源写到 Linux 上去。因此 EnvSync 用
`envsync_core::config::detected_os()` / `detected_arch()` 从 `cfg!(target_os)` /
`cfg!(target_arch)` 读取，**配置层没有任何覆盖入口**。

```text
配置里可以自报的（可能过时、可能夸大）   配置里不能自报的（结构性事实）
  hostname                                os
  tags                                    arch
  capabilities  ← 还要与安全 policy 取交集  device（由本机私有种子派生）
```

未收录的操作系统退化为 `linux`，未收录的架构退化为 `x86_64`：EnvSync 只在三大平台
做过验证，退化取值让程序仍可运行，且选择器的行为可预期。

### 1.2 字符串取值的规范化

`hostname`、`tags`、`capabilities` 的每个取值在解析期都会：

1. `trim` 首尾空白；
2. 拒绝空值或纯空白（`config.invalid_profile_value`）；
3. 拒绝超过 **256 字节**的取值；
4. 集合元素个数不得超过 **128**。

这些值是在设备之间比较的字面量，必须只有一种表示——否则 `"work"` 与 `"work "`
会成为两个不同的标签，而用户完全看不出区别。

---

## 2. Selector AST

选择器写在**资源**上，声明「哪些设备适用该资源」：

```yaml
resources:
  - id: shell/powershell/profile
    root: home
    target: Documents/PowerShell/Microsoft.PowerShell_profile.ps1
    mode: managed_block
    disposition: managed
    selector:
      all:
        - os: windows
        - capability: pwsh
```

### 2.1 语法：每个节点都是单键映射

选择器的每个节点都是一个**恰好含一个键**的 YAML 映射，键决定节点种类。
键不是单个、不是字符串、或映射有 0 / ≥2 个键时报 `config.invalid_selector`。

**组合子**

| 键 | 取值 | 语义 |
|---|---|---|
| `all` | 序列 | 全部子项成立；**空序列恒为真**（合取的单位元） |
| `any` | 序列 | 至少一个子项成立；**空序列恒为假**（析取的单位元） |
| `not` | 单个节点 | 子项取反 |

空集合的语义刻意固定为上述数学约定，而不是「空即匹配全部」之类的隐式行为。

**谓词**（取值一律是字符串）

| 键 | 合法取值 | 语义 | 例子 |
|---|---|---|---|
| `os` | `macos` / `linux` / `windows` | 操作系统相等 | `- os: macos` |
| `arch` | `x86_64` / `aarch64` | 架构相等 | `- arch: aarch64` |
| `hostname` | 任意规范化字符串 | 主机名**精确**相等（无通配、无正则） | `- hostname: workstation` |
| `tag` | 任意规范化字符串 | 设备带有该标签 | `- tag: work` |
| `capability` | 任意规范化字符串 | 设备具备该能力 | `- capability: brew` |
| `device` | 64 位小写十六进制 | 设备标识精确相等 | `- device: "9f2c…"` |

未知的键报 `config.invalid_selector`（「未知的选择器键 `xxx`」）；`os` / `arch` 写了
枚举外的取值同样报 `config.invalid_selector`。

### 2.2 为什么选择器是「封闭」的

选择器来自会被同步到所有设备的配置，因此是**不可信输入**：一台设备上写下的表达式
会在其他所有设备上求值。所以这里刻意**不提供**正则、通配符、脚本或范围比较，只保
留六个谓词与三个布尔组合子。这样求值一定终止、代价与节点数成正比，也不存在灾难性
回溯。

### 2.3 逐谓词示例

```yaml
# 只在 macOS 上下发
selector:
  os: macos

# Apple Silicon 的 macOS
selector:
  all:
    - os: macos
    - arch: aarch64

# 打了 work 标签、但不是服务器
selector:
  all:
    - tag: work
    - not:
        tag: server

# 有 brew 或有 scoop
selector:
  any:
    - capability: brew
    - capability: scoop

# 只给某一台机器（主机名）
selector:
  hostname: workstation

# 只给某一台机器（设备标识，比主机名更可靠：主机名可改，DeviceId 由私有种子派生）
selector:
  device: "9f2c3d4e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f"
```

嵌套写法（`not` 里再放组合子）也是允许的：

```yaml
selector:
  not:
    any:
      - os: windows
      - tag: ci
```

### 2.4 资源限制：深度 16、节点 256

| 常量 | 值 | 含义 |
|---|---|---|
| `MAX_SELECTOR_DEPTH` | 16 | 最大嵌套深度；单个谓词的深度为 1 |
| `MAX_SELECTOR_NODES` | 256 | 节点总数上限（组合子与谓词都计入） |

超限一律拒绝，错误码 `config.invalid_selector`。

选这两个数字的理由是**它们足够表达真实需求，又足够小以至于恶意输入无法造成资源
耗尽**。深度 16 意味着 16 层嵌套的布尔表达式——真实的「按 OS 分流 + 按标签细分 +
一条例外」通常只有 2～3 层；节点 256 意味着一条选择器最多引用 256 个条件。

限制在**四个地方**分别强制，缺一不可：

```text
YAML → Selector       selector_from_yaml()      转换时逐层限深
                      （递归转换本身就会先把栈耗尽，不能留给之后的 validate）
CBOR → Selector       node_from_value()         解码时逐层限深，理由同上
Selector::validate()  迭代遍历，边走边计数       深度 + 节点数 + 取值规范性
Selector::matches()   内部深度与节点预算         纵深防御，见下
```

`node_count()`、`depth()`、`validate()` 全部是**迭代**实现而非递归：选择器可能来自
不可信配置，递归遍历本身就是栈溢出的入口。

#### 求值超限为什么返回 `None` 而不是 `false`

`Selector::matches` 的使用契约是「先 `validate`，通过了再求值」。但作为纵深防御，
`matches` 内部仍保留一份硬性预算。关键在于**超限时怎么表达**：

```rust
// 内部求值：返回 None 表示「无法求值」，而不是 false。
fn eval(&self, profile: &DeviceProfile, depth: usize, budget: &mut usize) -> Option<bool> {
    if depth > MAX_SELECTOR_DEPTH || *budget == 0 {
        return None;
    }
    // …
    Selector::Not(inner) => Some(!inner.eval(profile, depth + 1, budget)?),
    // …
}

pub fn matches(&self, profile: &DeviceProfile) -> bool {
    let mut budget = MAX_SELECTOR_NODES;
    self.eval(profile, 1, &mut budget).unwrap_or(false)   // 只在最外层塌缩为 false
}
```

假设内层超限时直接返回 `false`，那么：

```text
选择器：  not( <一棵超过预算的巨大子树> )

内层耗尽预算 → 返回 false
外层 Not     → !false = true
结论         → 「匹配」——这个资源会被下发到**所有**设备
```

也就是说，**攻击者只要把选择器写得足够大，就能让「不匹配」翻转成「匹配所有设备」**。
资源耗尽本该是拒绝服务，结果变成了权限提升。

用 `None` 表达「无法求值」之后，`?` 会让 `None` 一路向上传播，`Not` 无从翻转它；只有
最外层的 `matches` 把它塌缩成保守的 `false`（不匹配 ＝ 不向该设备下发任何资源）。
`matches` 因此**绝不 panic、绝不栈溢出、绝不因为超限而扩大下发范围**。

这条规则值得推广：**在安全判定里，「失败」和「否」必须是不同的值。** 任何会被取反、
被 `any` 吸收、被短路的布尔判定，都不能用 `false` 兼任「算不出来」。

---

## 3. 投影优先级

四层，从低到高：

| 层 | 来源 | 能做什么 | 诊断种类 |
|---|---|---|---|
| 1 全局资源 | 没有 `selector`、没有命中的 `device_overrides` | 对所有设备下发 | `selected_by_global` |
| 2 selector | 资源的 `selector` | 命中则下发，未命中则排除 | `selected_by_selector` / `excluded_by_selector` / `unsupported_capability` |
| 3 设备覆盖 | 资源的 `device_overrides[<device-id>]` | **无条件**纳入并套用覆盖，可推翻第 2 层 | `overridden_by_device` |
| 4 安全 policy | `ProjectionPolicy::denied` 与 `capabilities` | 硬性排除，推翻前三层 | `excluded_by_policy` |

### 3.1 判定流程

```text
                       ┌─────────────────────────────┐
   对 StateRoot 里的     │  资源 R 在 policy.denied 里？ │
   每个资源 R（按标识    └──────────────┬──────────────┘
   升序遍历）                          │
                              是 ──────┴────── 否
                              │                │
                              ▼                ▼
                    excluded_by_policy   ┌───────────────────────────────┐
                    ⟹ 排除，不可申辩      │ 本设备命中 device_overrides？  │
                                         └───────────────┬───────────────┘
                                                 是 ─────┴───── 否
                                                 │             │
                                                 ▼             ▼
                                     overridden_by_device  ┌──────────────────┐
                                     ⟹ 纳入 + 套用覆盖      │ 资源声明了 selector？│
                                     （可推翻 selector）    └────────┬─────────┘
                                                          有 ───────┴─────── 无
                                                          │                 │
                                                          ▼                 ▼
                                            ┌───────────────────┐  selected_by_global
                                            │ selector.matches？ │  ⟹ 纳入
                                            └─────────┬─────────┘
                                             命中 ────┴──── 未命中
                                             │              │
                                             ▼              ▼
                              selected_by_selector   ┌──────────────────────────┐
                              ⟹ 纳入                  │ 未命中的原因里有「正向要求 │
                                                     │ 的能力本机不具备」吗？     │
                                                     └────────────┬─────────────┘
                                                          有 ─────┴───── 无
                                                          │             │
                                                          ▼             ▼
                                          unsupported_capability   excluded_by_selector
                                          ⟹ 排除（**不是删除**）   ⟹ 排除
```

排除意味着「该资源不出现在本设备的 `DeviceView` 里」，因此计划阶段既不会写它，
**也不会删它**——见第 4 节。

### 3.2 policy 为什么不可被绕过

`ProjectionPolicy` 描述的是「本机**被允许**做什么」，而不是「用户**希望**做什么」。
它有两个作用面：

```rust
pub struct ProjectionPolicy {
    /// 被安全策略硬性拒绝的资源（任何 selector 都无法覆盖）。
    pub denied: BTreeSet<ResourceId>,
    /// 本设备**实际**可用的能力（策略层认定的事实）。
    pub capabilities: BTreeSet<String>,
}
```

1. **`denied` 是第一道判定，且直接 `continue`。** 它排在循环体最前面，在读取规则、
   查设备覆盖、求值选择器之前就短路。因此不存在「写一条 device_overrides 把它捞回来」
   的路径——那段代码根本不会被执行到。
2. **`capabilities` 取交集，不取并集。** 选择器一律对「有效 Profile」求值：

   ```text
   有效能力 = 配置里自报的 capabilities  ∩  policy 认定的 capabilities
   ```

   于是「配置声称有 `pwsh`，但策略不认」的结果是**资源被排除**，而不是被下发。策略
   永远不会被配置里的自述放宽——放宽只能通过改策略，而策略不随工作区同步。

M1 的 CLI 路径上，`ProjectionPolicy::from_config` 构造的是「不拒绝任何资源、能力取配
置声明」的默认策略；`denied` 的实际填充留给 M2 的策略引擎。上述结构性保证（判定顺序
与交集语义）**现在就已经成立**，M2 只是往里填内容。

---

## 4. 投影只能缩小或转换意图，不能生成 tombstone

这是投影层最重要的一条不变量：

> **能力缺失产生 `unsupported_capability` 诊断，而不是删除动作。**

### 4.1 为什么

设想相反的实现：设备 A 装了 PowerShell，设备 B 没有。B 上投影时发现
`selector: {capability: pwsh}` 不成立，于是「合理地」生成一条
`ensure_absent`（tombstone）。这条 tombstone 会进入 B 的快照，发布到后端，然后被 A
拉下来——**A 上的 PowerShell Profile 就被 B 删掉了**。用户在 B 上做的事情只是「没装
pwsh」。

同样的推理适用于其余四种「资源不在视图里」的原因：

| 情况 | 正确结论 | 错误结论（被禁止） |
|---|---|---|
| 选择器未命中 | 本次不下发 | 删除 |
| 缺少能力 | 本次不下发 + 诊断 | 删除 |
| 被 policy 拒绝 | 本次不下发 + 诊断 | 删除 |
| 本机读不到文件 | 沿用上一版内容 + warning | 删除 |
| 平台不支持 | 标 `unsupported` | 删除 |

这与设计文档 §3.2「`absent`、`unsupported`、`unreadable`、`excluded` 都不能被推断为
删除意图」以及原则 4「默认不删除」是同一条规则在投影层的落地。

### 4.2 代码里的三处强制

1. **排除路径只有 `continue`。** `project_workspace_with_rules` 在资源被排除时直接跳
   过，没有任何构造 `DesiredDisposition::EnsureAbsent` 的分支——投影**没有生成
   tombstone 的语法**。
2. **投影不能新增资源。** 结果里的每个 `ResourceId` 一定来自输入 `StateRoot`：遍历的
   是 `state.entries`，没有凭空创造的入口。
3. **设备覆盖改成 `managed` 但没有内容时报错**，而不是静默丢弃：

   ```text
   ProjectionError::UnsatisfiableOverride
     "快照里没有该资源的内容，无法覆盖为 managed"
   ```

   覆盖成 `ensure_absent` 或 `unmanaged` 时则清掉 `blob`（这两种处置不允许携带内容）。
   `ensure_absent` **只能由用户在配置里显式写下**，投影忠实执行，绝不推断。

### 4.3 `missing_capabilities` 只看正向位置

区分 `unsupported_capability` 与 `excluded_by_selector` 时，只统计**不在 `not` 之下**
的 `capability` 谓词：

```yaml
selector:
  not:
    capability: pwsh      # 意思是「没有 pwsh 的设备才适用」
```

对这条选择器，缺少 `pwsh` 恰恰意味着**命中**，把它报成「缺少能力」是方向性错误。
遍历时携带一个 `negated` 标志，每经过一层 `not` 翻转一次，只有 `negated == false` 时
才计入缺失集合。该遍历同样是迭代实现。

---

## 5. `envsync profile explain`

```bash
envsync profile explain --config /home/YOUR_USER/.config/envsync/envsync.yaml
```

### 5.1 人类可读输出

```text
设备 Profile（9f2c3d4e5a6b…）
  平台：linux / x86_64
  主机名：workstation
  标签：laptop、work
  能力：git-xdg、pwsh
  设备视图：4b1d7c02a9…
    ✓ git/config/global：selected_by_global——全局资源，对所有设备下发。
    ✓ shell/zsh/main：selected_by_selector——选择器命中本设备。
    · shell/powershell/profile：unsupported_capability——本设备缺少所需能力：pwsh；该资源本次不下发，但**不会**被删除。
    · terminal/wezterm/module：excluded_by_selector——选择器未命中本设备。
    ✓ editor/settings：overridden_by_device——命中本设备的 device-id 覆盖。
```

怎么读：

| 记号 | 含义 |
|---|---|
| `✓` | 该资源**在**本设备视图里，会参与计划 |
| `·` | 该资源**不在**本设备视图里；它不会被写，**也不会被删** |
| `设备视图` | 投影结果状态的内容标识；两台设备的这个值相同 ⟺ 它们应当收敛到完全相同的内容 |
| `平台` | 编译期探测值，配置改不了 |

`设备视图` 是排查「为什么两台机器同步后文件不一样」的第一个抓手：值不同就说明投影
结论本身不同，问题在 selector / device_overrides / policy，而不在写入流程。

### 5.2 JSON 输出

```bash
envsync profile explain --config "$CFG" --json | jq
```

```json
{
  "schema_version": 2,
  "command": "profile.explain",
  "status": "ok",
  "data": {
    "os": "linux",
    "arch": "x86_64",
    "hostname": "workstation",
    "device": "9f2c3d4e5a6b…",
    "tags": ["laptop", "work"],
    "capabilities": ["git-xdg", "pwsh"],
    "state_root": "70a1c3…",
    "device_view": "4b1d7c02a9…",
    "resources": [
      {
        "resource": "shell/powershell/profile",
        "kind": "unsupported_capability",
        "included": false,
        "detail": "本设备缺少所需能力：pwsh；该资源本次不下发，但**不会**被删除。"
      }
    ]
  },
  "diagnostics": []
}
```

| 字段 | 说明 |
|---|---|
| `state_root` | 被投影的**完整**期望状态；工作区还没有任何快照时为 `null` |
| `device_view` | 投影**结果**的标识；即使 `state_root` 为 `null` 也有值（空状态也有标识） |
| `resources[].kind` | 六种诊断种类之一，见下表 |
| `resources[].included` | 该资源是否在视图里；由 `kind` 唯一决定 |

诊断种类与 `included` 的对应关系：

| `kind` | `included` |
|---|---|
| `selected_by_global` | `true` |
| `selected_by_selector` | `true` |
| `overridden_by_device` | `true` |
| `excluded_by_selector` | `false` |
| `excluded_by_policy` | `false` |
| `unsupported_capability` | `false` |

`profile explain` 只在 JSON schema v2 中定义；用 `--schema-version 1` 调用会被拒绝
（错误码 `recovery.manual_required`，退出码 1）而不是输出一个 v1 读者无法解释的
信封。

`plan` 的 `data.device_view` 是同一个值：计划针对的正是投影后的目标状态。

---

## 6. 配方

### 6.1 按操作系统分流

同一个逻辑意图在三个平台落在不同路径。写成三条资源，各带一条 `selector`：

```yaml
resources:
  - id: shell/rc/posix
    root: home
    target: .zshrc
    mode: managed_block
    disposition: managed
    selector:
      any:
        - os: macos
        - os: linux

  - id: shell/rc/windows
    root: home
    target: Documents/PowerShell/Microsoft.PowerShell_profile.ps1
    mode: managed_block
    disposition: managed
    selector:
      all:
        - os: windows
        - capability: pwsh
```

**为什么把 `capability: pwsh` 也写上**：`os: windows` 只说明平台，不说明装没装
PowerShell。加上能力谓词之后，没装的机器会得到一条 `unsupported_capability` 诊断
（明确告诉你「缺 pwsh」），而不是一条晦涩的写入失败。

### 6.2 按 work / personal 标签分流

标签是**本机声明**的（`profile.tags`），因此适合表达「这台机器扮演什么角色」：

```yaml
# 工作机上的公司代理配置
- id: net/proxy/corp
  root: home
  target: .config/envsync/corp-proxy.conf
  mode: full_file
  disposition: managed
  selector:
    tag: work

# 个人机上的娱乐向配置：打了 personal 标签，且明确排除工作机
- id: terminal/theme/personal
  root: home
  target: .config/envsync/theme.lua
  mode: full_file
  disposition: managed
  comment_prefix: "-- "
  selector:
    all:
      - tag: personal
      - not:
          tag: work
```

`not: {tag: work}` 是一道保险：一台机器同时打上 `work` 和 `personal` 时，工作策略
优先。**在选择器里把「例外」写出来，比依赖「用户不会同时打两个标签」可靠。**

对应的设备侧声明：

```yaml
# 工作机的 envsync.yaml
profile:
  tags: ["work", "laptop"]

# 个人机的 envsync.yaml
profile:
  tags: ["personal", "desktop"]
```

### 6.3 给单台机器打特例

三种粒度，从弱到强：

**(a) 用 `hostname` 谓词** —— 最直观，但主机名可以被改，也可能重名：

```yaml
selector:
  hostname: build-box
```

**(b) 用 `device` 谓词** —— 精确到由私有种子派生的 `DeviceId`，不会重名也改不了：

```yaml
selector:
  device: "9f2c3d4e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f"
```

设备标识可以从 `envsync profile explain` 的 `data.device` 或 `envsync status` 的
`data.device` 拿到。

**(c) 用 `device_overrides`** —— 不改变「谁适用」，而是改变「这台机器怎么落地」：

```yaml
- id: editor/settings
  root: home
  target: .config/Code/User/settings.json
  mode: full_file
  disposition: managed
  device_overrides:
    # 这台机器把同一份内容写到另一个路径
    "9f2c3d4e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f":
      target: .config/Code - Insiders/User/settings.json
    # 这台机器完全不接管该文件，只记录存在性
    "1122334455667788990011223344556677889900112233445566778899001122":
      disposition: unmanaged
```

**两个字段的作用面完全不同，务必分清：**

| 覆盖字段 | 影响什么 | 在哪一步生效 |
|---|---|---|
| `disposition` | **期望状态**（进入 `DeviceView`） | 投影阶段（`EntryOverride`） |
| `target` | **本机落地位置**（不进入共享 Snapshot） | 计划阶段（`WorkspaceConfig::for_device`） |

`target` 刻意不进入投影：它只决定本机把内容写到哪里，如果混进期望状态，一台机器的
本地路径偏好就会污染所有设备共享的 Snapshot 标识。

约束与常见错误：

| 写法 | 结果 |
|---|---|
| 键不是合法 64 位小写十六进制设备标识 | `config.invalid_device_override_key` |
| 条目里两个字段都省略（空覆盖） | `config.empty_device_override` |
| 覆盖 `target` 但值非法（`..`、绝对路径……） | `config.invalid_target` |
| 覆盖成 `managed` 但快照里没有该资源的内容 | `projection.unsatisfiable_override` |

**device_overrides 无条件推翻 selector。** 即使某资源的 `selector` 未命中本设备，只
要本设备的 `DeviceId` 出现在 `device_overrides` 里，该资源就会被纳入视图并套用覆盖。
这是刻意设计的「显式优先于推断」：你专门为这台机器写了一条规则，它就该生效。
唯一推翻它的是安全 policy。

---

## 7. 错误码速查

| 错误码 | 触发条件 |
|---|---|
| `config.invalid_profile_value` | `profile.hostname` / `tags` / `capabilities` 取值为空、超长或数量超限 |
| `config.invalid_selector` | 选择器写法不对（非单键映射、未知键、取值类型/枚举不对）或超出深度 / 节点上限 |
| `config.invalid_device_override_key` | `device_overrides` 的键不是合法设备标识 |
| `config.empty_device_override` | `device_overrides` 条目没有覆盖任何字段 |
| `config.field_requires_version` | 在 `version: 1` 的文档里写了 `profile` / `selector` / `device_overrides` / Git 后端 |
| `projection.invalid_selector` | 手工构造的 `WorkspaceConfig` 里选择器非法（解析路径已挡过一次） |
| `projection.invalid_profile` | Profile 取值不规范 |
| `projection.invalid_device_key` | 投影规则里的设备覆盖键非法 |
| `projection.unsatisfiable_override` | 覆盖成 `managed` 但没有可用内容 |
| `projection.invalid_state` | 投影结果不是合法 State Root——出现即说明实现有 bug |

---

## 8. 相关文档

- [命令行文档](cli.md)：`profile explain` 的参数与 JSON 契约
- [适配器](adapters.md)：内建适配器如何用 selector 表达平台与能力条件
- [Git 后端](backends/git.md)：多设备场景下投影与 CAS 的配合
- [冲突处理](conflicts.md)：投影之前的三方合并与冲突裁决
- [配置示例](../examples/workspace.yaml) 与 [Git 后端配置示例](../examples/workspace-git.yaml)
- 系统设计 §3.1：`docs/superpowers/specs/2026-07-24-envsync-design.md`
