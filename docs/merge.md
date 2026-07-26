# 三方合并规则（M1）

EnvSync 的合并引擎有一条不可商量的输出契约：

> 合并要么产出**干净字节**，要么产出**冲突对象**。
> `<<<<<<<` 之类的标记**永远不会**出现在干净结果里。

理由见 [冲突处理 §1.3](conflicts.md#13-为什么冲突-marker-绝不写进用户文件)。本文只讲
合并本身：每种格式的规则、已知限制、资源上限与校验。

实现见 `crates/envsync-core/src/merge/`。

---

## 1. 总览

| 入口 | 用途 |
|---|---|
| `merge_text(input)` | 逐行三方合并（diff3 风格） |
| `merge_structured(input, format)` | 按格式做语义合并，使用默认选项 |
| `merge_structured_with(input, format, options)` | 同上，可传入 `MergeOptions`（目前只有 INI 用到） |
| `merge(input, Option<format>)` | 有格式走语义合并，否则退化为文本合并 |

选哪一个由资源的 `policy.structured_format` 决定：声明了就走语义合并，没声明就走文本
合并。

```yaml
resources:
  - id: vcs/git/user
    root: home
    target: .gitconfig
    mode: full_file
    disposition: managed
    policy:
      structured_format: git_config     # json | yaml | toml | ini | git_config
```

### 1.1 与内容无关的快速路径

在做任何解析之前，`classify` 先处理这些情况（因此它们对所有格式一致）：

| ours | theirs | base | 结果 |
|---|---|---|---|
| 不存在 | 不存在 | — | `Deleted`（双方一致删除） |
| 存在 | 不存在 | 不存在 | `Clean`＝ours（仅 ours 新增） |
| 存在 | 不存在 | ＝ours | `Deleted`（theirs 删除，ours 未改动） |
| 存在 | 不存在 | ≠ours | `Conflict(delete_modify)` |
| 存在 | 存在 | — | ours ＝ theirs ⟹ `Clean`（双方改成了同一份内容） |
| 存在 | 存在 | ＝ours | `Clean`＝theirs（仅 theirs 修改） |
| 存在 | 存在 | ＝theirs | `Clean`＝ours（仅 ours 修改） |
| 存在 | 存在 | 其他 | 进入内容级合并 |

这些快速路径同时保证了两条 property：

- `merge(base, x, x)` 必然 `Clean(x)`；
- 只改一侧时，结果**逐字节等于**改动的那一侧。

### 1.2 结论也是审计记录

`MergeResult::Clean` 附带 `MergeProvenance`：

| 字段 | 含义 |
|---|---|
| `took_ours` / `took_theirs` / `took_base` | 分别采纳了多少个**行**（文本）或**键**（结构化） |
| `notes` | 审计备注，例如「仅 theirs 修改」「输入超过 4 MiB，按整份内容处理」——**不含文件正文** |

不做细粒度合并的整份内容路径（二进制、超限、双方字节一致），采纳的一侧按 `1` 计。

---

## 2. 统一资源限制

| 常量 | 值 | 作用 |
|---|---|---|
| `MAX_INPUT_BYTES` | **4 MiB**（`4 * 1024 * 1024`） | 单侧输入的最大字节数 |
| `MAX_PARSE_DEPTH` | **64** | 结构化解析的最大嵌套深度 |
| `MAX_NODES` | **100 000** | 结构化解析的最大节点数 |

**超限行为在文本与结构化之间刻意不同：**

| | 超过 4 MiB 时 |
|---|---|
| 文本合并 | **降级为整份内容比较**（等同二进制规则）：只改一侧仍是 `Clean`，双方都改则 `Conflict(binary_both)`，诊断注明 `input exceeds 4194304 bytes` |
| 结构化合并 | 直接返回 `MergeError::TooLarge { limit, actual }`（错误码 `merge.too_large`） |

差异的理由：文本合并**不应该因为文件大就完全罢工**——只改一侧的大文件仍然能被安全采
纳；而结构化合并必须先把整份文档读进内存建树，超限时没有安全的降级方式。

深度与节点上限由共享的 `Budget` 强制，每解析一个节点计一次数：

```rust
pub(crate) fn charge(&mut self, depth: usize) -> Result<(), MergeError> {
    if depth > MAX_PARSE_DEPTH {
        return Err(MergeError::DepthLimitExceeded { limit: MAX_PARSE_DEPTH });
    }
    self.nodes += 1;
    if self.nodes > MAX_NODES {
        return Err(MergeError::NodeLimitExceeded { limit: MAX_NODES });
    }
    Ok(())
}
```

对应错误码 `merge.depth_limit` 与 `merge.node_limit`。

**为什么必须有上限**：合并的输入来自远端，是不可信内容。一份 10 万层嵌套的 JSON 足以
把递归解析器的栈打穿；一份几百万节点的 YAML 足以耗尽内存。EnvSync 的立场是：**遇到
超限就明确报错，绝不"尽力而为"**。

---

## 3. 渲染后重新解析校验

所有**结构化**合并器在产出字节之前都会做一次自校验：

```text
三方语义模型  ──合并──▶  合并后的语义模型
                              │
                            渲染
                              ▼
                            字节
                              │
                          重新解析
                              ▼
                        重解析的语义模型
                              │
                        与合并结果比较 ──不一致──▶ MergeError::RenderVerificationFailed
```

比较使用与格式无关的 `Plain` 模型：

- **数字统一按规范化文本比较**，避免 `1.0` / `1` 这类往返表示差异造成误判；
- **`Map` 的键按字典序排序**，因为所有目标格式的对象 / 表在语义上都是无序的；
- 序列逐项比较（序列本身按原子值处理，但仍要保证渲染没有丢项）。

这道检查抓的是**渲染器的 bug**，不是用户的错误：如果某个 `toml_edit` 的排版转换悄悄
改变了语义，或者 INI 渲染把一个值写成了会被重新解析成别的东西的形式，我们宁可让这次
合并失败，也不把一份语义已经漂移的文件写进用户的配置。错误码
`merge.render_verification_failed`。

**文本合并没有这一步**：它的输出就是原始行的重新拼接，没有"渲染"这个环节。

---

## 4. 文本合并（diff3）

基于 `similar` 的行级 diff，求 base→ours 与 base→theirs 两组 Equal 段在 base 坐标上的
**交集**得到三方同步区，同步区之间的不稳定区逐段判定。

### 4.1 规则表

| 情况 | 结果 |
|---|---|
| 只改 ours / 只改 theirs | `Clean`，逐字节等于改动那一侧 |
| 双方相同修改 | `Clean`，结果就是那份内容 |
| 互不相交的行区间修改 | `Clean`，**两侧改动都保留** |
| 重叠区域双方不同修改 | `Conflict(text_overlap)`，诊断给出行区间 |
| 一侧删除、另一侧修改 | `Conflict(delete_modify)` |
| 双方都删除 | `Deleted` |
| 二进制内容双方都改 | `Conflict(binary_both)`，**不做行合并** |
| 超过 4 MiB 双方都改 | 同二进制规则，诊断里注明超限 |

**二进制的判据**：含 NUL 字节，**或**不是合法 UTF-8。判定发生在解析之前，因此非 UTF-8
内容永远不会被当成文本切行。

冲突诊断的形状（行号 1 起）：

```text
ours 12..18 vs theirs 12..15
```

### 4.2 换行处理约定

这是文本合并里最容易出错的一块，规则如下：

1. **比较用行尾归一化后的内容**：`\r\n` 与 `\n` 被视为同一行。因此「仅行尾风格不同」
   不会被当成内容变更，也不会产生冲突。
2. **输出保留被采纳那一侧该行的原始行尾**：
   - 稳定区（三方一致）沿用 **ours** 的原始行；
   - 只有一侧改动的区段沿用**那一侧**的原始行。
3. **拼接处需要补行尾时**，使用 **base 的主导换行风格**（base 缺失时用 ours 的）。
   「主导」的判据是：CRLF 数量**严格多于**纯 LF 数量时取 `\r\n`，否则取 `\n`。
4. 最后一行可以没有行终止符；`split_lines_keep` 保留终止符切行，`normalize` 只在比较
   时剥掉。

```text
base    :  a\n  b\n  c\n
ours    :  a\n  B\n  c\n        （改了第 2 行，保持 LF）
theirs  :  a\r\n b\r\n c\r\n    （只把整份文件换成了 CRLF）

归一化比较：ours 改了 b→B，theirs 什么都没改
结果      ：a\n  B\n  c\n       ← Clean，无冲突
```

### 4.3 已知限制

- **纯行尾风格变更在稳定区不会被采纳。** 上例中 theirs 把整份文件从 LF 改成 CRLF，而
  ours 改了别的行；结果沿用 ours 的 LF。这是有意的取舍：行尾归一化比较是避免"跨平台
  换行噪声压垮合并"的前提，代价就是行尾风格本身不参与合并。要统一行尾请用资源的
  `policy.line_ending`（`preserve` / `lf` / `crlf`）。
- **合并粒度是行**，不做词级或语法级合并。同一行上的两处不相干改动会冲突。
- **二进制内容不做任何合并**，双方都改就是冲突。这是正确的保守选择：字节级三方合并
  对二进制格式几乎总是产出损坏的文件。

---

## 5. JSON

### 5.1 规则

| 规则 | 说明 |
|---|---|
| **对象按 key 递归三方合并** | 双方改动不同 key 时两边改动都保留 |
| **数组是原子值** | 不做元素级合并；整体取一侧，双方改成不同数组即冲突 |
| **`null` 是一个值，不代表删除** | 删除只由「键不存在」表达 |
| 一侧删除 key、另一侧修改同一 key | 冲突，诊断记录该 key 的 **JSON Pointer** |
| **重复 key 被拒绝** | `MergeError::DuplicateKey`（`merge.duplicate_key`） |

`serde_json` 默认后者覆盖前者；EnvSync 用自定义 `DeserializeSeed` 自行检测重复 key
并报错——静默丢弃一个 key 是最难排查的一类数据损坏。

诊断形状：

```text
modify/modify /editor/tabSize
delete/modify /telemetry/enable
```

JSON Pointer 按 RFC 6901 转义：`~` → `~0`，`/` → `~1`。

### 5.2 已知限制

- **键顺序不被保留。** 输出是 `serde_json` 的 pretty 形式（以换行结尾），键顺序为
  **字典序**（`serde_json::Map` 底层是 `BTreeMap`）。原文件里的键顺序会被重排。
- **注释不被保留**——JSON 本身就没有注释；但这意味着 JSONC / JSON5 风格的带注释配置
  （例如 VS Code 的 `settings.json`）**会解析失败**（`merge.parse`）。这类文件请改用
  文本合并（不声明 `structured_format`）。
- 尾随内容（一个 JSON 文档之后还有字节）报 `merge.parse`，诊断给出行列。

---

## 6. YAML

### 6.1 接受的子集

只接受**安全数据模型**、**单文档**：

| 构造 | 处理 |
|---|---|
| 第二个文档（`---` 分隔） | `MergeError::UnsupportedConstruct`（`multiple documents in one stream`） |
| 自定义 tag（`!Foo`） | `UnsupportedConstruct`（`custom tag`） |
| alias 环 / alias 爆炸 | `UnsupportedConstruct`（`alias cycle or excessive alias expansion`） |
| 重复 key | `MergeError::DuplicateKey` |

**为什么拒绝自定义 tag**：自定义 tag 把 YAML 变成一个可执行的类型系统入口。合并器不做
任何 tag 语义推断——它无法知道 `!Include ./x.yaml` 是什么意思，猜测就是越权。

### 6.2 合并规则

- **mapping 按 key 递归合并**；
- **sequence 是原子值**；
- **只有键全部是字符串的 mapping 才递归**；含非字符串键的 mapping 按原子值处理。

### 6.3 已知限制

- **注释与锚点会丢失。** `serde_yaml_ng` 的数据模型不保留它们，因此合并结果里的注释、
  锚点（`&x`）、别名（`*x`）都不复存在——别名会被展开成实际值。
  **需要保留注释的 YAML 资源应当配置为文本合并**（不声明 `structured_format`）。
  这是 YAML 与 TOML / INI / Git config 的关键差别：后三者**保留**注释。
- 重复 key 的诊断只能给出**叶子键名**（底层错误不带完整路径），因此 pointer 形如
  `/name` 而不是 `/a/b/name`。
- 引号风格、块标量风格（`|` / `>`）、缩进宽度都由序列化器重新决定，不保留原样。

---

## 7. TOML

基于 `toml_edit`，**保留注释与格式**。

### 7.1 规则

- 表（`[table]`、内联表、dotted key）按 key 独立合并；
- **数组与 array-of-tables 是原子值**；
- 结果文档以 **ours 的文档为骨架**克隆而来，因此 ours 未被改动的部分连注释、空行、
  引号风格都**逐字保留**；被 theirs 改动的 key 会连同 **theirs 的格式**一起写入；
- 一侧删除 key、另一侧修改同一 key ⟹ 冲突，诊断记录键路径；
- 重复 key 与无效 TOML 由 `toml_edit` 拒绝，映射为 `merge.duplicate_key` /
  `merge.parse`，诊断**只含位置**。

### 7.2 已知限制

- **从 theirs 新增的 key 会追加到对应表的末尾**，可能与 ours 的原有排版顺序不同。
  语义正确，但 diff 看起来会比预期大。
- **ours 是内联表而 theirs 的对应子项是标准表时，写入会被转换成内联表形式**；语义不
  变，排版可能变化。

两条都属于"格式保留是尽力而为，语义正确是硬保证"——渲染后重解析校验保证了后者。

---

## 8. INI

自带解析器，无第三方依赖。与 Git config 共用同一套「节 + 键值行 + 版式（layout）」
模型。

### 8.1 语法子集

| 构造 | 支持 |
|---|---|
| 节头 `[name]`（前后可有空白） | ✅ |
| 键值 `key = value`（`=` 前后空白裁剪） | ✅ |
| 整行注释（以 `;` 或 `#` 开头） | ✅ 逐字保留 |
| **行尾注释** | ❌ **不被识别**，会成为值的一部分 |
| 值的引号 / 转义 | ❌ 不解析，逐字保留 |
| 其他形态的行 | ⟹ `merge.parse`，诊断**只含行号** |

**行尾注释不被识别**是最容易踩的一条：`key = value  ; 说明` 的值是
`value  ; 说明`。INI 没有统一标准，各实现对行尾注释的处理互不兼容；EnvSync 选择"逐字
保留"，因为它至少不会悄悄丢掉内容。

### 8.2 合并规则

- **键的 identity 是 `section/key`**，节名与键名**都大小写敏感**（与 Git config 不同）。
- **单个键的值列表作为原子单元**做三方合并；一侧删除、另一侧修改 ⟹ 冲突。
- **保留注释、空行、节顺序与原换行风格**：结果以 ours 的版式为骨架，未发生语义变化的
  行逐字保留。换行风格取 ours 文档的主导风格（CRLF 严格多于纯 LF 时为 `\r\n`）。

### 8.3 重复键：显式 `MultiValuePolicy`

INI 对同一节内的重复键**没有**默认约定，因此 EnvSync 要求**显式**选择：

| 策略 | 行为 |
|---|---|
| `Reject`（**默认**） | 同节内重复键直接报 `merge.duplicate_key` |
| `LastWins` | 只保留最后一次出现的值，位置沿用**第一次**出现的位置 |
| `Append` | 按出现顺序保留全部取值，合并时该键的值列表**整体**作为原子值 |

默认 `Reject` 的理由与 JSON 一致：静默丢弃一个键是最难排查的数据损坏。

---

## 9. Git config

复用 INI 的模型，按 git 规范扩展。

### 9.1 键 identity 与大小写规则

identity 是 `section / subsection / name`：

| 部分 | 大小写 | 说明 |
|---|---|---|
| **section** | **不敏感** | `[Core]` 与 `[core]` 是同一节 |
| **subsection** | **敏感**，逐字保留 | `[remote "Origin"]` ≠ `[remote "origin"]` |
| **name** | **不敏感** | `autoCRLF` 与 `autocrlf` 是同一个键 |

两种 subsection 写法 `[section "sub"]` 与传统的 `[section.sub]` 被识别为**同一
identity**。

这套规则正是"为什么 git config 不能用逐行文本合并"的原因：按行比较会把 `[Core]` 和
`[core]` 当成两个不同的节，把 `autoCRLF` 和 `autocrlf` 当成两个不同的键，从而产出一份
git 自己会以最后一次赋值为准、但用户完全看不懂的文件。

### 9.2 多值键

git 允许同一个键出现多次（例如 `remote.origin.fetch`）。Git config 合并器固定使用
`MultiValuePolicy::Append`：把一个键的**取值列表**当作有序的整体参与三方合并。

- 顺序被完整保留；
- 单值键因此天然退化为独立合并；
- 双方对同一个多值键做了不同修改 ⟹ 整个列表冲突（不做列表内的元素级合并）。

### 9.3 `include.path`：识别但绝不跟随

`include.path` 与 `includeIf.*.path` 的取值按**规范化路径**做身份识别：

| 原值 | 规范化后 |
|---|---|
| `~/git/../gitconfig` | `~/gitconfig` |
| `  ./a//b/./c/  ` | `a/b/c` |
| `/a/b/../../c` | `/c` |
| `../../x` | `../../x`（无可回退项时保留 `..`） |
| `C:\Users\me\.gitconfig` | `C:/Users/me/.gitconfig` |

因此 `~/git/../gitconfig` 与 `~/gitconfig` 被认为是同一条 include，不会被当成两条重复
的 include 各自保留。

规范化是**纯词法**的：不触碰文件系统、不解析符号链接、不展开 `~`。

> **合并器绝不打开、读取或跟随 include 目标。**

跟随 include 等价于"按文件内容里的任意路径去读盘"，是一个明确的越权面：远端推来的
`include.path = /etc/shadow` 会让合并器替攻击者读文件。include 只被当作普通的字符串
键值处理。

### 9.4 已知限制

- **值不做引号 / 转义 / 续行解析**，逐字保留原文。因此 `foo = "a; b"` 里的 `;` 不会
  被当作注释，但也不会被反转义（值里保留着引号）。
- **布尔简写不支持**：只有键名没有 `=` 的行（`[core]` 下的 `bare`）报 `merge.parse`。
  请写成 `bare = true`。
- 行尾注释不被识别（继承自 INI）。

---

## 10. 错误码速查

| 错误码 | 触发条件 |
|---|---|
| `merge.too_large` | 结构化合并的某一侧超过 4 MiB |
| `merge.depth_limit` | 结构化文档嵌套超过 64 层 |
| `merge.node_limit` | 结构化文档节点数超过 100 000 |
| `merge.parse` | 解析失败；`detail` **只含位置**（行号 / 行列），不含正文 |
| `merge.duplicate_key` | 同一容器里出现重复键；`pointer` 是键路径 |
| `merge.unsupported_construct` | YAML 多文档、自定义 tag、alias 环等有意不支持的构造 |
| `merge.render_verification_failed` | 渲染后重新解析，语义与合并结果不一致 |

**所有 `detail` 都只描述位置与结构**（`line 12`、`key path a.b`、JSON Pointer），
永远不包含被解析文件的正文。这与 `Conflict::diagnostics` 是同一条规则。

---

## 11. 怎么给资源选合并方式

| 文件 | 建议 | 理由 |
|---|---|---|
| `~/.gitconfig` | `git_config` | 键 identity 有自己的大小写与多值规则，按行合并会给出语义错误的结果 |
| `~/.zshrc`、`~/.bashrc` | **文本**（不声明格式） | 是脚本不是数据；顺序有语义 |
| PowerShell Profile | **文本** | 同上 |
| WezTerm `.lua` | **文本** | Lua 是代码 |
| `settings.json`（纯 JSON） | `json` | 键级合并显著减少冲突 |
| `settings.json`（**带注释**的 JSONC） | **文本** | JSON 解析器会拒绝注释 |
| `Cargo.toml` 之类的 TOML | `toml` | 保留注释与格式，键级合并 |
| 带注释的 YAML | **文本** | 结构化合并会**丢注释** |
| 不带注释、层级深的 YAML | `yaml` | 键级合并更少冲突 |
| 二进制 / 大文件 | 文本（会自动退化为整份内容处理） | 不做行合并，双方都改即冲突 |

一条经验法则：**顺序有语义、或注释重要，就用文本合并；键值是集合语义，就用结构化
合并。**

---

## 12. 相关文档

- [冲突处理](conflicts.md)：冲突对象、状态机、`conflicts` 命令与恢复流程
- [适配器](adapters.md)：内建适配器为哪些资源声明了 `structured_format`
- [命令行文档](cli.md)：`merge` 的参数与 JSON 契约
- [配置示例](../examples/workspace.yaml)：`policy.structured_format` 的写法
- 系统设计 §5：`docs/superpowers/specs/2026-07-24-envsync-design.md`
