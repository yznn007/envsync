# 合并冲突（M1）

冲突意味着「两台设备对同一份内容有不同的意图」。这只能由人来裁决，所以 EnvSync 在
冲突发生时**什么都不做**：不生成快照、不推进远端 Ref、不改一个本地字节。

实现见 `crates/envsync-core/src/sync.rs`（合并编排）、
`crates/envsync-core/src/merge/`（合并器）与
`crates/envsync-storage/src/conflicts.rs`（冲突索引与状态机）。

---

## 1. 冲突从哪来

`envsync merge` 把**本地草稿头**与**远端头**做三方合并：

```text
        base（最近公共祖先）
        /            \
     ours            theirs
   （本地草稿头）    （远端头）
        \            /
         ？合并结果？
```

**合并基**：沿 `SnapshotBody::parents` 逐层回溯求最近公共祖先。先收集本地一侧的全部
祖先，再从远端一侧按**广度优先**推进，第一个落在祖先集合里的快照就是合并基。广度优先
保证「最近」，`BTreeSet` 与已排序的 `parents` 保证结果确定。回溯上限
`MAX_HISTORY_WALK = 10_000` 个快照——历史来自远端，属于不可信输入；触碰上限时**报错**
而不是「猜一个基」，因为猜错会让三方合并把别人的改动当成删除。

没有共同历史（两端各自独立初始化过工作区）时 `base` 为 `None`，按「双方都是新增」
处理。

合并逐资源进行，四种结论：

| `merge` 的 `outcome` | 含义 | 是否生成快照 |
|---|---|---|
| `already_up_to_date` | 远端没有新内容，或本地已经领先 | 否 |
| `fast_forward` | 本地是远端的祖先：直接采用远端状态 | 否（无需新快照） |
| `merged` | 真正做了三方合并 | 是，`parents = [local, remote]` |
| `conflicted` | 存在需要人工裁决的冲突 | **否** |

### 1.1 五种冲突种类

| `kind` | 触发条件 | 来自 |
|---|---|---|
| `text_overlap` | 双方修改了同一文本区域 | 文本 diff3 合并 |
| `delete_modify` | 一侧删除、另一侧修改 | 文本与结构化合并都可能产生 |
| `structured_key` | 结构化数据的同一键被双方改成不同值 | JSON / YAML / TOML / INI / Git config |
| `binary_both` | 二进制内容（含 NUL 或非 UTF-8）双方均修改，或输入超过 4 MiB | 文本合并的退化路径 |
| `incompatible_policy` | 双方对同一资源声明了不同的 `mode` / `policy` / `disposition` | 条目级判定，早于内容比较 |

`incompatible_policy` 值得单独说明：写入语义本身有分歧（一边说 `full_file`、另一边说
`managed_block`）时，任何一侧的内容都可能让另一侧的文件被错误改写，所以**在读取字节
之前**就判定为冲突。

### 1.2 冲突对象的字段

`Conflict` 是**内容寻址的不可变对象**（canonical CBOR，`ConflictId` 即其内容摘要）：

| 字段 | 类型 | 说明 |
|---|---|---|
| `format_version` | `u32` | 当前为 `1`；未知版本必须拒绝，不静默降级 |
| `resource` | `ResourceId` | 发生冲突的资源 |
| `kind` | `ConflictKind` | 上表五种之一 |
| `base` | `Option<BlobId>` | 合并基一侧的内容标识；双方均为新增时为 `None` |
| `ours` | `Option<BlobId>` | 本地一侧；本地删除时为 `None` |
| `theirs` | `Option<BlobId>` | 远端一侧；远端删除时为 `None` |
| `diagnostics` | `Vec<String>` | **只含位置与结构**：行区间、JSON Pointer、键路径 |

`diagnostics` 的例子（注意它们全都不含文件正文）：

```text
ours 12..18 vs theirs 12..15              ← 文本行区间（1 起）
modify/modify /editor/tabSize             ← 结构化键路径（JSON Pointer）
delete/modify /remote"origin"/url         ← 一侧删除、一侧修改
both sides modified non-line-mergeable content
input exceeds 4194304 bytes
content is binary (NUL byte or invalid UTF-8)
双方对写入模式或策略的声明不一致
```

**冲突对象是内容寻址的**，这带来一个重要性质：**同样的三侧内容必然得到同一个
`ConflictId`**。因此重复合并同一组内容不会产生新的冲突条目，而且**已经裁决过的决定
会被自动复用**（见第 5 节）。

### 1.3 为什么冲突 marker 绝不写进用户文件

Git 的做法是把 `<<<<<<< ours` / `=======` / `>>>>>>> theirs` 直接写进工作区文件。
EnvSync 明确**不这么做**，理由有四条：

1. **被管理的文件正在被别的程序读取。** `.zshrc`、`~/.gitconfig`、
   `Microsoft.PowerShell_profile.ps1` 会被 shell、git、PowerShell 在你毫无察觉时加
   载。一个带 marker 的 `.zshrc` 就是一个**语法错误的 shell 启动文件**——下一个新终端
   直接坏掉。Git 的工作区文件没有这个性质：源码文件不会被自动执行。
2. **marker 会被下一次 capture 采进快照。** EnvSync 的闭环是「观察 → 快照 → 发布」。
   如果 marker 写进了文件，`envsync capture` 就会把它当成正常内容采集，然后发布到后
   端，再同步给其他设备。**一次未裁决的冲突会污染所有设备的共享历史。**
3. **marker 破坏结构化格式。** JSON / TOML 里插入 marker 会让文件无法解析，于是下一
   次结构化合并直接报 `merge.parse`——冲突把自己变成了一个更难修的问题。
4. **「文件里有 marker」不是一个可靠的状态记录。** 用户可能手工删掉半个 marker、可能
   把文件另存为、可能被编辑器格式化。EnvSync 需要一个**权威且不可变**的冲突事实，
   那就是 `Conflict` 对象加上冲突索引里的一行状态。

因此合并器的返回类型在语法层面就排除了 marker：

```rust
pub enum MergeResult {
    Clean { bytes: Vec<u8>, provenance: MergeProvenance },  // 可直接落盘，绝不含 marker
    Conflict(Conflict),                                     // 只有摘要与结构性诊断
    Deleted,
}
```

`Clean` 分支的字节全部来自 base / ours / theirs 的**原始行或原始键值**，没有任何构造
marker 的代码路径。`Conflict` 分支只携带三个 `BlobId` 和不含正文的诊断。

要看差异，用 `envsync conflicts show` 拿到三侧的 `BlobId`，或直接比较本地文件与草稿库
里的内容——**由你决定什么时候看，而不是由 EnvSync 决定往你的启动文件里塞什么。**

---

## 2. 冲突状态机

```text
                      ┌────────────────────────────────┐
   envsync merge      │                                │
   登记冲突（幂等）    ▼                                │
                  ┌────────┐                           │
                  │  open  │  等待用户决定               │
                  └───┬────┘                           │
             ┌────────┴────────┐                       │
             │                 │                       │
  conflicts resolve      supersede()                   │ 同一 ConflictId 再次
  （用户做出决定）        （被新的合并结果取代）          │ 出现时**不会**重新打开
             │                 │                       │
             ▼                 ▼                       │
       ┌──────────┐     ┌─────────────┐                │
       │ resolved │     │ superseded  │  ← 终态 ───────┘
       └──────────┘     └─────────────┘
```

| 状态 | 含义 | 谁写入 |
|---|---|---|
| `open` | 等待用户决定 | `envsync merge` 登记时 |
| `resolved` | 用户已经给出解决方案（`ours` / `theirs` / `manual` / `delete`） | `envsync conflicts resolve` |
| `superseded` | 已被新的合并结果取代，无需处理 | `ConflictStore::supersede`（M1 暂无 CLI 入口） |

三条硬性规则：

1. **终态不会回到 `open`。** 冲突标识就是内容摘要：同样的冲突再次出现时它**还是同一
   行**；内容不同的冲突则是另一个标识、另一行。
2. **`record` 是幂等的**（SQL 里是 `ON CONFLICT (conflict_id) DO NOTHING`），尤其
   **绝不会把一个已经解决的冲突重新打开**。
3. **重复裁决被拒绝**：对已处于终态的冲突再次 `resolve` 报 `conflict.not_open`。
   读到 `open` 与写入之间被其他连接抢先解决时，`UPDATE … WHERE state = 'open'` 影响
   0 行，同样报 `conflict.not_open`。

### 2.1 索引里存什么、不存什么

`conflicts` 表只存**索引与状态**：工作区、资源、种类、三个 Blob 指针、当前状态、解决
方式、结果 Blob、时间戳。

**诊断正文不入库**：它是不可变对象的一部分，复制一份进关系表就会出现两个可能不一致的
事实来源。需要正文时按 `ConflictId` 去草稿库取对象——`conflicts show` 正是这么做的。

冲突索引与草稿库**刻意共用同一个数据库文件**（`<state_dir>/draft/` 下）：
`ConflictStore::resolve` 需要在 `objects` 表里确认结果 Blob 确实存在，而那张表属于草
稿库。分成两个文件会让这道检查永远失败。

---

## 3. 命令

```text
envsync conflicts list    --config <path>
envsync conflicts show    --config <path> --conflict <conflict-id>
envsync conflicts resolve --config <path> --conflict <conflict-id>
                          (--ours | --theirs | --file <path> | --delete)
```

这三条命令**只读写本地冲突索引与草稿库**，不联网、不碰用户文件，因此离线可用。
它们只在 JSON schema v2 中定义（`--schema-version 1` 会被拒绝）。

### 3.1 `conflicts list`

列出**当前工作区**中全部 `open` 的冲突，按登记时间、标识升序。

```text
未解决冲突：2 个
  - 3f8a1c05d2e7…（vcs/git/user，structured_key）
  - a91b7e44c608…（shell/zsh/main，text_overlap）
```

```json
{
  "open": 2,
  "conflicts": [
    {
      "conflict": "3f8a1c05d2e7…",
      "resource": "vcs/git/user",
      "kind": "structured_key",
      "state": "open"
    }
  ]
}
```

没有未解决冲突时输出「没有未解决的冲突。」，`open` 为 `0`，`conflicts` 为空数组。

### 3.2 `conflicts show`

查看单个冲突的详情。**不含文件正文**——只有三侧的内容标识与结构性诊断。

```text
冲突 3f8a1c05d2e7…
  资源：vcs/git/user
  种类：structured_key
  状态：open
  base：7a2c9e11…
  ours：4d0f5b83…
  theirs：91ce7a20…
    · modify/modify /user/email
```

```json
{
  "conflict": "3f8a1c05d2e7…",
  "resource": "vcs/git/user",
  "kind": "structured_key",
  "state": "open",
  "base": "7a2c9e11…",
  "ours": "4d0f5b83…",
  "theirs": "91ce7a20…",
  "diagnostics": ["modify/modify /user/email"]
}
```

`base` / `ours` / `theirs` 为 `null` 表示该侧不存在该资源（双方新增时 `base` 为
`null`，某侧删除时对应字段为 `null`）。冲突不存在时报错，错误码
`operation.not_found`，退出码 1。

### 3.3 `conflicts resolve`

四种裁决**互斥**，必须给出且只能给出一个；一个都不给是**用法错误**（退出码 2），
EnvSync 不会替你挑一个默认值。

| 开关 | 语义 | 结果 Blob | 该侧是删除时 |
|---|---|---|---|
| `--ours` | 采用**本地**一侧的内容 | `conflict.ours` | **报错**：「ours 一侧是删除，请改用 `--file` 或 `delete` 裁决」 |
| `--theirs` | 采用**远端**一侧的内容 | `conflict.theirs` | 同上（针对 theirs） |
| `--file <PATH>` | 采用该文件的内容（人工合并结果） | 读入的字节存成**新 Blob** | 与删除无关，总是可用 |
| `--delete` | **确认删除**该资源 | 无（`null`） | — |

```bash
# 采用远端版本
envsync conflicts resolve --config "$CFG" --conflict 3f8a1c05d2e7… --theirs

# 人工合并：先把两侧内容导出来，手工改好，再喂回去
envsync conflicts resolve --config "$CFG" --conflict 3f8a1c05d2e7… --file /tmp/merged-gitconfig

# 确认删除
envsync conflicts resolve --config "$CFG" --conflict a91b7e44c608… --delete
```

输出：

```text
冲突 3f8a1c05d2e7… 已裁决为 theirs
  结果内容：91ce7a20…
下一步：重新运行 `envsync merge`。
```

```json
{
  "conflict": "3f8a1c05d2e7…",
  "choice": "theirs",
  "resolved_blob": "91ce7a20…"
}
```

`--delete` 时 `resolved_blob` 为 `null`，人类可读输出里显示「（删除）」。

**几条重要语义**

- **`--delete` 是唯一能让资源消失的裁决。** 与 `disposition: ensure_absent` 一样，
  删除必须由人显式表达；合并器自己永远不会推断出删除意图。
- **裁决选定的内容一律以新 Blob 写进草稿库**，因此后续重新合并时一定取得到。
  `--ours` / `--theirs` 也会把对应侧的字节读出来再写一遍草稿库——冲突可能来自远端，
  本地草稿库未必已经有它。
- **写入索引前再确认一次 Blob 存在**（`ConflictStore::resolve` 查 `objects` 表）。
  这道检查必须发生在动用户文件之前：如果等到收敛阶段才发现内容取不到，届时文件可能
  已经被改写，只能走回滚。
- **`--file` 的内容不做任何格式校验**：它是你的最终决定。若内容不是合法的目标格式，
  问题会在下一次结构化合并时以 `merge.parse` 暴露出来。
- 读取 `--file` 失败时错误信息**只保留文件名与错误类别**，不出现绝对路径。

### 3.4 错误码

| 错误码 | 触发条件 | 退出码 |
|---|---|---|
| `conflict.unknown` | 冲突标识在索引里不存在 | 1 |
| `conflict.not_open` | 冲突已处于 `resolved` / `superseded` | 1 |
| `conflict.mismatch` | 解决方案针对的冲突与被操作的不一致（内部一致性检查） | 1 |
| `conflict.invalid_resolution` | 解决方案形状不自洽，或引用了不存在的 Blob | 1 |
| `conflict.corrupt` | 索引里存在无法解释的值 | 1 |
| `conflict.sqlite` / `conflict.storage` | 底层存储错误 | 1 |
| `operation.not_found` | `conflicts show` 找不到该冲突 | 1 |
| `recovery.manual_required` | `--ours` / `--theirs` 指向的那一侧是删除；或裁决内容读不出来 | 1 |
| （clap 用法错误） | 四个裁决开关一个都没给 | **2** |

---

## 4. 退出码 13 与「两边都不变」的保证

| 码 | 含义 | 谁产生 |
|---|---|---|
| **10** | 后端 **CAS 冲突**：别的设备先发布了 | `sync` 的发布阶段 |
| **13** | 存在未解决的**合并冲突** | `sync` 的最前置检查 |

两者容易混淆，务必分清：

| | 退出码 10（CAS 冲突） | 退出码 13（合并冲突） |
|---|---|---|
| 冲突在哪一层 | 后端 Ref 的 revision | 资源**内容** |
| 谁能解决 | 重新 `capture` / `plan` / `sync` 即可，机器能自动处理 | 只能**由人**裁决 |
| 错误码 | `cas_conflict` | `sync.conflicted` |
| 保证 | 本地一个字节都没被写过 | 本地文件与远端 Ref **都没有被改动** |

### 4.1 保证是怎么成立的

退出码 13 由 `EnvSyncService::apply_plan` 的**第一行**产生：

```rust
pub fn apply_plan(&mut self, plan_id: PlanId) -> CoreResult<ApplyOutcome> {
    // 未解决的冲突一票否决，而且必须排在最前面：此后的任何一步都会动本地文件
    // 或远端 Ref，而「有冲突时两者都不变」是 M1 的硬性承诺。
    let open = self.conflicts_list()?;
    if !open.is_empty() {
        return Err(CoreError::Conflicted { count: open.len() });
    }
    // …恢复、新鲜度校验、上传对象、CAS 发布、逐动作应用…
}
```

**位置就是保证本身**：这条检查排在自动恢复、计划新鲜度校验、对象上传、CAS 发布、动作
应用之前。它之后的每一步都会动本地文件或远端 Ref，所以只要它先返回，两者必然都没被
碰过。

另一半保证来自合并侧——`merge_states` 在发现冲突时：

- **不**生成合并快照（否则一个未经裁决的结果会成为共享历史的一部分）；
- **不**设置草稿头；
- **不**推进远端 Ref（发布只发生在显式 `apply`）；
- **不**改任何本地文件（合并只读写对象库与冲突索引）；
- 只把 `Conflict` 对象写进草稿库、把索引行写进 `conflicts` 表。

### 4.2 `merge` 本身不返回 13

**`envsync merge` 发现冲突时退出码是 0**，`data.outcome` 为 `"conflicted"`，
`data.conflicts` 列出冲突标识。这是刻意的：merge 成功地完成了它的工作——**发现并登记
了冲突**，这不是失败。

退出码 13 只在你试图 `sync` 时出现。脚本应当这样判断：

```bash
MERGED=$(envsync merge --config "$CFG" --json)
if [ "$(echo "$MERGED" | jq -r '.data.outcome')" = "conflicted" ]; then
    echo "$MERGED" | jq -r '.data.conflicts[]'
    exit 1
fi
```

`envsync status` 也会把工作区标成 `conflicted`，并在 `data.open_conflicts` 给出数量
（schema v2 起）。

---

## 5. 恢复流程：从发现冲突到重新同步

```text
 ①  envsync fetch     把远端对象拉进本地草稿库（不碰用户文件）
        ↓
 ②  envsync merge     三方合并 → outcome=conflicted，登记冲突，退出码 0
        ↓             本地文件与远端 Ref 都没变
 ③  envsync conflicts list      看有哪些冲突
        ↓
 ④  envsync conflicts show      逐个看资源、种类、三侧摘要与诊断
        ↓
 ⑤  envsync conflicts resolve   逐个裁决（ours / theirs / file / delete）
        ↓
 ⑥  envsync merge     **再合并一次**：已裁决的冲突被自动复用 → outcome=merged
        ↓
 ⑦  envsync plan      针对合并后的目标状态生成不可变计划
        ↓
 ⑧  envsync sync      发布 + 收敛（此时 open_conflicts 为 0，不会退 13）
        ↓
 ⑨  envsync status    确认回到 clean
```

### 5.1 完整脚本

```bash
CFG=/home/YOUR_USER/.config/envsync/envsync.yaml

# ① 拉取远端
envsync fetch --config "$CFG"

# ② 合并
envsync merge --config "$CFG" --json | jq '{outcome: .data.outcome, conflicts: .data.conflicts}'
# → {"outcome": "conflicted", "conflicts": ["3f8a1c05d2e7…", "a91b7e44c608…"]}

# ③④ 逐个查看
for C in $(envsync conflicts list --config "$CFG" --json | jq -r '.data.conflicts[].conflict'); do
    envsync conflicts show --config "$CFG" --conflict "$C"
done

# ⑤ 裁决（这里必须由人判断，不要写成无条件的 --theirs）
envsync conflicts resolve --config "$CFG" --conflict 3f8a1c05d2e7… --theirs
envsync conflicts resolve --config "$CFG" --conflict a91b7e44c608… --file /tmp/merged-zshrc

# ⑥ 再合并
envsync merge --config "$CFG" --json | jq -r '.data.outcome'
# → "merged"

# ⑦⑧ 计划并应用
PLAN=$(envsync plan --config "$CFG" --json | jq -r '.data.plan')
envsync sync --config "$CFG" --plan "$PLAN"

# ⑨ 确认
envsync status --config "$CFG" --json | jq '{state:.data.state, conflicts:.data.open_conflicts}'
# → {"state": "clean", "conflicts": 0}
```

### 5.2 第 ⑥ 步为什么能自动复用裁决

冲突是内容寻址的：同样的 base / ours / theirs 三侧内容，必然算出同一个 `ConflictId`。
所以第二次 `merge` 走到同一个资源时：

1. 合并器再次得出 `MergeResult::Conflict(conflict)`；
2. `resolved_entry` 用 `conflict.id()` 去冲突索引查询；
3. 查到状态为 `resolved` 的记录 ⟹ **直接采用用户已经做出的决定**：
   - `resolved_blob` 有值 ⟹ 该资源用这个 Blob，处置设为 `managed`；
   - `resolved_blob` 为 `null`（`--delete`）⟹ 该资源在合并结果中**不存在**；
4. 该资源不再计入本轮冲突，合并得以继续走完。

因此**不需要重新 fetch，也不需要重新裁决**——只要三侧内容没变，决定就一直有效。
反过来，如果在裁决之后远端又推进了（theirs 变了），三侧内容不同 ⟹ 新的 `ConflictId`
⟹ **新的冲突**需要重新裁决。这正是我们想要的：你裁决的是**那一组具体内容**，不是
「这个资源以后都听远端的」。

### 5.3 常见变体

**冲突只涉及一个资源，你确定要用远端版本**

```bash
C=$(envsync conflicts list --config "$CFG" --json | jq -r '.data.conflicts[0].conflict')
envsync conflicts resolve --config "$CFG" --conflict "$C" --theirs
envsync merge --config "$CFG"
```

**想在裁决前看看两侧到底差在哪**

`conflicts show` 只给摘要，不给正文（这是刻意的）。要看内容，请对照本地文件与你在
另一台设备上的版本，或按诊断给出的键路径 / 行区间定位。诊断已经足够精确：

```text
modify/modify /user/email          ← 就看这个键
ours 12..18 vs theirs 12..15       ← 就看这几行
```

**裁决错了，想改**

不能直接改：冲突已处于终态，再次 `resolve` 报 `conflict.not_open`。正确做法是**先让
内容前进一步**——在本机把文件改成你真正想要的样子，`envsync capture` 生成新草稿头，
再 `merge`。三侧内容变了，就是一个新的冲突（或者干脆不再冲突）。

**一侧是删除，`--ours` / `--theirs` 报错**

```text
冲突 3f8a1c05… 的 theirs 一侧是删除，请改用 --file 或 delete 裁决
```

这是有意的：`--theirs` 的语义是「采用远端**的内容**」，而远端根本没有内容。想接受删除
就用 `--delete`（显式确认删除），想保留就用 `--ours` 或 `--file`。

**离线时能做什么**

`conflicts list` / `show` / `resolve` 全部离线可用（只读写本地）。`fetch`、`plan`、
`sync` 需要联网。所以「在飞机上把冲突裁决完，落地后再同步」是可行的——前提是起飞前
已经 `fetch` 过。

---

## 6. 相关文档

- [合并规则](merge.md)：五种结构化格式与文本合并的详细规则、已知限制与资源上限
- [命令行文档](cli.md)：`merge` / `conflicts` 的完整参数与 JSON 契约
- [Git 后端](backends/git.md)：CAS 冲突（退出码 10）与远端行为
- [设备 Profile 与投影](profiles.md)：合并之后的投影阶段
- [M0 运维手册](m0-operations.md)：事务边界、失败状态与回滚
