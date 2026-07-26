# EnvSync 安全模型（M0）

本文描述 EnvSync **M0 阶段**的信任边界、实际提供的安全保证，以及**明确不提供**的保证。

第三部分（§3「M0 不提供的保证」）与前两部分同等重要。一个同步工具最危险的失败模式不是
「缺少某项防护」，而是「用户以为它有」。在把真实凭据交给 EnvSync 之前，请把 §3 读完。

配套文档：运维流程见 [`docs/m0-operations.md`](m0-operations.md)，命令与 JSON 契约见
[`docs/cli.md`](cli.md)，设计原则见
[`docs/superpowers/specs/2026-07-24-envsync-design.md`](superpowers/specs/2026-07-24-envsync-design.md)。

---

## 1. 信任边界

### 1.1 谁被信任

| 主体 | M0 的信任级别 | 说明 |
|---|---|---|
| 本机 EnvSync 进程 | **完全信任** | 它按你的配置读写你的文件，这是它的全部工作 |
| 本机配置文件 `envsync.yaml` | **完全信任** | 授权根、资源清单、策略全部来自它。**能改这个文件的人 = 能让 EnvSync 写任何被授权目录下的文件** |
| 本机 `state_dir` | **完全信任** | journal 是崩溃恢复的唯一事实来源，备份是唯一的字节级退路 |
| 本机已解锁的用户账户 | **完全信任**（M0 的边界即在此） | 见 §3.6 |
| **后端存储** | **部分信任**：完整性由内容寻址自校验，**机密性不设防** | 见下 |
| 网络与传输通道 | M0 **不适用**（本地目录后端无网络 I/O）；M1 起由 Git 传输层负责 | — |
| 其他设备 | **不做密码学验证** | M0 的 `SnapshotSignature.algorithm` 恒为 `"none"` |
| 插件 | **不适用** | M0 无插件机制（M4） |
| Agent Bundle | **不适用** | M0 无 Agent Bundle（M3） |

### 1.2 后端：可以篡改，但不能骗你

后端在 M0 被当作一个**可能损坏、可能被替换、但不会被当作真相来源**的存储：

| 后端能做的事 | EnvSync 的反应 |
|---|---|
| 返回与请求摘要不符的对象字节 | 拒绝返回内容，报 `corruption` |
| 用一个 Blob 冒充一个 State Root | 域分隔哈希使两者摘要空间不相交，冒充不成立 |
| 提供非 canonical 但语义等价的 CBOR | 解码器拒绝（ADR-0001） |
| 提供未知 `format_version` 的对象 | 拒绝，绝不静默降级 |
| **读取你同步的全部配置明文** | **完全可以**——M0 没有加密（§3.1、§3.2） |
| **把 Ref 回退到旧 revision** | **可以**——M0 没有本地检查点（§3.3） |
| 删除对象 | 检测得到（`object.missing`），但无法自愈 |

一句话概括：**M0 信任后端持有的内容不会被神不知鬼不觉地改掉（靠摘要），但完全不信任
它保密（没有加密），也不信任它不会倒退（没有反回滚）。**

### 1.3 用户文件系统：只碰被授权的地方

```text
                 ┌──────────────────────────────────────┐
                 │  配置里声明的 roots（授权根白名单）    │
                 │                                      │
   EnvSync ─────►│   home: /home/YOUR_USER              │──► 可读可写
   （只经由      │   xdg_config: /home/YOUR_USER/.config │
     platform    └──────────────────────────────────────┘
     crate）
                 ┌──────────────────────────────────────┐
        ✗ ──────►│  授权根之外的一切                     │──► 一律拒绝
                 │  符号链接指向的根外目标               │
                 │  ../ 逃逸、绝对路径、UNC、盘符        │
                 └──────────────────────────────────────┘
```

`envsync-platform` 是**唯一**被允许触碰用户文件系统的 crate。上层（core、cli）只描述
「在哪个授权根的哪个相对目标上做什么」，真实路径解析、符号链接拒绝、原子替换、备份与回滚
全部在这一个可以被完整审计的模块里完成。

**备份目录刻意不放在授权根内部**——否则备份自身会被下一次同步当成用户文件。

---

## 2. M0 提供的保证

每条保证都给出实现依据与锁定它的测试。测试名可直接用
`cargo test --workspace <名字>` 运行。

### 2.1 路径约束

**保证：EnvSync 永远不会读写授权根之外的任何路径。**

两层防护，缺一不可：

**第一层：纯文本校验（`RelativeTarget::parse`），在任何系统调用之前执行。**
因为它不需要文件系统，所以一份计划**在没有磁盘的环境里也能被验证**。被拒绝的形状：

| 形状 | 例子 | 错误 |
|---|---|---|
| 绝对路径 | `/etc/passwd` | `TargetError::Absolute` |
| `..` / `.` 段 | `../../etc/passwd`、`./.zshrc` | `TargetError::DotSegment` |
| 空段 | `a//b`、`/a`、`a/` | `TargetError::EmptySegment` |
| Windows 盘符 / 冒号 | `C:/Users/x`、`a:b` | `TargetError::DriveLetter` |
| UNC 前缀 | `//server/share`、`\\server\share` | `TargetError::UncPrefix` |
| 反斜杠 | `a\b` | `TargetError::Backslash` |
| Windows 保留设备名 | `NUL`、`NUL.txt`、`com1` | `TargetError::ReservedDeviceName` |
| 以空格或点结尾的段 | `"file "`、`"file."` | `TargetError::TrailingDotOrSpace` |
| NUL 与控制字符 | `a\0b` | `TargetError::NulByte` / `ControlCharacter` |
| 超长 / 超段数 | >1024 字节 / >32 段 | `TargetError::TooLong` / `TooManySegments` |

冒号即使不在开头也一律拒绝：它在 NTFS 上是备用数据流分隔符。以空格或点结尾的段也拒绝：
Windows 会静默去掉它们，从而让两个不同的目标指向同一个文件，破坏「计划决定唯一目标」的
前提。**这些限制在三大平台上一致生效**，好让同一份配置在 Linux、macOS、Windows 上表达
完全相同的意图。

**第二层：运行时逐段 no-follow 解析（`AuthorizedRoot::resolve`）。**
即使目标文本合法，中间目录仍可能是指向授权根之外的符号链接。EnvSync 持有授权根的
`cap_std::fs::Dir` 能力句柄，对每个中间段先 `symlink_metadata`（no-follow）确认既不是符号
链接又确实是目录，再 `open_dir` 进入下一段；最终段若已存在，同样确认不是符号链接。所有调用
都是**相对当前目录句柄**的，不经过任何绝对路径，因此不依赖进程 cwd。

| 实现依据 | 锁定测试 |
|---|---|
| `envsync-platform::capability::parse_segments` | `rejects_absolute_dotdot_nul_drive_unc_and_device_names` |
| `AuthorizedRoot::resolve` 逐段 no-follow | `rejects_symlinked_intermediate_directory` |
| 同上，最终段 | `rejects_symlinked_final_file_even_inside_root` |
| `SafeWriter` 只经 `ResolvedPath::dir` 写入 | `writes_are_confined_to_the_authorized_root` |
| 根别名必须已注册 | `unregistered_root_alias_is_rejected` |
| 根必须是已存在的目录 | `root_must_be_an_existing_directory` |
| 配置层同样拒绝非法 target | `rule05_invalid_targets_are_rejected` |
| `ResourceId` 自身不得像路径 | `resource_id_accepts_canonical_form_and_rejects_path_escapes` |

补充保证：**失败绝不被伪装成缺失。** 权限错误、I/O 错误、超限都返回明确错误或
`ObservedState::Unreadable`，永远不会变成 `Absent`——因为 `Absent` 在计划层意味着
「可以放心创建」（测试 `missing_target_is_absent_not_unreadable`、
`permission_error_is_unreadable_not_absent`、`directory_target_is_unreadable`）。

超限文件**绝不截断**，一律报 `platform.too_large`
（测试 `oversized_target_errors_without_truncating`、
`oversized_content_is_rejected_before_touching_target`）。

### 2.2 默认不删除

**保证：只有配置里显式写了 `disposition: ensure_absent` 的资源，才可能产生删除动作。**

五种观察状态——`present`、`absent`、`unsupported`、`unreadable`、`excluded`——**没有一种**
会被推断为删除意图。「远端没有」「本机读不出来」「平台不支持」「被策略排除」都不等于
「删掉它」。

| 实现依据 | 锁定测试 |
|---|---|
| `DesiredDisposition` 只有三个变体，删除动作只从 `EnsureAbsent` 生成 | `a_missing_observation_never_becomes_a_tombstone` |
| `capture` 读不到资源时沿用上一版快照条目并留 `capture.reused_previous` 警告 | `capture_never_turns_a_missing_file_into_a_deletion`、`capture_reuses_previous_entry_when_a_resource_is_unreadable` |
| 目标快照里没有的资源不产生任何动作 | `resource_missing_from_snapshot_is_never_deleted` |
| 只有 `ensure_absent` 生成 `delete_file` | `only_ensure_absent_produces_delete_actions` |
| `ensure_absent` 且目标本就不存在 → 无动作 | `absent_target_with_ensure_absent_produces_no_action` |
| 不可读 / 不支持的资源永远不可写 | `unreadable_and_unsupported_are_never_writable` |
| Managed Block 的 tombstone 只删块不删文件 | `managed_block_tombstone_removes_block_not_file` |

删除动作在计划里恒为 `risk: high`，且 `backup: required`——**删除前总是先备份**。

### 2.3 计划先行

**保证：任何对用户文件的写入都必须先出现在一份不可变的计划里，且该计划以内容摘要绑定
了当时的本机现状。**

`Plan` 绑定：格式版本、工作区、设备、目标快照、base revision、待写入的下一个 Ref、
全部观察结果（含每个资源的内容摘要）、全部动作、全部诊断。`PlanId` 是这些内容的域分隔
摘要。因此**任何一项变化都会改变 Plan ID**，`sync` 的新鲜度检查就是一次纯粹的等价性判断：
重新观察、重新计划，比较标识。

**不参与** Plan ID 的是「每次运行都会变、且不代表状态差异」的字段——`Plan::created_at_unix_ms`
与每条 `Observation::observed_at_unix_ms`（ADR-0003）。判据是「如果这个字段变了，用户是否
需要重新审阅这份计划？」时刻不需要，内容摘要需要。这让计划可以被保存、传输、在桌面端审阅
三分钟后再应用，而不会因为审阅耗时而失效。

计划里**绝不保存绝对路径**：`ActionTarget` 只有授权根别名 + 相对分段。绝对路径既是本机信息
泄露，也让计划无法在设备之间被审阅比较。

所有依赖当前文件内容的逻辑（Managed Block 渲染尤其如此）都发生在**计划阶段**并被
`expected_before` 摘要绑定；应用阶段只做「写入这些已经算好的字节」。

| 实现依据 | 锁定测试 |
|---|---|
| Plan 绑定草稿头、后端 Ref 与本机观察 | `plan_binds_draft_head_backend_ref_and_local_observations` |
| 任一绑定输入变化即改变 Plan ID | `plan_id_changes_when_any_bound_input_changes` |
| 输入顺序不影响 Plan ID | `plan_id_is_independent_of_input_order` |
| 生成时刻不影响 Plan ID | `plan_id_is_independent_of_creation_time`、`plan_id_ignores_observation_timestamps` |
| 相同条件下跨运行确定性 | `planning_is_deterministic_across_runs` |
| 目标被改动后计划失效 | `apply_plan_rejects_a_stale_plan_after_the_target_changed`、`stale_plan_exits_11` |
| 未知计划标识被拒绝 | `apply_plan_rejects_an_unknown_plan_id`、`unknown_plan_id_exits_11` |
| 阻塞诊断在登记 operation 之前拦截 | `blocked_plan_is_rejected_without_touching_the_journal`、`blocking_diagnostic_exits_12` |
| 写入前再次比对摘要 | `stale_digest_before_write_is_rejected`、`expecting_absent_but_target_exists_is_stale` |

### 2.4 原子替换与备份

**保证：一次动作被中断后，目标文件要么是旧值、要么是新值，且旧值总有一份可校验的备份。**

写入序列及其理由：

```text
解析路径（逐段 no-follow）
  → 重读目标并比对 expected_before   ← 计划绑定的现状必须仍然成立
  → 同目录临时文件（O_EXCL 创建）+ 写入 + fsync
                                     ← 到此为止目标一个字节都没变：临时文件是独立 inode
  → 备份原文件（copy 语义，原文件保持原地）
                                     ← 用 rename 挪走原文件会让目标短暂消失
  → rename 覆盖                      ← POSIX 原子；Windows 走 MoveFileEx + REPLACE_EXISTING
  → fsync 父目录                     ← 否则崩溃后目录项可能仍指向旧 inode
```

**备份失败即动作失败。** 宁可什么都不做，也不在没有退路的情况下覆盖。备份写入的正是刚刚
读出并已计算摘要的同一份字节，因此备份内容与收据的 `original_digest` 天然一致，比「再 copy
一次」少一个竞态窗口。

**回滚是被摘要守卫的，不是盲目的：** 目标当前摘要必须等于收据的 `applied_digest`，备份内容
摘要必须等于 `original_digest`，任一不符即**拒绝**并保持现场不变。

事务层面：CAS 发布发生在**任何本地写入之前**；任一动作失败则已应用的动作按**逆序**回滚。

| 实现依据 | 锁定测试 |
|---|---|
| rename 之前目标不变 | `temp_file_does_not_change_target_before_rename` |
| 替换后摘要与权限正确 | `successful_replace_matches_digest_and_permissions` |
| 备份路径确定性 | `original_file_is_backed_up_to_deterministic_path`、`backup_path_is_deterministic` |
| 删除总是先备份 | `delete_always_backs_up_first` |
| 删除不存在的目标是幂等成功 | `deleting_missing_target_is_idempotent_success` |
| 中断留下可恢复证据 | `injected_rename_failure_keeps_target_and_backup_as_evidence`、`injected_delete_failure_keeps_backup` |
| 早期失败不留垃圾 | `injected_staging_failure_cleans_up_and_leaves_no_backup` |
| 回滚精确还原原字节 | `rollback_restores_original_bytes`、`explicit_rollback_of_a_completed_operation_restores_original_bytes` |
| 新建文件的回滚 = 删除 | `rollback_of_created_file_removes_it` |
| 目标被改过则拒绝回滚 | `rollback_refused_when_target_changed_after_apply` |
| 备份缺失 / 损坏则拒绝回滚 | `rollback_refused_when_backup_is_missing`、`rollback_refused_when_backup_content_is_corrupted` |
| CAS 冲突时不触碰文件系统 | `cas_conflict_never_invokes_the_file_mutator`、`cas_conflict_exits_10` |
| preflight 失败时后端与本地零变更 | `preflight_failure_leaves_backend_and_local_untouched` |
| 失败按逆序回滚 | `failure_midway_rolls_back_applied_actions_in_reverse_order`、`verify_failure_rolls_back_current_and_previous_actions` |
| 回滚失败保留 `published_not_converged` | `rollback_failure_keeps_published_not_converged_with_both_errors` |
| 崩溃恢复幂等且不覆盖外部修改 | `recovery_is_idempotent_on_the_converging_path`、`diverged_target_stops_and_never_overwrites_user_changes` |
| Ref 替换中断后旧/新 Ref 必有其一完整 | `leftover_temp_files_do_not_disturb_ref_reads` |
| 并发 CAS 只有一方成功 | `concurrent_cas_has_exactly_one_winner` |

### 2.5 内容寻址与 canonical 编码

**保证：摘要不匹配的对象绝不被返回给上层；同一逻辑对象只有唯一一种合法字节表示。**

- 所有标识都是 **BLAKE3 32 字节摘要 + 域分隔标签**（`envsync:blob:v1`、`envsync:state:v1`、
  `envsync:snapshot:v1`、`envsync:plan:v1` 等，完整表见
  [`m0-operations.md` §1.3](m0-operations.md)）。域分隔让字节相同、种类不同的对象拥有不同
  摘要，杜绝跨种类冒充。
- 除 Blob 外的所有对象使用**严格 canonical CBOR 子集**（ADR-0001）：确定长度编码、最短整数
  编码、map 键按编码字节严格升序、无重复键、不支持浮点数 / tag / simple value、深度上限 64、
  节点上限 4,000,000、顶层解析后不得有剩余字节。解码后还会重新编码并**逐字节比较**作为纵深
  防御。
- 「解码成功」因此蕴含「输入是唯一 canonical 表示」。这条性质是内容寻址去重、校验和 M2 反
  回滚检查的地基：只要存在两种字节序列解码为同一逻辑对象，攻击者就能构造摘要不同、语义相同
  的对象绕过这些机制。
- 校验发生在**每一个边界**：后端写入前、后端读出后、草稿库写入前、草稿库读出后、preflight
  暂存内容时。

| 实现依据 | 锁定测试 |
|---|---|
| 相同字节 → 相同 `BlobId` | `identical_bytes_always_hash_to_the_same_blob_id` |
| 插入顺序不影响 State Root ID | `state_root_id_ignores_entry_insertion_order` |
| metadata 顺序不影响 Snapshot ID，但内容影响 | `snapshot_id_ignores_metadata_order_but_tracks_content` |
| 非 canonical 编码被拒绝 | `non_canonical_encodings_are_refused` |
| 未知 `format_version` 被拒绝 | `changing_the_format_version_changes_the_identity_and_decoding_is_refused`、`state_root_rejects_unknown_format_version` |
| 摘要不符可由重算检出 | `digest_mismatch_is_detectable_by_recomputation` |
| 后端读出时校验，损坏对象不返回 | `get_object_verifies_digest_and_never_returns_corrupt_bytes` |
| 后端写入时校验 | `put_object_rejects_bytes_that_do_not_match_id`、`put_object_detects_existing_object_with_different_content` |
| 草稿库两端都校验 | `put_rejects_bytes_that_do_not_match_the_object_id`、`get_reports_corruption_instead_of_returning_tampered_bytes` |
| preflight 校验动作内容 | `preflight_rejects_content_that_does_not_match_its_blob_id` |
| Ref 只能单调前进 | `non_monotonic_or_foreign_ref_is_rejected`、`first_cas_only_accepts_expected_revision_zero`、`stale_expected_revision_returns_conflict_with_observed_revision` |
| 后端目录格式标记逐字节校验 | `open_rejects_directory_with_wrong_format_marker` |

### 2.6 输出脱敏

**保证：错误信息不含绝对路径；所有输出（人类可读与 JSON）都经过同一个脱敏器。**

三层：

1. **结构上不产生。** `PlatformError` 的每个变体的 `Display` 只包含授权根别名、相对分段、
   摘要短表示和 `io::ErrorKind` + OS 错误码。这里故意**不使用** `io::Error` 的 `Display`——
   某些来源会把路径拼进消息里。`Blob` 的 `Debug` 只输出标识与长度，绝不输出内容。
   `ResolvedPath` 的 `Debug` 只输出 `alias:a/b/c` 展示串。
2. **计划与诊断不携带敏感内容。** `Diagnostic.code` / `message` 与 `ActionTarget` 都不含绝对
   路径；被 `policy.secret` 标记的资源，其**内容**从不出现在任何输出里，计划里只有
   `sensitive: true` 标记和内容摘要。
3. **统一脱敏器兜底。** 人类可读文本走 `redact_text`，JSON 走 `redact_json`：
   - 按键名：键名（忽略大小写与 `-`/`_`）包含 `token`、`secret`、`password`、`apikey`、
     `authorization`、`bearer` 时，**整个值**（哪怕是对象或数组）替换为 `"<redacted>"`；
   - 按文本：`bearer <令牌>`（令牌 ≥8 个 `[A-Za-z0-9._-]` 字符）与
     `<敏感键>=<值>` / `<敏感键>: <值>` 替换为 `<redacted>`。

脱敏是**保守**的：值必须以 ASCII 字母或数字开头才会被吃掉，所以「token 数量为 3」这类正常
文本不会被误伤。它是**最后一道防线，不是唯一一道**。

`--json` 时 stdout **只有一行 JSON**，日志 writer 固定为 stderr——否则日志会污染契约。

| 实现依据 | 锁定测试 |
|---|---|
| I/O 错误不带路径 | `io_errors_never_carry_paths` |
| `Blob` 的 `Debug` 不泄露内容 | `blob_debug_never_leaks_content` |
| `ResolvedPath` 的 `Debug` 不泄露绝对路径 | `resolved_path_never_leaks_absolute_path_in_debug` |
| 后端错误不带绝对路径 | `errors_never_leak_absolute_paths` |
| 配置层 I/O 错误不带绝对路径 | `rule13_io_error_does_not_leak_absolute_path` |
| 校验失败信息不泄露路径 | `verify_reports_mismatch_without_leaking_paths` |
| 敏感键名识别 | `sensitive_key_variants_are_detected` |
| JSON 敏感键整棵子树被替换 | `json_sensitive_key_variants_are_replaced`、`sensitive_key_replaces_whole_subtree`、`json_nested_objects_and_arrays_are_redacted` |
| 纯文本 bearer / key=value 脱敏 | `plain_text_bearer_token_is_redacted`、`plain_text_key_value_is_redacted` |
| 日志不污染 JSON stdout | `logs_never_pollute_json_stdout`、`human_output_goes_to_stdout_and_errors_to_stderr` |

### 2.7 `forbid(unsafe_code)`

工作区的**每一个 crate**——`envsync-domain`、`envsync-backend`、`envsync-platform`、
`envsync-storage`、`envsync-core`、`envsync-cli`，以及端到端验收套件 `envsync-e2e`——
都在 crate 根设置了 `#![forbid(unsafe_code)]`。这是编译期强制的：任何 `unsafe` 块都会导致
编译失败，无法用 `#[allow]` 局部豁免。

代价与收益的取舍见 §3.7（Windows 未使用 `ReplaceFileW`）。

CI 在 `ubuntu-latest`、`macos-latest`、`windows-latest` 三平台运行
`cargo fmt --all --check`、`cargo clippy --workspace --all-targets -- -D warnings`、
`cargo test --workspace`、`cargo test --workspace --doc`，另有 `cargo audit` 依赖审计
（记录但不阻塞合并）。

---

## 3. M0 明确不提供的保证

以下每一条都是**当前的真实状态**，不是疏忽。

### 3.1 没有任何密码学签名

`SnapshotSignature` 的字段布局已经固定，但 M0 的 `algorithm` 恒为 `"none"`、`signature` 为
空字节（`SnapshotSignature::unsigned`）。因此：

- **无法验证一个快照确实由哪台设备创建。** `SnapshotBody.author_device` 只是一个自述字段，
  任何能写后端的人都可以伪造。
- **无法检测后端内容被替换成另一份内部自洽的历史。** 摘要保证「对象没被改坏」，但不保证
  「这些对象是你的设备写的」。

真正的 Ed25519 签名与强制校验在 **M2**。在此之前，**后端目录的写权限等价于对工作区的完全
控制权**——请像对待私有目录一样保护它。

### 3.2 没有加密：后端持有明文配置内容

Blob 就是文件的原始字节，没有任何加密层。**任何能读后端目录的人都能读到你同步的全部配置
文件内容。**

具体含义：

- 放在网盘或共享目录上的后端 = 把这些配置文件明文放在那里；
- Blob 的文件名是内容摘要，看不出资源名，但**内容本身完全可读**；
- `policy.secret: true` **不加密任何东西**，它只影响本机文件权限、风险评级和输出脱敏。

端到端加密的 Vault（每个工作区随机数据密钥、每设备 HPKE envelope、Argon2id 恢复密钥）在
**M2**。在此之前：**不要把真实 API Token、私钥或任何凭据放进 EnvSync 管理的普通资源。**

### 3.3 没有反回滚保护

`WorkspaceRef.revision` 在单次 CAS 中被校验为严格递增（`check_successor`），但 EnvSync
**不在本地保存已见过的最高 revision**。因此后端可以把 Ref 换回一个更旧的版本，本机下次
`plan` 会老老实实地朝那个旧快照收敛，并且**不会报告任何异常**。

基于本地检查点的反回滚检测在 **M2**（快照检查点 + 设备成员链）。

### 3.4 advisory 锁在网络文件系统上不可靠

`LocalBackend` 的 per-workspace 锁用 `O_CREAT|O_EXCL` 的原子性实现：创建
`locks/<workspace-uuid>.lock` 成功即持锁；竞争时有界重试（1000 次 × 5 ms，约 5 秒）；
超过 30 秒未更新的锁文件被视为陈旧（持有者崩溃或被强杀）并回收。

**这套机制依赖 `O_EXCL` 的原子性，而该语义在部分网络文件系统上不成立**（典型如某些 NFS
配置、部分云盘的同步目录）。在这类介质上：

- 两台设备可能**同时**认为自己持有锁；
- CAS 因此不再是强 CAS，「并发发布至多一方成功」的保证失效；
- 更糟的是，失败方可能得不到正确的 observed revision。

`BackendDescriptor.supports_strong_cas` 是为这个问题准备的协商位，但 `LocalBackend` 无法
探测自己被放在了什么文件系统上，因此**它总是自述为强 CAS**。

**运维建议：多设备并发写入时，把本地后端放在真正的本地文件系统上。** 需要跨网络共享时，
等 M1 的 Git 后端——它的 CAS 由 Git 的 ref 更新语义提供。

另外，30 秒的陈旧锁回收窗口意味着：一个**运行超过 30 秒但仍在正常工作**的发布过程，其锁
可能被另一个进程回收。在 M0 的本地后端上，发布是纯文件复制，实际耗时远低于此。

### 3.5 逐段 symlink 检查存在理论 TOCTOU 窗口

`AuthorizedRoot::resolve` 对每一段先 `symlink_metadata`（判断类型）再 `open_dir`（进入）。
cap-std 3.4 的 `Dir` **没有**暴露 `open_dir_nofollow`，也没有 `OpenOptions` 级别的 `nofollow`
开关，因此这是当前可行的等价实现。「先 stat 再 open」在原理上存在一个时间窗口：攻击者可能
在两次调用之间把某一段替换成符号链接。

**为什么这个窗口是可接受的**——它被两条独立的约束夹住：

1. **cap-std 保证相对操作不会逃出根目录句柄。** 所有解析都是相对能力句柄的，不经过任何
   绝对路径。因此即便竞态成功，**最坏情况仍被限制在授权根内部**——攻击者能改变的是「写到
   授权根内的哪个文件」，而不是「写到授权根外」。
2. **写入前还会再比对一次内容摘要。** rename 之前 `SafeWriter` 会重读目标并与
   `expected_before` 比较，被掉包的目标会以 `platform.stale_observation` 失败而**不是被
   覆盖**。要利用这个窗口，攻击者必须同时赢得竞态**并**让替换后的目标恰好拥有计划所绑定的
   那个摘要。

同时注意 §3.6：能在你的授权根内制造这种竞态的进程，本来就以你的身份运行，M0 不把它当作
威胁模型内的攻击者。

### 3.6 不防御本机同用户下的恶意进程

**M0 的信任边界是「本机已解锁的用户账户」。** 以你的身份运行的任何进程都可以：

- 修改 `envsync.yaml`，把授权根扩大到任意目录；
- 直接改写 `journal.db` 或删除 `backups/`，破坏恢复能力；
- 在 EnvSync 运行期间改动目标文件（这会被摘要检查挡下，表现为 `stale_observation` 失败，
  但足以造成拒绝服务）；
- 直接读写 EnvSync 管理的任何文件——根本不需要经过 EnvSync。

EnvSync 防御的是**自身的错误行为**（写错地方、覆盖不该覆盖的东西、丢失原内容），不是**同
权限的恶意进程**。后者需要操作系统级的隔离（沙箱、单独用户、MAC 策略），不在本工具的能力
范围内。

推论：`policy.secret` 的 `0o600` 权限保护的是**其他用户**，不是同用户下的其他进程。

### 3.7 Windows 未使用 `ReplaceFileW`

设计文档 §5 写「Windows 使用 `ReplaceFile` 或可恢复的 journaled replace」。M0 选择后者。

原因：`ReplaceFileW` 需要 `unsafe` FFI，而全部 crate 都是 `#![forbid(unsafe_code)]`，交接
指南也禁止引入 `unsafe`。

替代实现与等价性论证：

| `ReplaceFileW` 提供 | M0 的等价来源 |
|---|---|
| 原子替换 | `std::fs::rename` / `cap_std::fs::Dir::rename` 在 Windows 上内部走 `MoveFileEx` + `MOVEFILE_REPLACE_EXISTING`，已经是替换语义 |
| 保留原文件属性 / 备份副本 | `SafeWriter` 在替换前用 copy 语义写下确定性路径的备份，并在收据中记录 `original_digest`，可精确复原原字节 |
| journaled replace 的崩溃可恢复性 | SQLite journal 的 `OperationState` 状态机（`synchronous=FULL`，每次提交都 fsync）+ 收据；崩溃后可判断处于哪个阶段并重放或回滚 |

**已知的平台差异（诚实列出）：**

- **Windows 没有「fsync 一个目录句柄」的等价操作**，`sync_parent_dir` 在非 unix 平台上是
  空操作。目录项本身的耐久性由 journal 的恢复流程补齐，而不是由文件系统屏障保证。
- **`policy.unix_mode` 与秘密资源的 `0o600` 默认权限在 Windows 上不生效**：设置权限位的代码
  是 `#[cfg(unix)]`，`PermissionSummary.unix_mode` 在 Windows 上恒为 `None`。M0 **不设置
  Windows ACL**。这意味着 §4 的「秘密资源默认 0o600」只是一条 **unix 平台的保证**。

### 3.8 其他不提供的东西

| 不提供 | 何时提供 |
|---|---|
| Git / Gist 后端，网络传输安全 | M1 / M4 |
| Profile 投影、结构化合并、冲突对象的实际使用 | M1 |
| 设备成员关系、密钥轮换、秘密审计 | M2 |
| 包管理器期望状态、Agent Bundle quarantine、策略引擎 | M3 |
| 插件沙箱与版本化 RPC | M4 |
| 备份目录的自动清理与保留策略 | 未排期；M0 的 `backups/` 只增不减 |
| 对 `envsync.yaml` 自身的完整性保护 | 无计划——它是信任根，见 §1.1 |

---

## 4. 秘密处理约定

### 4.1 `ResourcePolicy::secret` 的含义

`policy.secret: true` 是一个**声明**，它触发四件事：

| 效果 | 实现位置 | 平台 |
|---|---|---|
| 文件以 `0o600`（仅属主可读写）创建 | `SafeWriter::effective_mode` → `SECRET_DEFAULT_MODE` | **仅 unix** |
| 权限从**创建的那一刻**就受限，不是先落盘再收紧 | `create_temp_file` 用 `OpenOptions::mode()` 传入，且写入后再 `set_permissions` 一次以抵消 umask | **仅 unix** |
| 该资源的**任何**写入动作恒为 `risk: high` | `planner::write_risk` | 全平台 |
| 计划与输出里只出现 `sensitive: true` 与内容摘要，**内容本身从不出现** | `PlanActionData.sensitive`、`Blob` 的 `Debug`、统一脱敏器 | 全平台 |

权限优先级：**显式 `policy.unix_mode` > 秘密资源默认 `0o600` > 沿用原文件权限 > 平台默认
（由 umask 决定）**。也就是说，显式写了 `unix_mode` 就以它为准——如果你给一个 `secret: true`
的资源写了 `unix_mode: "0644"`，得到的就是 `0644`。这是有意的（显式优先），但请确认那确实
是你想要的。

锁定测试：`secret_resource_defaults_to_owner_only_mode`、`secret_resource_writes_are_always_high_risk`。

### 4.2 禁止退化到暴露明文的写入路径

设计约束是：**秘密文件不得退化为可暴露明文的非原子流程。**

M0 的实现方式是**结构性的**：`SafeWriter` 只有一条写入路径——同目录 `O_EXCL` 临时文件 →
（unix 上）创建即带受限权限 → fsync → 备份 → 原子 rename → fsync 父目录。**不存在**
「先写一个宽权限文件再 chmod」「先截断目标再写入」「跨目录 copy+delete」这些退化分支，
因此也就无从退化。

`WriteRequest.secret` 由 `Action.secret` 传入，后者直接来自 `policy.secret`，一路不丢失。

需要清楚的边界：**备份文件**继承原文件的权限位（unix 上）。因此一个 `0o600` 的秘密资源，
其备份也是 `0o600`；但备份位于 `<state_dir>/backups/` 下，**该目录本身的权限由创建它的
umask 决定，M0 不额外收紧**。如果 `state_dir` 位于一个宽权限目录下，请自行 `chmod` 它。

### 4.3 M2 之前的硬性建议

> **在 M2 的 Vault 交付之前，不要把真实凭据放进 EnvSync 管理的普通资源。**

原因已在 §3.2 说明：后端持有明文。`secret: true` 保护的是**本机文件权限**和**输出不泄露**，
它**不保护后端里的字节**。

如果你现在就必须同步一个含凭据的文件，可选做法（按推荐度排序）：

1. **不要同步它。** 用系统 Keychain / Credential Manager / Secret Service 管理，等 M2。
2. 同步一个**不含凭据的模板**（例如 `.zshrc` 里用 `source ~/.secrets.zsh`），把
   `~/.secrets.zsh` 排除在 EnvSync 之外，各设备手工维护。
3. 若确实要同步，把后端放在**只有你能读**的本地介质上（加密卷、加密的可移动介质），并接受
   §3.1 / §3.2 / §3.3 的全部后果。

另外：**`device.seed_hex` 是本机私有材料，绝不上传后端，也绝不跨机器复制。** 换机器请重新
生成。它在 M2 会被真正的密钥材料取代（ADR-0002）。

---

## 5. 报告安全问题

如果你发现了一个安全问题——特别是能让 EnvSync **写到授权根之外**、**在没有备份的情况下
覆盖用户文件**、**把秘密内容写进输出或日志**，或**绕过计划直接写入**的路径——请不要提交
公开 issue。

请通过项目仓库
（[`https://github.com/envsync/envsync`](https://github.com/envsync/envsync)）的私密安全
报告渠道联系维护者，并在报告中包含：

- 受影响的版本或提交号；
- 复现步骤，最好是一个失败的测试用例；
- 你认为被违反的是本文中的哪一条保证；
- **不要**附带真实凭据、真实用户路径或本机配置——用 `/home/YOUR_USER` 这样的占位符。

请注意 §3 中已经列出的项目**不是**安全漏洞，而是 M0 已知且明示的边界。如果你认为某条边界
的**说明本身**不准确或有误导性，同样欢迎报告——文档与实现不一致，在本项目里被视为安全
问题的一种。
