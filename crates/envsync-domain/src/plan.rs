//! 不可变、绑定观察结果的同步计划。
//!
//! 计划是 EnvSync 的核心安全装置：**任何**对用户文件的写入都必须先出现在计划里。
//! 计划一旦生成即不可变，并且同时绑定：
//!
//! * 目标快照标识；
//! * 生成计划时后端 Ref 的 revision；
//! * 本机所有相关资源的观察结果（含内容摘要）。
//!
//! 应用之前会重新观察，只要任何一项发生变化，计划标识就会改变，从而被判定为
//! stale 并拒绝执行。

use serde::{Deserialize, Serialize};

use crate::cbor::{self, CborCodec, CborError, Value};
use crate::id::{BlobId, DeviceId, Digest32, PlanId, ResourceId, SnapshotId, WorkspaceId};
use crate::resource::Observation;
use crate::snapshot::WorkspaceRef;
use crate::{cbor_struct, cbor_unit_enum};

/// 计划的当前格式版本。
pub const PLAN_FORMAT_VERSION: u32 = 1;

/// 动作风险等级。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    /// 创建新文件等无损操作。
    Low,
    /// 覆盖已有文件内容。
    Medium,
    /// 删除文件、修改秘密资源等不可逆或高影响操作。
    High,
}

cbor_unit_enum!(Risk {
    Risk::Low => "low",
    Risk::Medium => "medium",
    Risk::High => "high",
});

/// 备份策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupPolicy {
    /// 必须先备份原文件才能继续；备份失败即动作失败。
    Required,
    /// 目标原本不存在，无需备份。
    NotApplicable,
}

cbor_unit_enum!(BackupPolicy {
    BackupPolicy::Required => "required",
    BackupPolicy::NotApplicable => "not_applicable",
});

/// 回滚能力。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackCapability {
    /// 可精确恢复到原字节。
    Exact,
    /// 只能做补偿性回滚，结果可能与原状态不完全一致。
    Compensating,
    /// 不可回滚。
    None,
}

cbor_unit_enum!(RollbackCapability {
    RollbackCapability::Exact => "exact",
    RollbackCapability::Compensating => "compensating",
    RollbackCapability::None => "none",
});

/// 动作种类。
///
/// 排序权重固定：删除 < 写入 < 块更新，保证同一资源上的多个动作顺序确定。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// 显式删除文件。
    DeleteFile,
    /// 创建原本不存在的文件。
    CreateFile,
    /// 整体替换已存在的文件。
    ReplaceFile,
    /// 更新文件中的受管区块，保留块外内容。
    UpdateManagedBlock,
}

cbor_unit_enum!(ActionKind {
    ActionKind::DeleteFile => "delete_file",
    ActionKind::CreateFile => "create_file",
    ActionKind::ReplaceFile => "replace_file",
    ActionKind::UpdateManagedBlock => "update_managed_block",
});

impl ActionKind {
    /// 排序权重。
    pub const fn order_rank(self) -> u8 {
        match self {
            ActionKind::DeleteFile => 0,
            ActionKind::CreateFile => 1,
            ActionKind::ReplaceFile => 2,
            ActionKind::UpdateManagedBlock => 3,
        }
    }

    /// 是否为删除动作。
    pub const fn is_delete(self) -> bool {
        matches!(self, ActionKind::DeleteFile)
    }
}

/// 动作的写入目标：授权根别名 + 平台无关的相对分段。
///
/// 计划里**绝不**保存绝对路径：绝对路径既是本机信息泄露，也让计划无法在设备之间
/// 被审阅比较。真实路径在平台层由授权根解析。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ActionTarget {
    /// 授权根别名，例如 `home`。
    pub root: String,
    /// 相对该根的路径分段。
    pub segments: Vec<String>,
}

cbor_struct!(ActionTarget {
    root: String,
    segments: Vec<String>,
});

impl ActionTarget {
    /// 以 `/` 连接的展示形式（仅用于人类可读输出）。
    pub fn display_path(&self) -> String {
        format!("{}:{}", self.root, self.segments.join("/"))
    }
}

/// 应用后的验证规则。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum VerifyRule {
    /// 目标文件内容摘要必须等于给定值。
    ExpectDigest(Digest32),
    /// 目标必须不存在。
    ExpectAbsent,
}

impl CborCodec for VerifyRule {
    fn to_value(&self) -> Value {
        match self {
            VerifyRule::ExpectDigest(digest) => {
                Value::Array(vec![Value::Text("expect_digest".into()), digest.to_value()])
            }
            VerifyRule::ExpectAbsent => Value::Array(vec![Value::Text("expect_absent".into())]),
        }
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        match (
            items.first().ok_or(CborError::ArityMismatch)?.as_text()?,
            items.len(),
        ) {
            ("expect_digest", 2) => Ok(VerifyRule::ExpectDigest(Digest32::from_value(&items[1])?)),
            ("expect_absent", 1) => Ok(VerifyRule::ExpectAbsent),
            ("expect_digest" | "expect_absent", _) => Err(CborError::ArityMismatch),
            (other, _) => Err(CborError::UnknownVariant(other.to_owned())),
        }
    }
}

/// 计划中的单个动作。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    /// 关联资源。
    pub resource: ResourceId,
    /// 动作种类。
    pub kind: ActionKind,
    /// 写入目标。
    pub target: ActionTarget,
    /// 应用前目标应有的内容摘要；`None` 表示目标应当不存在。
    ///
    /// 这是防止“计划生成后文件被外部修改”的关键绑定。
    pub expected_before: Option<Digest32>,
    /// 应用后目标应有的内容摘要；`None` 表示删除。
    pub expected_after: Option<Digest32>,
    /// 待写入的完整文件内容 Blob；删除动作为 `None`。
    ///
    /// Managed Block 也在计划阶段完成渲染，因此应用阶段只做“写入这些字节”，
    /// 不再包含任何依赖当前文件内容的逻辑。
    pub content: Option<BlobId>,
    /// 风险等级。
    pub risk: Risk,
    /// 备份策略。
    pub backup: BackupPolicy,
    /// 回滚能力。
    pub rollback: RollbackCapability,
    /// 期望的 POSIX 权限位。
    pub unix_mode: Option<u32>,
    /// 是否涉及秘密资源。
    pub secret: bool,
    /// 验证规则。
    pub verify: VerifyRule,
}

cbor_struct!(Action {
    resource: ResourceId,
    kind: ActionKind,
    target: ActionTarget,
    expected_before: Option<Digest32>,
    expected_after: Option<Digest32>,
    content: Option<BlobId>,
    risk: Risk,
    backup: BackupPolicy,
    rollback: RollbackCapability,
    unix_mode: Option<u32>,
    secret: bool,
    verify: VerifyRule,
});

impl Action {
    /// 排序键：先按资源标识，再按动作种类权重。
    pub fn sort_key(&self) -> (String, u8) {
        (self.resource.as_str().to_owned(), self.kind.order_rank())
    }
}

/// 诊断严重级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// 仅供参考。
    Info,
    /// 需要注意但不阻塞。
    Warning,
    /// 阻塞：存在该级别诊断时计划不可应用。
    Blocking,
}

cbor_unit_enum!(Severity {
    Severity::Info => "info",
    Severity::Warning => "warning",
    Severity::Blocking => "blocking",
});

/// 计划诊断。
///
/// `code` 是机器可读的稳定错误码，`message` 是人类可读说明；两者都**不得**包含
/// 秘密内容或绝对路径。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// 严重级别。
    pub severity: Severity,
    /// 稳定错误码，例如 `resource.unreadable`。
    pub code: String,
    /// 关联资源；与具体资源无关时为 `None`。
    pub resource: Option<ResourceId>,
    /// 人类可读说明。
    pub message: String,
}

cbor_struct!(Diagnostic {
    severity: Severity,
    code: String,
    resource: Option<ResourceId>,
    message: String,
});

impl Diagnostic {
    /// 构造阻塞级诊断。
    pub fn blocking(code: &str, resource: Option<ResourceId>, message: impl Into<String>) -> Self {
        Diagnostic {
            severity: Severity::Blocking,
            code: code.to_owned(),
            resource,
            message: message.into(),
        }
    }

    /// 构造警告级诊断。
    pub fn warning(code: &str, resource: Option<ResourceId>, message: impl Into<String>) -> Self {
        Diagnostic {
            severity: Severity::Warning,
            code: code.to_owned(),
            resource,
            message: message.into(),
        }
    }

    /// 构造信息级诊断。
    pub fn info(code: &str, resource: Option<ResourceId>, message: impl Into<String>) -> Self {
        Diagnostic {
            severity: Severity::Info,
            code: code.to_owned(),
            resource,
            message: message.into(),
        }
    }
}

/// 不可变同步计划。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    /// 格式版本。
    pub format_version: u32,
    /// 工作区标识。
    pub workspace: WorkspaceId,
    /// 生成计划的设备。
    pub device: DeviceId,
    /// 目标快照。
    pub target_snapshot: SnapshotId,
    /// 生成计划时后端 Ref 的 revision。
    pub base_revision: u64,
    /// 应用时将通过 CAS 写入的下一个引用。
    pub next_ref: WorkspaceRef,
    /// 参与计划的全部观察结果，按资源标识升序。
    pub observations: Vec<Observation>,
    /// 排序后的动作列表。
    pub actions: Vec<Action>,
    /// 诊断。
    pub diagnostics: Vec<Diagnostic>,
    /// 计划创建时刻（Unix 毫秒）。**不参与**计划标识计算。
    pub created_at_unix_ms: u64,
}

impl Plan {
    /// 由未排序的动作与观察构造计划，内部完成确定性排序。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace: WorkspaceId,
        device: DeviceId,
        target_snapshot: SnapshotId,
        base_revision: u64,
        next_ref: WorkspaceRef,
        mut observations: Vec<Observation>,
        mut actions: Vec<Action>,
        mut diagnostics: Vec<Diagnostic>,
        created_at_unix_ms: u64,
    ) -> Self {
        observations.sort_by(|a, b| a.resource.cmp(&b.resource));
        actions.sort_by_key(Action::sort_key);
        diagnostics.sort_by(|a, b| {
            (a.severity, &a.code, &a.resource).cmp(&(b.severity, &b.code, &b.resource))
        });
        Plan {
            format_version: PLAN_FORMAT_VERSION,
            workspace,
            device,
            target_snapshot,
            base_revision,
            next_ref,
            observations,
            actions,
            diagnostics,
            created_at_unix_ms,
        }
    }

    /// 编码除 `created_at_unix_ms` 之外的全部字段。
    ///
    /// `Plan` 序列化为 `[binding, created_at]` 两元数组，这样「ID 覆盖什么」在编码
    /// 结构上一目了然，而不依赖注释约定。
    fn binding_value(&self) -> Value {
        self.encode_binding(&self.observations)
    }

    /// 计划标识的原像。
    ///
    /// 与 [`Plan::binding_value`] 的唯一区别是**观察时刻被归零**：
    /// `Observation::observed_at_unix_ms` 只是诊断信息，每次重新观察都会变。若让它
    /// 进入原像，「重新计划并比较标识」这一新鲜度检查将永远失败，命令面完全不可用
    /// （见 ADR-0003，对 `created_at_unix_ms` 是同样的道理）。
    ///
    /// 被绑定的是观察的**内容**（资源与状态，含内容摘要），而不是观察发生的时刻。
    fn id_preimage(&self) -> Value {
        let normalised: Vec<Observation> = self
            .observations
            .iter()
            .map(|observation| Observation {
                resource: observation.resource.clone(),
                state: observation.state.clone(),
                observed_at_unix_ms: 0,
            })
            .collect();
        self.encode_binding(&normalised)
    }

    fn encode_binding(&self, observations: &[Observation]) -> Value {
        Value::Array(vec![
            Value::Uint(self.format_version as u64),
            self.workspace.to_value(),
            self.device.to_value(),
            self.target_snapshot.to_value(),
            Value::Uint(self.base_revision),
            self.next_ref.to_value(),
            Value::Array(observations.iter().map(CborCodec::to_value).collect()),
            self.actions.to_value(),
            self.diagnostics.to_value(),
        ])
    }

    /// 计划标识。
    pub fn id(&self) -> PlanId {
        PlanId::of(&cbor::encode(&self.id_preimage()))
    }

    /// 是否存在阻塞诊断。
    pub fn is_blocked(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity == Severity::Blocking)
    }

    /// 阻塞诊断列表。
    pub fn blocking_diagnostics(&self) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Blocking)
    }

    /// 是否不需要任何本地写入。
    pub fn is_noop(&self) -> bool {
        self.actions.is_empty()
    }

    /// 计划中的最高风险等级。
    pub fn max_risk(&self) -> Option<Risk> {
        self.actions.iter().map(|action| action.risk).max()
    }

    /// 查找某个资源的观察结果。
    pub fn observation(&self, resource: &ResourceId) -> Option<&Observation> {
        self.observations
            .binary_search_by(|probe| probe.resource.cmp(resource))
            .ok()
            .map(|index| &self.observations[index])
    }
}

impl CborCodec for Plan {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            self.binding_value(),
            Value::Uint(self.created_at_unix_ms),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let outer = value.as_array()?;
        if outer.len() != 2 {
            return Err(CborError::ArityMismatch);
        }
        let items = outer[0].as_array()?;
        if items.len() != 9 {
            return Err(CborError::ArityMismatch);
        }
        let format_version = u32::from_value(&items[0])?;
        if format_version != PLAN_FORMAT_VERSION {
            return Err(CborError::UnsupportedFormatVersion {
                found: format_version,
                supported: PLAN_FORMAT_VERSION,
            });
        }
        Ok(Plan {
            format_version,
            workspace: WorkspaceId::from_value(&items[1])?,
            device: DeviceId::from_value(&items[2])?,
            target_snapshot: SnapshotId::from_value(&items[3])?,
            base_revision: u64::from_value(&items[4])?,
            next_ref: WorkspaceRef::from_value(&items[5])?,
            observations: Vec::<Observation>::from_value(&items[6])?,
            actions: Vec::<Action>::from_value(&items[7])?,
            diagnostics: Vec::<Diagnostic>::from_value(&items[8])?,
            created_at_unix_ms: u64::from_value(&outer[1])?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{ObservedState, PermissionSummary, PresentFile};
    use crate::snapshot::WorkspaceRef;

    fn target(name: &str) -> ActionTarget {
        ActionTarget {
            root: "home".into(),
            segments: vec![name.to_owned()],
        }
    }

    fn action(resource: &str, kind: ActionKind) -> Action {
        Action {
            resource: ResourceId::parse(resource).unwrap(),
            kind,
            target: target(resource),
            expected_before: None,
            expected_after: Some(Digest32::domain_hash("t", resource.as_bytes())),
            content: Some(BlobId::of(resource.as_bytes())),
            risk: Risk::Low,
            backup: BackupPolicy::NotApplicable,
            rollback: RollbackCapability::Exact,
            unix_mode: Some(0o644),
            secret: false,
            verify: VerifyRule::ExpectDigest(Digest32::domain_hash("t", resource.as_bytes())),
        }
    }

    fn observation(resource: &str) -> Observation {
        Observation::new(
            ResourceId::parse(resource).unwrap(),
            ObservedState::Absent,
            42,
        )
    }

    fn plan_with(actions: Vec<Action>, observations: Vec<Observation>) -> Plan {
        let workspace = WorkspaceId::from_uuid(uuid::Uuid::nil());
        Plan::new(
            workspace,
            DeviceId::derive(b"device"),
            SnapshotId::of(b"snap"),
            3,
            WorkspaceRef::initial(workspace).advance(SnapshotId::of(b"snap")),
            observations,
            actions,
            vec![],
            1_700_000_000_000,
        )
    }

    #[test]
    fn plan_id_is_independent_of_input_order() {
        let forward = plan_with(
            vec![
                action("a/one", ActionKind::CreateFile),
                action("b/two", ActionKind::CreateFile),
            ],
            vec![observation("a/one"), observation("b/two")],
        );
        let backward = plan_with(
            vec![
                action("b/two", ActionKind::CreateFile),
                action("a/one", ActionKind::CreateFile),
            ],
            vec![observation("b/two"), observation("a/one")],
        );
        assert_eq!(forward.id(), backward.id());
    }

    #[test]
    fn plan_id_is_independent_of_creation_time() {
        let mut early = plan_with(vec![action("a/one", ActionKind::CreateFile)], vec![]);
        let mut late = early.clone();
        early.created_at_unix_ms = 1;
        late.created_at_unix_ms = 999_999;
        assert_eq!(early.id(), late.id(), "创建时间不应影响计划标识");
    }

    #[test]
    fn plan_id_ignores_observation_timestamps() {
        // 回归测试：观察时刻曾经进入 Plan ID 原像，导致两次重新计划只要不在同一
        // 毫秒就得到不同标识，`sync` 的新鲜度检查 100% 判定为 stale，命令面不可用。
        let mut early = plan_with(
            vec![action("a/one", ActionKind::CreateFile)],
            vec![observation("a/one")],
        );
        let mut late = early.clone();
        early.observations[0].observed_at_unix_ms = 1;
        late.observations[0].observed_at_unix_ms = 9_999_999;
        assert_eq!(early.id(), late.id(), "观察时刻不应影响计划标识");

        // 但观察的**内容**变化仍然必须改变标识。
        let mut changed = early.clone();
        changed.observations[0].state = ObservedState::Present(PresentFile {
            content_digest: Digest32::domain_hash("t", b"drift"),
            size: 5,
            mtime_unix_ms: None,
            permissions: PermissionSummary {
                readonly: false,
                unix_mode: None,
            },
            managed_digest: None,
        });
        assert_ne!(early.id(), changed.id(), "观察内容变化必须改变计划标识");
    }

    #[test]
    fn plan_id_changes_with_every_bound_input() {
        let base = plan_with(
            vec![action("a/one", ActionKind::CreateFile)],
            vec![observation("a/one")],
        );

        let mut other_snapshot = base.clone();
        other_snapshot.target_snapshot = SnapshotId::of(b"different");
        assert_ne!(
            base.id(),
            other_snapshot.id(),
            "目标快照变化必须改变计划标识"
        );

        let mut other_revision = base.clone();
        other_revision.base_revision = 4;
        assert_ne!(
            base.id(),
            other_revision.id(),
            "revision 变化必须改变计划标识"
        );

        let mut other_observation = base.clone();
        other_observation.observations[0].state = ObservedState::Present(PresentFile {
            content_digest: Digest32::domain_hash("t", b"x"),
            size: 1,
            mtime_unix_ms: None,
            permissions: PermissionSummary {
                readonly: false,
                unix_mode: None,
            },
            managed_digest: None,
        });
        assert_ne!(
            base.id(),
            other_observation.id(),
            "观察变化必须改变计划标识"
        );

        let mut other_action = base.clone();
        other_action.actions[0].expected_after = Some(Digest32::domain_hash("t", b"changed"));
        assert_ne!(base.id(), other_action.id(), "动作变化必须改变计划标识");

        let mut other_device = base.clone();
        other_device.device = DeviceId::derive(b"another-device");
        assert_ne!(base.id(), other_device.id(), "设备变化必须改变计划标识");
    }

    #[test]
    fn actions_are_sorted_by_resource_then_kind() {
        let plan = plan_with(
            vec![
                action("b/two", ActionKind::UpdateManagedBlock),
                action("a/one", ActionKind::ReplaceFile),
                action("a/one", ActionKind::DeleteFile),
            ],
            vec![],
        );
        let order: Vec<(&str, ActionKind)> = plan
            .actions
            .iter()
            .map(|a| (a.resource.as_str(), a.kind))
            .collect();
        assert_eq!(
            order,
            vec![
                ("a/one", ActionKind::DeleteFile),
                ("a/one", ActionKind::ReplaceFile),
                ("b/two", ActionKind::UpdateManagedBlock),
            ]
        );
    }

    #[test]
    fn blocking_diagnostics_block_the_plan() {
        let mut plan = plan_with(vec![], vec![]);
        assert!(!plan.is_blocked());
        plan.diagnostics
            .push(Diagnostic::warning("x", None, "仅警告"));
        assert!(!plan.is_blocked());
        plan.diagnostics.push(Diagnostic::blocking(
            "resource.unreadable",
            None,
            "无法读取",
        ));
        assert!(plan.is_blocked());
        assert_eq!(plan.blocking_diagnostics().count(), 1);
    }

    #[test]
    fn plan_round_trips_through_canonical_cbor() {
        let plan = plan_with(
            vec![action("a/one", ActionKind::CreateFile)],
            vec![observation("a/one")],
        );
        let bytes = plan.to_canonical_vec();
        let decoded = Plan::from_canonical_slice(&bytes).expect("解码成功");
        assert_eq!(decoded, plan);
        assert_eq!(decoded.id(), plan.id());
    }

    #[test]
    fn observation_lookup_uses_sorted_order() {
        let plan = plan_with(vec![], vec![observation("z/last"), observation("a/first")]);
        assert!(plan
            .observation(&ResourceId::parse("a/first").unwrap())
            .is_some());
        assert!(plan
            .observation(&ResourceId::parse("z/last").unwrap())
            .is_some());
        assert!(plan
            .observation(&ResourceId::parse("m/middle").unwrap())
            .is_none());
    }

    #[test]
    fn max_risk_reflects_worst_action() {
        let mut high = action("a/one", ActionKind::DeleteFile);
        high.risk = Risk::High;
        let plan = plan_with(vec![action("b/two", ActionKind::CreateFile), high], vec![]);
        assert_eq!(plan.max_risk(), Some(Risk::High));
    }
}
