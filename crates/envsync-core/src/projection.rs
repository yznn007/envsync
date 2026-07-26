//! Workspace 到 DeviceView 的**纯函数**投影。
//!
//! Snapshot 是唯一完整的期望状态；它描述「整个工作区应该是什么样」，而不是「这台
//! 设备应该写什么」。投影负责把前者收窄成后者：
//!
//! ```text
//! StateRoot（全量）+ DeviceProfile（我是谁）+ ProjectionPolicy（我被允许做什么）
//!   → DeviceView（本机目标状态 + 可解释的诊断）
//! ```
//!
//! ## 四条不可动摇的规则
//!
//! 1. **优先级固定**：全局资源 < selector 命中 < device-id 覆盖 < 安全 policy。
//!    policy 位于最高层且**不可被覆盖**：无论选择器或设备覆盖怎么写，被
//!    [`ProjectionPolicy::denied`] 拒绝的资源都不会出现在 [`DeviceView`] 里。
//! 2. **能力缺失不是删除意图**。设备缺少选择器要求的能力时只产生
//!    [`ProjectionNoteKind::UnsupportedCapability`] 诊断，资源被**排除**在视图之外，
//!    绝不生成 `EnsureAbsent`（tombstone）——否则「今天没装 pwsh」会变成「把别人的
//!    PowerShell 配置删掉」。
//! 3. **只能收窄或转换，不能新增**。投影结果里的 ResourceId 一定是输入
//!    [`StateRoot`] 里已有的；投影没有任何凭空创造资源的路径。
//! 4. **确定性**。函数不读时钟、不读磁盘、不依赖迭代顺序：[`StateRoot`] 内部是
//!    `BTreeMap`，诊断按资源标识升序产生，因此相同输入必然得到相同的
//!    [`DeviceView::id`] 与相同的诊断序列。
//!
//! ## 选择器与覆盖来自配置层
//!
//! [`envsync_domain::ResourceEntry`] 里没有 selector 字段：Snapshot 是共享对象，把
//! 「哪台设备适用」写进去会让每次 Profile 调整都改变 Snapshot 标识。因此选择器和
//! device-id 覆盖住在配置层（[`crate::config::ResourceConfig`]），投影时以
//! [`ProjectionRules`] 的形式传入。

use std::collections::{BTreeMap, BTreeSet};

use envsync_domain::{
    DesiredDisposition, DeviceId, DeviceProfile, Predicate, ProfileError, ProjectionNote,
    ProjectionNoteKind, ResourceEntry, ResourceId, Selector, StateRoot, StateRootId,
};

use crate::config::WorkspaceConfig;

/// 安全策略：投影链条上**最高**的一层。
///
/// 它描述的是「本机被允许做什么」，而不是「用户希望做什么」，因此既不能被选择器
/// 放宽，也不能被 device-id 覆盖绕开。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectionPolicy {
    /// 被安全策略硬性拒绝的资源（任何 selector 都无法覆盖）。
    pub denied: BTreeSet<ResourceId>,
    /// 本设备**实际**可用的能力。
    ///
    /// 与 [`DeviceProfile::capabilities`] 的区别是信任来源：Profile 是配置里的
    /// 自述（可能过时或夸大），这里是策略层认定的事实。求值时取二者的**交集**，
    /// 于是「配置声称有 pwsh 但策略不认」只会让资源被排除，而不会被下发。
    pub capabilities: BTreeSet<String>,
}

impl ProjectionPolicy {
    /// 由配置构造：不拒绝任何资源，能力取配置声明的集合。
    ///
    /// M1 还没有独立的策略来源，因此这是 CLI 路径上的默认策略；测试与更高里程碑
    /// 可以直接构造更严格的实例。
    pub fn from_config(config: &WorkspaceConfig) -> Self {
        ProjectionPolicy {
            denied: BTreeSet::new(),
            capabilities: config.profile.capabilities.clone(),
        }
    }
}

/// 单个资源的投影规则（来自配置层）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceRule {
    /// 选择器；`None` 表示全局资源。
    pub selector: Option<Selector>,
    /// device-id 级别的覆盖。
    pub device_overrides: BTreeMap<DeviceId, EntryOverride>,
}

/// device-id 覆盖中**影响快照条目**的部分。
///
/// `target` 只决定本机把内容写到哪里，不影响期望状态，因此不在这里；它由
/// [`WorkspaceConfig::for_device`] 在计划阶段套用。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EntryOverride {
    /// 覆盖期望处置。
    pub disposition: Option<DesiredDisposition>,
}

impl EntryOverride {
    /// 是否什么都不覆盖。
    pub fn is_empty(&self) -> bool {
        self.disposition.is_none()
    }
}

/// 全部资源的投影规则。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectionRules {
    /// 资源标识 -> 规则；未出现的资源按「全局资源、无覆盖」处理。
    pub resources: BTreeMap<ResourceId, ResourceRule>,
}

impl ProjectionRules {
    /// 空规则集：所有资源都是全局资源。
    pub fn empty() -> Self {
        ProjectionRules::default()
    }

    /// 由工作区配置提取投影规则。
    ///
    /// 配置解析期已经校验过选择器与设备标识，这里只做形状转换；即便如此仍然重新
    /// 校验一次选择器，因为 [`WorkspaceConfig`] 的字段是公开的，可能被手工构造。
    pub fn from_config(config: &WorkspaceConfig) -> Result<Self, ProjectionError> {
        let mut resources = BTreeMap::new();
        for resource in &config.resources {
            if let Some(selector) = &resource.selector {
                selector
                    .validate()
                    .map_err(|source| ProjectionError::InvalidSelector {
                        resource: resource.id.clone(),
                        source,
                    })?;
            }
            let mut device_overrides = BTreeMap::new();
            for (key, overrides) in &resource.device_overrides {
                let device =
                    key.parse::<DeviceId>()
                        .map_err(|_| ProjectionError::InvalidDeviceKey {
                            resource: resource.id.clone(),
                            key: key.clone(),
                        })?;
                let entry_override = EntryOverride {
                    disposition: overrides.disposition,
                };
                // 只影响本机路径的覆盖（仅 target）在这里是空的，不必进入规则集。
                if !entry_override.is_empty() {
                    device_overrides.insert(device, entry_override);
                }
            }
            let rule = ResourceRule {
                selector: resource.selector.clone(),
                device_overrides,
            };
            if rule.selector.is_some() || !rule.device_overrides.is_empty() {
                resources.insert(resource.id.clone(), rule);
            }
        }
        Ok(ProjectionRules { resources })
    }
}

/// 投影结果：本设备的目标状态 + 可解释的诊断。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceView {
    /// 本设备应当收敛到的状态。
    pub state: StateRoot,
    /// 逐资源的投影结论，按资源标识升序。
    pub notes: Vec<ProjectionNote>,
}

impl DeviceView {
    /// 视图状态的内容标识。
    ///
    /// 只覆盖 `state`：诊断是给人看的解释，不参与内容寻址——否则改一句中文措辞就会
    /// 让「视图是否变化」的判断失效。
    pub fn id(&self) -> StateRootId {
        self.state.id()
    }

    /// 查询某个资源的诊断。
    pub fn note(&self, resource: &ResourceId) -> Option<&ProjectionNote> {
        self.notes.iter().find(|note| &note.resource == resource)
    }
}

/// 投影失败的原因。
///
/// 投影本身不做 I/O，因此这些错误都只描述结构问题，可以安全写进日志与 CLI 输出。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProjectionError {
    /// 选择器不合法（深度、节点数或取值不规范）。
    #[error("资源 `{resource}` 的选择器非法：{source}")]
    InvalidSelector {
        /// 出问题的资源。
        resource: ResourceId,
        /// 领域层给出的原因。
        #[source]
        source: ProfileError,
    },
    /// 设备 Profile 不合法。
    #[error("设备 Profile 非法：{0}")]
    InvalidProfile(#[source] ProfileError),
    /// 覆盖键不是合法的设备标识。
    #[error("资源 `{resource}` 的设备覆盖键 `{key}` 非法")]
    InvalidDeviceKey {
        /// 出问题的资源。
        resource: ResourceId,
        /// 非法的键。
        key: String,
    },
    /// 覆盖之后的条目不再自洽（例如把没有内容的资源改成 `managed`）。
    #[error("资源 `{resource}` 的设备覆盖无法满足：{reason}")]
    UnsatisfiableOverride {
        /// 出问题的资源。
        resource: ResourceId,
        /// 原因说明。
        reason: &'static str,
    },
    /// 投影结果不是合法的 State Root——出现即说明实现有 bug。
    #[error("投影结果不是合法的 State Root：{0}")]
    InvalidState(String),
}

impl ProjectionError {
    /// 稳定的机器可读错误码。
    pub fn code(&self) -> &'static str {
        match self {
            ProjectionError::InvalidSelector { .. } => "projection.invalid_selector",
            ProjectionError::InvalidProfile(_) => "projection.invalid_profile",
            ProjectionError::InvalidDeviceKey { .. } => "projection.invalid_device_key",
            ProjectionError::UnsatisfiableOverride { .. } => "projection.unsatisfiable_override",
            ProjectionError::InvalidState(_) => "projection.invalid_state",
        }
    }
}

/// 按设备 Profile 与安全策略投影工作区状态。
///
/// 这是没有选择器与设备覆盖的简化入口（等价于所有资源都是全局资源）；需要配置层
/// 规则时用 [`project_workspace_with_rules`]。
pub fn project_workspace(
    state: &StateRoot,
    profile: &DeviceProfile,
    policy: &ProjectionPolicy,
) -> Result<DeviceView, ProjectionError> {
    project_workspace_with_rules(state, profile, policy, &ProjectionRules::empty())
}

/// 带配置层规则的完整投影。
///
/// 逐资源的判定顺序即优先级顺序：
///
/// 1. **全局资源**：没有规则时默认下发（[`ProjectionNoteKind::SelectedByGlobal`]）；
/// 2. **selector**：命中则下发，未命中则排除；未命中且原因是缺少能力时，诊断是
///    [`ProjectionNoteKind::UnsupportedCapability`] 而不是 `ExcludedBySelector`；
/// 3. **device-id 覆盖**：命中本设备时**无条件**纳入并套用覆盖，可以推翻第 2 步；
/// 4. **安全 policy**：`denied` 里的资源一律排除，推翻前三步。
pub fn project_workspace_with_rules(
    state: &StateRoot,
    profile: &DeviceProfile,
    policy: &ProjectionPolicy,
    rules: &ProjectionRules,
) -> Result<DeviceView, ProjectionError> {
    profile
        .validate()
        .map_err(ProjectionError::InvalidProfile)?;

    // 选择器一律对「有效 Profile」求值：能力取 Profile 声明与策略认定的交集，
    // 于是策略永远不会被配置里的自述放宽。
    let effective = effective_profile(profile, policy);

    let mut entries: Vec<ResourceEntry> = Vec::new();
    let mut notes: Vec<ProjectionNote> = Vec::new();

    // `StateRoot::entries` 是 BTreeMap，因此遍历顺序即资源标识升序：输入乱序不会
    // 改变输出顺序，也不会改变 DeviceView 标识。
    for (resource, entry) in &state.entries {
        // 第 4 层：安全 policy 最高，先于一切判定短路。
        if policy.denied.contains(resource) {
            notes.push(ProjectionNote::new(
                resource.clone(),
                ProjectionNoteKind::ExcludedByPolicy,
                "被安全策略拒绝；选择器与设备覆盖都不能放宽这一层。",
            ));
            continue;
        }

        let rule = rules.resources.get(resource);
        let device_override = rule.and_then(|rule| {
            effective
                .device
                .and_then(|id| rule.device_overrides.get(&id))
        });

        let (selected, note) = match (
            device_override,
            rule.and_then(|rule| rule.selector.as_ref()),
        ) {
            // 第 3 层：device-id 覆盖，优先级高于选择器。
            (Some(_), _) => (
                true,
                ProjectionNote::new(
                    resource.clone(),
                    ProjectionNoteKind::OverriddenByDevice,
                    "命中本设备的 device-id 覆盖。",
                ),
            ),
            // 第 2 层：选择器。
            (None, Some(selector)) => {
                if selector.matches(&effective) {
                    (
                        true,
                        ProjectionNote::new(
                            resource.clone(),
                            ProjectionNoteKind::SelectedBySelector,
                            "选择器命中本设备。",
                        ),
                    )
                } else {
                    let missing = missing_capabilities(selector, &effective);
                    if missing.is_empty() {
                        (
                            false,
                            ProjectionNote::new(
                                resource.clone(),
                                ProjectionNoteKind::ExcludedBySelector,
                                "选择器未命中本设备。",
                            ),
                        )
                    } else {
                        (
                            false,
                            ProjectionNote::new(
                                resource.clone(),
                                ProjectionNoteKind::UnsupportedCapability,
                                format!(
                                    "本设备缺少所需能力：{}；该资源本次不下发，但**不会**被删除。",
                                    missing.join("、")
                                ),
                            ),
                        )
                    }
                }
            }
            // 第 1 层：全局资源。
            (None, None) => (
                true,
                ProjectionNote::new(
                    resource.clone(),
                    ProjectionNoteKind::SelectedByGlobal,
                    "全局资源，对所有设备下发。",
                ),
            ),
        };

        notes.push(note);
        if !selected {
            continue;
        }
        entries.push(apply_override(entry, device_override)?);
    }

    let state = StateRoot::from_entries(entries)
        .map_err(|error| ProjectionError::InvalidState(error.to_string()))?;
    Ok(DeviceView { state, notes })
}

/// 构造「有效 Profile」：能力取 Profile 与策略的交集，其余原样保留。
fn effective_profile(profile: &DeviceProfile, policy: &ProjectionPolicy) -> DeviceProfile {
    let mut effective = profile.clone();
    effective.capabilities = profile
        .capabilities
        .intersection(&policy.capabilities)
        .cloned()
        .collect();
    effective
}

/// 套用 device-id 覆盖，并保持条目自洽。
///
/// `disposition` 与 `blob` 的组合由 [`ResourceEntry::validate`] 约束：非 `managed`
/// 的条目不能带内容，`managed` 必须带内容。因此覆盖成非 `managed` 时要清掉 blob；
/// 想覆盖成 `managed` 却没有内容可用时**报错**——静默丢弃覆盖会让用户以为它生效了。
fn apply_override(
    entry: &ResourceEntry,
    device_override: Option<&EntryOverride>,
) -> Result<ResourceEntry, ProjectionError> {
    let Some(overrides) = device_override else {
        return Ok(entry.clone());
    };
    let mut projected = entry.clone();
    if let Some(disposition) = overrides.disposition {
        projected.disposition = disposition;
        match disposition {
            DesiredDisposition::Managed => {
                if projected.blob.is_none() {
                    return Err(ProjectionError::UnsatisfiableOverride {
                        resource: entry.resource.clone(),
                        reason: "快照里没有该资源的内容，无法覆盖为 managed",
                    });
                }
            }
            // 只有显式的 ensure_absent 才是删除意图，而它必须由**用户**写下来；
            // 这里只是忠实执行，不做任何推断。
            DesiredDisposition::EnsureAbsent | DesiredDisposition::Unmanaged => {
                projected.blob = None;
            }
        }
    }
    projected
        .validate()
        .map_err(|error| ProjectionError::InvalidState(error.to_string()))?;
    Ok(projected)
}

/// 收集选择器中**正向**要求、但设备并不具备的能力。
///
/// 只看正向位置（不在 `Not` 之下）的 [`Predicate::Capability`]：`not(capability x)`
/// 表达的是「没有 x 才适用」，缺少 x 恰恰意味着命中，不该被报成能力缺失。
///
/// 实现是迭代的：选择器来自不可信配置，递归遍历本身就是栈溢出入口。
fn missing_capabilities(selector: &Selector, profile: &DeviceProfile) -> Vec<String> {
    let mut missing: BTreeSet<String> = BTreeSet::new();
    let mut stack = vec![(selector, false)];
    while let Some((node, negated)) = stack.pop() {
        match node {
            Selector::All(items) | Selector::Any(items) => {
                stack.extend(items.iter().map(|item| (item, negated)));
            }
            Selector::Not(inner) => stack.push((&**inner, !negated)),
            Selector::Is(Predicate::Capability(capability)) => {
                if !negated && !profile.has_capability(capability) {
                    missing.insert(capability.clone());
                }
            }
            Selector::Is(_) => {}
        }
    }
    missing.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use envsync_domain::{Arch, BlobId, FileMode, Os, ResourcePolicy};

    fn entry(name: &str) -> ResourceEntry {
        ResourceEntry {
            resource: ResourceId::parse(name).expect("资源标识合法"),
            disposition: DesiredDisposition::Managed,
            blob: Some(BlobId::of(name.as_bytes())),
            mode: FileMode::FullFile,
            policy: ResourcePolicy::default(),
        }
    }

    #[test]
    fn empty_policy_and_rules_keep_every_resource() {
        let state = StateRoot::from_entries([entry("a/one"), entry("b/two")]).expect("状态合法");
        let profile = DeviceProfile::new(Os::Linux, Arch::X86_64);
        let view = project_workspace(&state, &profile, &ProjectionPolicy::default())
            .expect("投影应当成功");
        assert_eq!(view.state.len(), 2);
        assert!(view
            .notes
            .iter()
            .all(|note| note.kind == ProjectionNoteKind::SelectedByGlobal));
    }

    #[test]
    fn negated_capability_is_not_reported_as_missing() {
        let selector = Selector::negate(Selector::is(Predicate::Capability("pwsh".into())));
        let profile = DeviceProfile::new(Os::Linux, Arch::X86_64);
        assert!(missing_capabilities(&selector, &profile).is_empty());
    }
}
