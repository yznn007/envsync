//! 完全内存的包管理器测试替身。
//!
//! CI 上没有 Homebrew、没有 Scoop、也没有 apt，但**契约必须被测到**：安装、升级、
//! 已满足、版本满足不了、显式卸载、部分失败、verify 漂移、三种回滚能力。
//! [`FakePackageManager`] 把这些场景变成可注入的内存状态，让 red-green 循环不依赖
//! 任何真实包管理器，也不会改动跑测试的机器。
//!
//! # 它是替身，不是模拟器
//!
//! 它**不**模拟依赖解析、不模拟下载、不模拟 tap 更新。它只忠实地实现
//! [`PackageAdapter`] 契约里那些「所有适配器都必须遵守」的规则，因此可以用来钉住契约
//! 本身；真实管理器的输出解析由各自的 fixture 测试覆盖。
//!
//! # 构造器对非法输入直接 panic
//!
//! 夹具写错（包身份不合法、包不属于本管理器）应当**立刻**失败，而不是变成一个含糊的
//! 测试结果。因此 `with_*` 系列在输入不合法时 panic，并给出明确信息。

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use envsync_domain::package::{
    InstalledPackage, PackageAction, PackageActionKind, PackageDisposition, PackageIdentity,
    PackageIntent, PackageObservation, PackageObservationSet, PackageState, VersionPolicy,
};
use envsync_domain::profile::Os;
use envsync_domain::RollbackCapability;

use super::{
    plan_from_intents, ApplyContext, ObserveContext, PackageAdapter, PackageAdapterError,
    PackageManagerDescriptor, PackageReceipt, VerifyResult,
};

/// 用户级 fake：可补偿回滚，不需要提权。
pub static FAKE_USER_DESCRIPTOR: PackageManagerDescriptor = PackageManagerDescriptor {
    id: "fake.pkg.user",
    manager: "fakeuser",
    display_name: "Fake User-Scope Package Manager",
    supported_os: &[Os::MacOs, Os::Linux, Os::Windows],
    required_capabilities: &[],
    system_scope: false,
    rollback: RollbackCapability::Compensating,
};

/// 精确回滚 fake：能把包恢复到原字节（例如内容寻址的包存储）。
pub static FAKE_EXACT_DESCRIPTOR: PackageManagerDescriptor = PackageManagerDescriptor {
    id: "fake.pkg.exact",
    manager: "fakeexact",
    display_name: "Fake Content-Addressed Package Manager",
    supported_os: &[Os::MacOs, Os::Linux, Os::Windows],
    required_capabilities: &[],
    system_scope: false,
    rollback: RollbackCapability::Exact,
};

/// 系统级 fake：需要提权，且**无法**回滚。
///
/// ID 刻意使用 `builtin.pkg.system.` 前缀，这样契约与计划测试能真正命中内建策略里的
/// 系统级包规则（`envsync_policy::BUILTIN_SYSTEM_PACKAGE_PREFIX`），而不是测一条
/// 走不到的分支。
pub static FAKE_SYSTEM_DESCRIPTOR: PackageManagerDescriptor = PackageManagerDescriptor {
    id: "builtin.pkg.system.fake",
    manager: "fakesystem",
    display_name: "Fake System-Scope Package Manager",
    supported_os: &[Os::Linux],
    required_capabilities: &[],
    system_scope: true,
    rollback: RollbackCapability::None,
};

/// 可注入的内存状态。
#[derive(Debug, Default)]
struct FakeState {
    /// 已安装包。
    installed: BTreeMap<PackageIdentity, InstalledPackage>,
    /// 源里可用的版本；**没有登记的包不做目录检查**。
    catalog: BTreeMap<PackageIdentity, Vec<String>>,
    /// 状态读不出来的包。
    unreadable: BTreeMap<PackageIdentity, String>,
    /// 注入的执行失败。
    failures: BTreeMap<PackageIdentity, String>,
    /// 注入的 verify 漂移（值是「实际观察到的状态」描述）。
    drift: BTreeMap<PackageIdentity, String>,
    /// 整个管理器不可用。
    unavailable: Option<String>,
    /// 已成功执行的动作，按顺序。
    applied: Vec<PackageAction>,
    /// 单调递增的假时钟。
    clock: u64,
}

/// 内存包管理器测试替身。
#[derive(Debug)]
pub struct FakePackageManager {
    descriptor: &'static PackageManagerDescriptor,
    state: Mutex<FakeState>,
}

impl FakePackageManager {
    /// 构造一个空的 fake（什么都没装、目录为空）。
    pub fn new(descriptor: &'static PackageManagerDescriptor) -> Self {
        FakePackageManager {
            descriptor,
            state: Mutex::new(FakeState::default()),
        }
    }

    /// 解析夹具里的包身份，并确认它属于本管理器。
    ///
    /// # Panics
    ///
    /// 身份不合法或不属于本管理器时 panic：夹具写错必须立刻暴露。
    pub fn identity(&self, text: &str) -> PackageIdentity {
        let identity = PackageIdentity::parse(text)
            .unwrap_or_else(|err| panic!("夹具里的包身份 `{text}` 不合法：{err}"));
        assert_eq!(
            identity.manager,
            self.descriptor.manager_id(),
            "夹具里的包 `{text}` 不属于管理器 `{}`",
            self.descriptor.manager
        );
        identity
    }

    fn lock(&self) -> MutexGuard<'_, FakeState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// 注入一个用户显式安装的包。
    #[must_use]
    pub fn with_installed(self, identity: &str, version: Option<&str>) -> Self {
        let identity = self.identity(identity);
        self.lock().installed.insert(
            identity,
            InstalledPackage {
                version: version.map(str::to_owned),
                explicit: true,
            },
        );
        self
    }

    /// 注入一个由依赖自动引入的包（`explicit == false`）。
    #[must_use]
    pub fn with_dependency(self, identity: &str, version: Option<&str>) -> Self {
        let identity = self.identity(identity);
        self.lock().installed.insert(
            identity,
            InstalledPackage {
                version: version.map(str::to_owned),
                explicit: false,
            },
        );
        self
    }

    /// 登记源里可用的版本。
    ///
    /// 空列表表示「源里根本没有这个包」，安装时会得到
    /// [`PackageAdapterError::PackageNotFound`]。
    #[must_use]
    pub fn with_available(self, identity: &str, versions: &[&str]) -> Self {
        let identity = self.identity(identity);
        self.lock().catalog.insert(
            identity,
            versions
                .iter()
                .map(|version| (*version).to_owned())
                .collect(),
        );
        self
    }

    /// 注入一个「状态读不出来」的包。
    #[must_use]
    pub fn with_unreadable(self, identity: &str, reason: &str) -> Self {
        let identity = self.identity(identity);
        self.lock().unreadable.insert(identity, reason.to_owned());
        self
    }

    /// 注入一次执行失败。
    #[must_use]
    pub fn failing(self, identity: &str, detail: &str) -> Self {
        let identity = self.identity(identity);
        self.lock().failures.insert(identity, detail.to_owned());
        self
    }

    /// 注入一次 verify 漂移：应用「成功」了，但世界不是期望的样子。
    #[must_use]
    pub fn drifting(self, identity: &str, actual: &str) -> Self {
        let identity = self.identity(identity);
        self.lock().drift.insert(identity, actual.to_owned());
        self
    }

    /// 让整个包管理器不可用。
    #[must_use]
    pub fn unavailable(self, reason: &str) -> Self {
        self.lock().unavailable = Some(reason.to_owned());
        self
    }

    /// 设置假时钟起点。
    #[must_use]
    pub fn with_clock(self, unix_ms: u64) -> Self {
        self.lock().clock = unix_ms;
        self
    }

    /// 查询某个包当前安装的版本。
    pub fn installed_version(&self, identity: &str) -> Option<String> {
        let identity = self.identity(identity);
        self.lock()
            .installed
            .get(&identity)
            .and_then(|info| info.version.clone())
    }

    /// 某个包当前是否已安装。
    pub fn is_installed(&self, identity: &str) -> bool {
        let identity = self.identity(identity);
        self.lock().installed.contains_key(&identity)
    }

    /// 已成功执行的动作，按执行顺序。
    pub fn applied_actions(&self) -> Vec<PackageAction> {
        self.lock().applied.clone()
    }
}

impl FakeState {
    /// 源里为某个包登记的可用版本。
    fn catalog_of(&self, identity: &PackageIdentity) -> Option<&[String]> {
        self.catalog.get(identity).map(Vec::as_slice)
    }

    /// 目录检查：源里没有这个包、或者满足不了版本策略时**阻塞**。
    fn check_catalog(
        &self,
        adapter: &'static str,
        action: &PackageAction,
    ) -> Result<(), PackageAdapterError> {
        if action.kind == PackageActionKind::Uninstall {
            return Ok(());
        }
        let Some(versions) = self.catalog_of(&action.identity) else {
            // 没有登记目录：这个 fake 对该包不做来源检查。
            return Ok(());
        };
        if versions.is_empty() {
            return Err(PackageAdapterError::PackageNotFound {
                adapter,
                identity: action.identity.to_string(),
            });
        }
        if action
            .to_version
            .best_match(versions.iter().map(String::as_str))
            .is_none()
        {
            return Err(PackageAdapterError::UnsupportedVersion {
                identity: action.identity.to_string(),
                policy: action.to_version.to_string(),
                reason: format!("源里只有 {}", versions.join(", ")),
            });
        }
        Ok(())
    }

    /// 应用一个动作后，包应当处于哪个版本。
    fn resolve_target(&self, action: &PackageAction) -> Option<String> {
        if let Some(versions) = self.catalog_of(&action.identity) {
            if let Some(best) = action
                .to_version
                .best_match(versions.iter().map(String::as_str))
            {
                return Some(best.to_owned());
            }
        }
        match &action.to_version {
            VersionPolicy::Exact(version) => Some(version.clone()),
            // 没有目录信息时，「装上就行」保留当前版本（若有），否则未知。
            _ => self
                .installed
                .get(&action.identity)
                .and_then(|info| info.version.clone()),
        }
    }
}

/// 动作期望的状态描述，用于漂移诊断。
fn describe_expected(action: &PackageAction) -> String {
    match action.kind {
        PackageActionKind::Uninstall => "absent".to_owned(),
        _ => format!("installed {}", action.to_version),
    }
}

impl PackageAdapter for FakePackageManager {
    fn descriptor(&self) -> &'static PackageManagerDescriptor {
        self.descriptor
    }

    fn observe(
        &self,
        ctx: &ObserveContext<'_>,
    ) -> Result<PackageObservationSet, PackageAdapterError> {
        let state = self.lock();
        if let Some(reason) = &state.unavailable {
            return Err(PackageAdapterError::ManagerUnavailable {
                adapter: self.descriptor.id,
                reason: reason.clone(),
            });
        }
        if !self.descriptor.applies_to(ctx.profile) {
            return Err(PackageAdapterError::ManagerUnavailable {
                adapter: self.descriptor.id,
                reason: "设备 Profile 不满足操作系统或能力要求".to_owned(),
            });
        }

        let mut observed =
            PackageObservationSet::new(self.descriptor.manager_id(), ctx.observed_at_unix_ms);
        for (identity, info) in &state.installed {
            observed.insert(PackageObservation::new(
                identity.clone(),
                PackageState::Installed(info.clone()),
            ))?;
        }
        // 读不出来的包必须显式记录：留空会被当成「没装」，进而生成一次多余的安装。
        for (identity, reason) in &state.unreadable {
            observed.insert(PackageObservation::new(
                identity.clone(),
                PackageState::Unreadable {
                    reason: reason.clone(),
                },
            ))?;
        }
        Ok(observed)
    }

    fn plan(
        &self,
        desired: &[PackageIntent],
        observed: &PackageObservationSet,
    ) -> Result<Vec<PackageAction>, PackageAdapterError> {
        let mut actions = plan_from_intents(self.descriptor, desired, observed)?;
        let state = self.lock();
        let manager = self.descriptor.manager_id();

        // `Latest` 在纯函数层无法判定（「最新」需要查询源），由这里补足。
        for intent in desired {
            if intent.identity.manager != manager
                || intent.disposition != PackageDisposition::Managed
                || intent.version != VersionPolicy::Latest
            {
                continue;
            }
            let Some(info) = observed.state_of(&intent.identity).installed() else {
                continue;
            };
            let Some(versions) = state.catalog_of(&intent.identity) else {
                continue;
            };
            let Some(newest) =
                VersionPolicy::Latest.best_match(versions.iter().map(String::as_str))
            else {
                continue;
            };
            if info.version.as_deref() != Some(newest) {
                actions.push(self.descriptor.decorate(PackageAction::new(
                    intent.identity.clone(),
                    PackageActionKind::Upgrade,
                    info.version.clone(),
                    VersionPolicy::Latest,
                )));
            }
        }

        for action in &actions {
            state.check_catalog(self.descriptor.id, action)?;
        }

        actions.sort_by_key(PackageAction::sort_key);
        actions.dedup();
        Ok(actions)
    }

    fn apply(
        &self,
        action: &PackageAction,
        ctx: &ApplyContext<'_>,
    ) -> Result<PackageReceipt, PackageAdapterError> {
        if action.identity.manager != self.descriptor.manager_id() {
            return Err(PackageAdapterError::ManagerMismatch {
                adapter: self.descriptor.id,
                identity: action.identity.to_string(),
            });
        }
        // 纵深防御：即便有人绕过核心层直接调用适配器，破坏性动作也不会在没有确认、
        // 没有提权授权的情况下发生。
        ctx.authorize(action)?;

        let mut state = self.lock();
        if let Some(reason) = &state.unavailable {
            return Err(PackageAdapterError::ManagerUnavailable {
                adapter: self.descriptor.id,
                reason: reason.clone(),
            });
        }
        if let Some(detail) = state.failures.get(&action.identity) {
            return Err(PackageAdapterError::ManagerFailed {
                identity: action.identity.to_string(),
                kind: action.kind.as_str(),
                detail: detail.clone(),
            });
        }
        state.check_catalog(self.descriptor.id, action)?;

        let started_at_unix_ms = state.clock;
        state.clock += 1;

        let before_version = state
            .installed
            .get(&action.identity)
            .and_then(|info| info.version.clone())
            .or_else(|| action.from_version.clone());

        let after_version = match action.kind {
            PackageActionKind::Uninstall => {
                state.installed.remove(&action.identity);
                None
            }
            kind => {
                let resolved = state.resolve_target(action);
                if kind == PackageActionKind::ChangeSource {
                    // 换源不是并排安装：同名的旧来源必须先消失。
                    let stale: Vec<PackageIdentity> = state
                        .installed
                        .keys()
                        .filter(|installed| {
                            installed.name == action.identity.name
                                && installed.source != action.identity.source
                        })
                        .cloned()
                        .collect();
                    for identity in stale {
                        state.installed.remove(&identity);
                    }
                }
                state.installed.insert(
                    action.identity.clone(),
                    InstalledPackage {
                        version: resolved.clone(),
                        explicit: true,
                    },
                );
                resolved
            }
        };

        state.clock += 1;
        let finished_at_unix_ms = state.clock;
        state.applied.push(action.clone());

        Ok(PackageReceipt {
            adapter: self.descriptor.id,
            identity: action.identity.clone(),
            kind: action.kind,
            before_version,
            after_version,
            rollback: self.descriptor.rollback,
            commands: Vec::new(),
            started_at_unix_ms,
            finished_at_unix_ms,
        })
    }

    fn verify(
        &self,
        action: &PackageAction,
        ctx: &ObserveContext<'_>,
    ) -> Result<VerifyResult, PackageAdapterError> {
        if action.identity.manager != self.descriptor.manager_id() {
            return Err(PackageAdapterError::ManagerMismatch {
                adapter: self.descriptor.id,
                identity: action.identity.to_string(),
            });
        }
        let state = self.lock();
        if !self.descriptor.applies_to(ctx.profile) {
            return Ok(VerifyResult::Unknown {
                reason: "设备 Profile 不满足操作系统或能力要求".to_owned(),
            });
        }
        if let Some(reason) = &state.unavailable {
            return Ok(VerifyResult::Unknown {
                reason: reason.clone(),
            });
        }
        // 注入的漂移优先：模拟「命令说成功了，但世界没变成期望的样子」。
        if let Some(actual) = state.drift.get(&action.identity) {
            return Ok(VerifyResult::Drift {
                expected: describe_expected(action),
                actual: actual.clone(),
            });
        }
        if let Some(reason) = state.unreadable.get(&action.identity) {
            return Ok(VerifyResult::Unknown {
                reason: reason.clone(),
            });
        }

        let installed = state.installed.get(&action.identity);
        Ok(match (action.kind, installed) {
            (PackageActionKind::Uninstall, None) => VerifyResult::Match,
            (PackageActionKind::Uninstall, Some(info)) => VerifyResult::Drift {
                expected: "absent".to_owned(),
                actual: format!(
                    "installed {}",
                    info.version.as_deref().unwrap_or("<unknown>")
                ),
            },
            (_, None) => VerifyResult::Drift {
                expected: describe_expected(action),
                actual: "absent".to_owned(),
            },
            (_, Some(info)) => match &info.version {
                Some(version) if action.to_version.selects(version) => VerifyResult::Match,
                Some(version) => VerifyResult::Drift {
                    expected: describe_expected(action),
                    actual: format!("installed {version}"),
                },
                // 管理器不报告版本：能确认装上了，确认不了版本。
                None if matches!(
                    action.to_version,
                    VersionPolicy::Present | VersionPolicy::Latest
                ) =>
                {
                    VerifyResult::Match
                }
                None => VerifyResult::Unknown {
                    reason: "包管理器不报告已安装版本".to_owned(),
                },
            },
        })
    }
}
