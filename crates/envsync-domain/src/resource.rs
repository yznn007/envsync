//! 资源观察状态与期望处置。
//!
//! 设计文档要求把“资源不存在”“平台不支持”“读不出来”“被策略排除”严格区分开，
//! 因为它们对计划的含义完全不同：只有**显式**的 [`DesiredDisposition::EnsureAbsent`]
//! 才能产生删除动作，任何一种“观察不到”都不得被推断为删除意图。

use serde::{Deserialize, Serialize};

use crate::cbor::{CborCodec, CborError, Value};
use crate::id::{BlobId, Digest32, ResourceId};
use crate::{cbor_struct, cbor_unit_enum};

/// 文件管理模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileMode {
    /// EnvSync 管理整个文件内容。
    FullFile,
    /// 只管理带稳定标识的区块，块外内容属于用户。
    ManagedBlock,
    /// 对结构化配置做语义合并（M1 起启用）。
    StructuredMerge,
    /// 生成独立文件，再向主配置注入一条 include/source（M1 起启用）。
    GeneratedInclude,
}

cbor_unit_enum!(FileMode {
    FileMode::FullFile => "full_file",
    FileMode::ManagedBlock => "managed_block",
    FileMode::StructuredMerge => "structured_merge",
    FileMode::GeneratedInclude => "generated_include",
});

/// 结构化合并使用的具体格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuredFormat {
    /// JSON。
    Json,
    /// YAML（仅安全子集）。
    Yaml,
    /// TOML。
    Toml,
    /// INI。
    Ini,
    /// Git 配置文件。
    GitConfig,
}

cbor_unit_enum!(StructuredFormat {
    StructuredFormat::Json => "json",
    StructuredFormat::Yaml => "yaml",
    StructuredFormat::Toml => "toml",
    StructuredFormat::Ini => "ini",
    StructuredFormat::GitConfig => "git_config",
});

/// 换行风格。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineEnding {
    /// 沿用目标文件现有风格；文件不存在时使用平台默认。
    Preserve,
    /// 强制 `\n`。
    Lf,
    /// 强制 `\r\n`。
    Crlf,
}

cbor_unit_enum!(LineEnding {
    LineEnding::Preserve => "preserve",
    LineEnding::Lf => "lf",
    LineEnding::Crlf => "crlf",
});

/// 期望处置。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesiredDisposition {
    /// 把资源收敛到快照内容。
    Managed,
    /// 显式删除（tombstone）。
    EnsureAbsent,
    /// 不归 EnvSync 管理，仅记录存在性。
    Unmanaged,
}

cbor_unit_enum!(DesiredDisposition {
    DesiredDisposition::Managed => "managed",
    DesiredDisposition::EnsureAbsent => "ensure_absent",
    DesiredDisposition::Unmanaged => "unmanaged",
});

/// 单个资源的写入策略。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePolicy {
    /// 读取与写入的字节上限；超过时报错而不是截断。
    pub max_bytes: u64,
    /// 换行风格。
    pub line_ending: LineEnding,
    /// POSIX 权限位；`None` 表示沿用现有文件或使用平台默认。
    pub unix_mode: Option<u32>,
    /// 是否属于秘密资源。秘密资源禁止退化到可能暴露明文的写入路径。
    pub secret: bool,
    /// 结构化合并格式，仅在 [`FileMode::StructuredMerge`] 下有意义。
    pub structured_format: Option<StructuredFormat>,
}

impl ResourcePolicy {
    /// 默认文件大小上限：16 MiB。
    pub const DEFAULT_MAX_BYTES: u64 = 16 * 1024 * 1024;
}

impl Default for ResourcePolicy {
    fn default() -> Self {
        ResourcePolicy {
            max_bytes: Self::DEFAULT_MAX_BYTES,
            line_ending: LineEnding::Preserve,
            unix_mode: None,
            secret: false,
            structured_format: None,
        }
    }
}

cbor_struct!(ResourcePolicy {
    max_bytes: u64,
    line_ending: LineEnding,
    unix_mode: Option<u32>,
    secret: bool,
    structured_format: Option<StructuredFormat>,
});

/// 观察到的文件权限摘要。
///
/// 只记录同步语义关心的部分：是否只读，以及 POSIX 权限位。绝不记录属主 uid/gid 等
/// 会跨设备泄露本机信息的字段。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionSummary {
    /// 是否只读。
    pub readonly: bool,
    /// POSIX 权限位；Windows 上为 `None`。
    pub unix_mode: Option<u32>,
}

cbor_struct!(PermissionSummary {
    readonly: bool,
    unix_mode: Option<u32>,
});

/// 观察到的“存在”状态所携带的信息。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresentFile {
    /// 文件全部内容的摘要。
    pub content_digest: Digest32,
    /// 文件字节数。
    pub size: u64,
    /// 修改时间（Unix 毫秒）；文件系统不提供时为 `None`。
    ///
    /// mtime **只作为诊断信息**，新鲜度判定一律使用内容摘要，避免时间戳精度和时钟
    /// 回拨造成误判。
    pub mtime_unix_ms: Option<u64>,
    /// 权限摘要。
    pub permissions: PermissionSummary,
    /// Managed Block 模式下，块内受管内容的摘要；其他模式为 `None`。
    pub managed_digest: Option<Digest32>,
}

cbor_struct!(PresentFile {
    content_digest: Digest32,
    size: u64,
    mtime_unix_ms: Option<u64>,
    permissions: PermissionSummary,
    managed_digest: Option<Digest32>,
});

/// 观察状态。五个变体互斥，且都不等价于“应当删除”。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ObservedState {
    /// 资源存在且可读。
    Present(PresentFile),
    /// 资源确定不存在。
    Absent,
    /// 当前平台或适配器不支持该资源。
    Unsupported {
        /// 不支持的原因（不含路径等本机信息）。
        reason: String,
    },
    /// 资源存在但读取失败（权限不足、I/O 错误等）。
    Unreadable {
        /// 失败原因。
        reason: String,
    },
    /// 被策略排除。
    Excluded {
        /// 排除原因。
        reason: String,
    },
}

impl ObservedState {
    /// 稳定的状态名，用于诊断输出和 JSON 契约。
    pub fn kind(&self) -> &'static str {
        match self {
            ObservedState::Present(_) => "present",
            ObservedState::Absent => "absent",
            ObservedState::Unsupported { .. } => "unsupported",
            ObservedState::Unreadable { .. } => "unreadable",
            ObservedState::Excluded { .. } => "excluded",
        }
    }

    /// 是否处于可以安全写入的状态。
    ///
    /// `Unreadable` 与 `Unsupported` 都不可写：前者说明我们不知道当前内容，覆盖会
    /// 造成不可恢复的数据丢失；后者说明适配器无法保证语义。
    pub fn is_writable(&self) -> bool {
        matches!(self, ObservedState::Present(_) | ObservedState::Absent)
    }

    /// 取出存在状态的详细信息。
    pub fn present(&self) -> Option<&PresentFile> {
        match self {
            ObservedState::Present(file) => Some(file),
            _ => None,
        }
    }

    /// 当前内容摘要；不存在时为 `None`。
    pub fn content_digest(&self) -> Option<Digest32> {
        self.present().map(|file| file.content_digest)
    }
}

impl CborCodec for ObservedState {
    fn to_value(&self) -> Value {
        match self {
            ObservedState::Present(file) => {
                Value::Array(vec![Value::Text("present".into()), file.to_value()])
            }
            ObservedState::Absent => Value::Array(vec![Value::Text("absent".into())]),
            ObservedState::Unsupported { reason } => Value::Array(vec![
                Value::Text("unsupported".into()),
                Value::Text(reason.clone()),
            ]),
            ObservedState::Unreadable { reason } => Value::Array(vec![
                Value::Text("unreadable".into()),
                Value::Text(reason.clone()),
            ]),
            ObservedState::Excluded { reason } => Value::Array(vec![
                Value::Text("excluded".into()),
                Value::Text(reason.clone()),
            ]),
        }
    }

    fn from_value(value: &Value) -> Result<Self, CborError> {
        let items = value.as_array()?;
        let tag = items.first().ok_or(CborError::ArityMismatch)?.as_text()?;
        let arity = items.len();
        match (tag, arity) {
            ("present", 2) => Ok(ObservedState::Present(PresentFile::from_value(&items[1])?)),
            ("absent", 1) => Ok(ObservedState::Absent),
            ("unsupported", 2) => Ok(ObservedState::Unsupported {
                reason: items[1].as_text()?.to_owned(),
            }),
            ("unreadable", 2) => Ok(ObservedState::Unreadable {
                reason: items[1].as_text()?.to_owned(),
            }),
            ("excluded", 2) => Ok(ObservedState::Excluded {
                reason: items[1].as_text()?.to_owned(),
            }),
            ("present" | "absent" | "unsupported" | "unreadable" | "excluded", _) => {
                Err(CborError::ArityMismatch)
            }
            (other, _) => Err(CborError::UnknownVariant(other.to_owned())),
        }
    }
}

/// 一次对单个资源的观察结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    /// 被观察的资源。
    pub resource: ResourceId,
    /// 观察到的状态。
    pub state: ObservedState,
    /// 观察发生的时刻（Unix 毫秒），仅用于诊断。
    pub observed_at_unix_ms: u64,
}

cbor_struct!(Observation {
    resource: ResourceId,
    state: ObservedState,
    observed_at_unix_ms: u64,
});

impl Observation {
    /// 构造一次观察。
    pub fn new(resource: ResourceId, state: ObservedState, observed_at_unix_ms: u64) -> Self {
        Observation {
            resource,
            state,
            observed_at_unix_ms,
        }
    }
}

/// State Root 中的一条资源条目：描述“这个资源应该是什么样子”。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceEntry {
    /// 资源标识。
    pub resource: ResourceId,
    /// 期望处置。
    pub disposition: DesiredDisposition,
    /// 期望内容的 Blob；仅 [`DesiredDisposition::Managed`] 必须有值。
    pub blob: Option<BlobId>,
    /// 文件管理模式。
    pub mode: FileMode,
    /// 写入策略。
    pub policy: ResourcePolicy,
}

cbor_struct!(ResourceEntry {
    resource: ResourceId,
    disposition: DesiredDisposition,
    blob: Option<BlobId>,
    mode: FileMode,
    policy: ResourcePolicy,
});

/// 资源条目自身的一致性错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResourceEntryError {
    /// `Managed` 缺少内容 Blob。
    #[error("资源 `{0}` 的处置为 managed 但缺少内容 Blob")]
    ManagedWithoutBlob(ResourceId),
    /// 非 `Managed` 却携带内容 Blob。
    #[error("资源 `{0}` 的处置为 {1} 但携带了内容 Blob")]
    NonManagedWithBlob(ResourceId, &'static str),
    /// `StructuredMerge` 缺少格式声明。
    #[error("资源 `{0}` 使用 structured_merge 但未声明具体格式")]
    StructuredWithoutFormat(ResourceId),
}

impl ResourceEntry {
    /// 校验条目内部一致性。
    ///
    /// 该检查在写入 State Root 之前执行，保证快照永远不会包含自相矛盾的条目。
    pub fn validate(&self) -> Result<(), ResourceEntryError> {
        match (self.disposition, &self.blob) {
            (DesiredDisposition::Managed, None) => {
                return Err(ResourceEntryError::ManagedWithoutBlob(
                    self.resource.clone(),
                ));
            }
            (DesiredDisposition::EnsureAbsent, Some(_)) => {
                return Err(ResourceEntryError::NonManagedWithBlob(
                    self.resource.clone(),
                    "ensure_absent",
                ));
            }
            (DesiredDisposition::Unmanaged, Some(_)) => {
                return Err(ResourceEntryError::NonManagedWithBlob(
                    self.resource.clone(),
                    "unmanaged",
                ));
            }
            _ => {}
        }
        if self.mode == FileMode::StructuredMerge && self.policy.structured_format.is_none() {
            return Err(ResourceEntryError::StructuredWithoutFormat(
                self.resource.clone(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn present_file() -> PresentFile {
        PresentFile {
            content_digest: Digest32::domain_hash("test", b"content"),
            size: 7,
            mtime_unix_ms: Some(1_700_000_000_000),
            permissions: PermissionSummary {
                readonly: false,
                unix_mode: Some(0o644),
            },
            managed_digest: None,
        }
    }

    #[test]
    fn all_five_observed_states_round_trip_losslessly() {
        let states = vec![
            ObservedState::Present(present_file()),
            ObservedState::Absent,
            ObservedState::Unsupported {
                reason: "平台不支持".into(),
            },
            ObservedState::Unreadable {
                reason: "权限不足".into(),
            },
            ObservedState::Excluded {
                reason: "被策略排除".into(),
            },
        ];
        for state in states {
            let bytes = state.to_canonical_vec();
            let decoded = ObservedState::from_canonical_slice(&bytes).expect("解码成功");
            assert_eq!(decoded, state, "状态 {} 序列化后不一致", state.kind());
        }
    }

    #[test]
    fn only_present_and_absent_are_writable() {
        assert!(ObservedState::Present(present_file()).is_writable());
        assert!(ObservedState::Absent.is_writable());
        assert!(!ObservedState::Unreadable { reason: "x".into() }.is_writable());
        assert!(!ObservedState::Unsupported { reason: "x".into() }.is_writable());
        assert!(!ObservedState::Excluded { reason: "x".into() }.is_writable());
    }

    #[test]
    fn observed_state_decoding_rejects_wrong_arity_and_unknown_tag() {
        let wrong_arity = Value::Array(vec![Value::Text("absent".into()), Value::Uint(1)]);
        assert_eq!(
            ObservedState::from_value(&wrong_arity),
            Err(CborError::ArityMismatch)
        );

        let unknown = Value::Array(vec![Value::Text("deleted".into())]);
        assert_eq!(
            ObservedState::from_value(&unknown),
            Err(CborError::UnknownVariant("deleted".into()))
        );
    }

    #[test]
    fn disposition_has_exactly_three_variants() {
        // 该断言的意义在于：任何人想新增“隐式删除”之类的处置，都必须先改这里，
        // 从而被迫面对设计文档中“默认不删除”的约束。
        let all = [
            DesiredDisposition::Managed,
            DesiredDisposition::EnsureAbsent,
            DesiredDisposition::Unmanaged,
        ];
        let tags: Vec<String> = all
            .iter()
            .map(|d| d.to_value().as_text().expect("文本判别式").to_owned())
            .collect();
        assert_eq!(tags, vec!["managed", "ensure_absent", "unmanaged"]);
    }

    #[test]
    fn resource_entry_validation_enforces_blob_rules() {
        let resource = ResourceId::parse("shell/zsh/main").unwrap();
        let managed_without_blob = ResourceEntry {
            resource: resource.clone(),
            disposition: DesiredDisposition::Managed,
            blob: None,
            mode: FileMode::FullFile,
            policy: ResourcePolicy::default(),
        };
        assert!(matches!(
            managed_without_blob.validate(),
            Err(ResourceEntryError::ManagedWithoutBlob(_))
        ));

        let tombstone_with_blob = ResourceEntry {
            resource: resource.clone(),
            disposition: DesiredDisposition::EnsureAbsent,
            blob: Some(BlobId::of(b"x")),
            mode: FileMode::FullFile,
            policy: ResourcePolicy::default(),
        };
        assert!(matches!(
            tombstone_with_blob.validate(),
            Err(ResourceEntryError::NonManagedWithBlob(_, "ensure_absent"))
        ));

        let structured_without_format = ResourceEntry {
            resource,
            disposition: DesiredDisposition::Managed,
            blob: Some(BlobId::of(b"x")),
            mode: FileMode::StructuredMerge,
            policy: ResourcePolicy::default(),
        };
        assert!(matches!(
            structured_without_format.validate(),
            Err(ResourceEntryError::StructuredWithoutFormat(_))
        ));
    }

    #[test]
    fn resource_entry_round_trips() {
        let entry = ResourceEntry {
            resource: ResourceId::parse("terminal/wezterm/config").unwrap(),
            disposition: DesiredDisposition::Managed,
            blob: Some(BlobId::of(b"lua")),
            mode: FileMode::FullFile,
            policy: ResourcePolicy {
                line_ending: LineEnding::Lf,
                ..ResourcePolicy::default()
            },
        };
        entry.validate().expect("条目合法");
        let bytes = entry.to_canonical_vec();
        assert_eq!(ResourceEntry::from_canonical_slice(&bytes).unwrap(), entry);
    }
}
