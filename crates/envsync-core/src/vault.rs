//! Vault application service：端到端加密的秘密存取。
//!
//! 这是 CLI 与桌面端操作秘密的**唯一**入口。它把四样东西缝在一起：
//!
//! | 组件 | 职责 |
//! |---|---|
//! | [`envsync_backend::Backend`] | 存放密封对象、信封、成员事件与索引（**不被信任**） |
//! | [`envsync_platform::secure_store::SecureStore`] | 存放设备私钥与工作区密钥环（受操作系统保护） |
//! | [`crate::membership`] | 判定「谁现在是成员」，以及新事件是否合法 |
//! | [`crate::checkpoint`] | 阻止后端把本设备拉回旧状态 |
//! | [`envsync_storage::DraftStore`] | 本地对象缓存，让离线读取不必每次回后端 |
//!
//! ## 后端上看不到明文
//!
//! 秘密值只以 [`envsync_crypto::sealed::SealedSecret`] 的形式存在于后端；快照里保存的
//! 是 [`SecretRef`]——**逻辑标识 + 密封对象标识**，仅此而已。因此对后端做一次全量
//! Blob 扫描（`grep -r` 那种）不会命中任何明文；`tests/vault_service.rs` 里有一条测试
//! 逐字节遍历后端目录来证明这一点，而不是靠约定。
//!
//! ## 值只能从三个地方来
//!
//! [`SecretInput`] **没有** `from_str` / `From<&str>` 之类的构造函数，只能由
//! [`SecretInput::from_reader`]（stdin）、[`SecretInput::from_env_var`]（环境变量**名**）
//! 或 [`SecretInput::from_hidden_prompt`]（交互式隐藏输入）产生。这样「CLI 参数里直接
//! 写明文」在类型层面就不可能——而 CLI 参数会进入 shell history、`ps` 输出和 CI 日志。
//!
//! ## 密钥环：为什么不是「一个工作区一把密钥」
//!
//! 撤销设备会把纪元从 `n` 推到 `n+1`，但后端上仍然躺着一大批用 `n` 加密的旧对象。
//! 因此安全存储里保存的是一个 **[`KeyRing`]**：`纪元 -> 数据密钥` 的映射，外加一个
//! 「当前纪元」指针。新秘密只用当前纪元的密钥；旧对象在**被读到时**才用新密钥重加密
//! （lazy rewrap，见 [`VaultService::flush_rewraps`]）。
//!
//! 一次性把所有旧对象重加密听起来更干净，代价是撤销操作要在离线时段扫完整个 vault，
//! 而且中途失败会留下一半一半的状态。lazy rewrap 把这份工作摊开，并且天然幂等。
//!
//! ## 发布顺序
//!
//! ```text
//! 1. 写密封对象/信封/成员事件（不可变，幂等）
//! 2. 写索引对象
//! 3. 写快照 + 签名
//! 4. CAS 推进 Ref
//! 5. 推进反回滚检查点
//! ```
//!
//! 第 5 步必须在第 4 步之后：检查点先走一步的话，进程崩在两步之间就会留下「本机认为
//! 已经到 revision N，后端其实还在 N-1」的死结，而 N-1 的数据再也不会被接受。

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use envsync_backend::{Backend, BackendError};
use envsync_crypto::device::{DeviceKeypair, DevicePublic};
use envsync_crypto::envelope::{open_envelope, seal_envelope, KeyEnvelope};
use envsync_crypto::sealed::{open as open_sealed, seal, SealedSecret, SecretId};
use envsync_crypto::suite::{DataKey, KeyEpoch, Plaintext, MAX_PLAINTEXT_LEN};
pub use envsync_crypto::vault::{
    SecretRef, VaultIndex, MAX_SECRETS, VAULT_INDEX_FORMAT_VERSION, VAULT_INDEX_METADATA_KEY,
};
use envsync_domain::cbor::{CborCodec, CborError, Value};
use envsync_domain::id::{DeviceId, ResourceId, SnapshotId, WorkspaceId};
use envsync_domain::membership::{MembershipEvent, MembershipState};
use envsync_domain::object::{ObjectId, ObjectKind, StateRoot};
use envsync_domain::snapshot::{SnapshotBody, SnapshotSignature, WorkspaceRef};
use envsync_platform::secure_store::{SecureKey, SecurePurpose, SecureStore};
use envsync_storage::{DraftStore, RotationJournal};
use zeroize::{Zeroize, Zeroizing};

use crate::checkpoint::{advance as advance_checkpoint, Checkpoint, CheckpointStore};
use crate::error::{CoreError, CoreResult};
use crate::membership::{self, membership_object_id};
use crate::ports::Clock;

/// **工作区级**快照元数据的键前缀。
///
/// 快照的 `metadata` 里混着两类东西：
///
/// * **本次 capture 自己的事实**——`device_name`、`format`、`merge`。它们描述「这一次
///   发布是谁、用什么方式做的」，每次发布都应该重新写；
/// * **工作区级的事实**——目前是 Vault 索引指针与它的背书。它们描述「这个工作区现在
///   是什么样」，与「谁发布了这一版」无关。
///
/// 第二类必须被**继承**。M2 之前不继承，后果是 M0/M1 的发布路径（`capture` 自建头快照，
/// `metadata` 只写 `device_name` / `format`）一跑完就把 Vault 索引指针弄丢了：`vault get`
/// 报 `vault.secret_not_found`，`vault list` 却照常以 `status: ok` 返回一个空 Vault——
/// 一次例行 `envsync sync` 就让整个 Vault 从用户视角消失。
///
/// 用前缀而不是一份硬编码名单：新增一个工作区级键时，只要名字带上前缀就自动被继承，
/// 不必再去每一条发布路径上补一行。
pub const WORKSPACE_METADATA_PREFIX: &str = "envsync.";

/// 快照元数据中承载 Vault 索引背书的键名。
///
/// 值的形状与语义见 [`crate::attestation`]。
pub const VAULT_ATTESTATION_METADATA_KEY: &str = "envsync.vault.attestation";

/// 快照签名使用的用途标签。
pub const SNAPSHOT_SIGNATURE_DOMAIN: &str = "snapshot";

/// 密钥环的格式版本。
pub const KEY_RING_FORMAT_VERSION: u32 = 1;

/// 密钥环中允许保留的纪元数量上限。
pub const MAX_KEY_EPOCHS: usize = 256;

// ---------------------------------------------------------------------------
// 错误
// ---------------------------------------------------------------------------

/// Vault 层错误。
///
/// **所有变体都只描述结构**：秘密的逻辑标识可以出现（它本来就是公开的名字），
/// 秘密的**值**绝不出现。`tests/vault_cli.rs` 里的 canary 测试会遍历这些错误的
/// `Display` 做断言。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VaultError {
    /// 本工作区还没有 genesis：需要先 `envsync device init` + `vault create`。
    #[error("工作区尚未初始化 Vault；请先创建工作区或加入一台已有设备")]
    NotInitialized,

    /// 工作区已经有 genesis，不能重复创建。
    #[error("工作区已经初始化过，不能重复创建")]
    AlreadyInitialized,

    /// 找不到该逻辑秘密。
    #[error("秘密 `{id}` 不存在")]
    SecretNotFound {
        /// 逻辑标识（公开名字，不是值）。
        id: String,
    },

    /// 秘密数量超过上限。
    #[error("秘密数量超过上限 {limit}")]
    TooManySecrets {
        /// 上限。
        limit: usize,
    },

    /// 输入的秘密值为空。
    ///
    /// 空值几乎总是「变量名写错了」或「管道里什么都没有」，把它当成一次成功的写入会
    /// 静默地覆盖掉一条真正的秘密。
    #[error("秘密值为空；请确认输入来源确实有内容")]
    EmptyValue,

    /// 输入的秘密值超过上限。
    #[error("秘密值超过上限 {limit} 字节")]
    ValueTooLarge {
        /// 上限。
        limit: usize,
    },

    /// 指定的环境变量不存在或不是合法 UTF-8。
    #[error("环境变量 `{name}` 不存在或不是合法 UTF-8")]
    EnvVarMissing {
        /// 变量**名**（不是值）。
        name: String,
    },

    /// 当前设备没有本工作区的身份。
    #[error("本设备尚未在该工作区注册身份；请先运行 `envsync device init`")]
    DeviceIdentityMissing,

    /// 安全存储里没有本纪元的数据密钥。
    #[error("本机缺少纪元 {epoch} 的工作区数据密钥；请先加入工作区或用恢复短语恢复")]
    DataKeyMissing {
        /// 缺失的纪元。
        epoch: u64,
    },

    /// 本设备当前不是成员（可能刚被撤销）。
    #[error("本设备不是该工作区的成员")]
    NotAMember,

    /// 该操作需要管理员权限。
    #[error("该操作需要管理员权限")]
    AdminRequired,

    /// 撤销目标不是当前成员。
    #[error("设备 {device} 不是该工作区的成员")]
    NotAMemberDevice {
        /// 相关设备。
        device: DeviceId,
    },

    /// 后端上的对象与索引声称的不一致。
    #[error("索引与后端不一致：{detail}")]
    IndexInconsistent {
        /// 静态说明，不回显任何内容。
        detail: &'static str,
    },

    /// 邀请对象非法（过期、跨工作区、签名不符）。
    #[error("邀请无效：{reason}")]
    InvitationInvalid {
        /// 静态原因。
        reason: &'static str,
    },

    /// Gist 公开引导区与本地信任锚点不一致。
    #[error("Gist 引导无效：{reason}")]
    GistBootstrapInvalid {
        /// 静态原因，不回显远端对象内容。
        reason: &'static str,
    },

    /// 交互式隐藏输入在当前环境不可用。
    #[error("当前环境无法提供隐藏输入；请改用 `--stdin` 或 `--from-env <NAME>`")]
    HiddenInputUnavailable,

    /// 要求把秘密写到 stdout，但既没有 TTY 也没有 `--allow-non-tty`。
    #[error("拒绝把秘密写到非终端的 stdout；确需如此请显式加上 `--allow-non-tty`")]
    NonTtyOutputRefused,
}

impl VaultError {
    /// 稳定的机器可读错误码，用于 CLI 的 JSON 契约。
    ///
    /// 这些字符串属于对外契约的一部分，只能新增、不能重命名。
    pub fn code(&self) -> &'static str {
        match self {
            VaultError::NotInitialized => "vault.not_initialized",
            VaultError::AlreadyInitialized => "vault.already_initialized",
            VaultError::SecretNotFound { .. } => "vault.secret_not_found",
            VaultError::TooManySecrets { .. } => "vault.too_many_secrets",
            VaultError::EmptyValue => "vault.empty_value",
            VaultError::ValueTooLarge { .. } => "vault.value_too_large",
            VaultError::EnvVarMissing { .. } => "vault.env_var_missing",
            VaultError::DeviceIdentityMissing => "vault.device_identity_missing",
            VaultError::DataKeyMissing { .. } => "vault.data_key_missing",
            VaultError::NotAMember => "vault.not_a_member",
            VaultError::AdminRequired => "vault.admin_required",
            VaultError::NotAMemberDevice { .. } => "vault.not_a_member_device",
            VaultError::IndexInconsistent { .. } => "vault.index_inconsistent",
            VaultError::InvitationInvalid { .. } => "vault.invitation_invalid",
            VaultError::GistBootstrapInvalid { .. } => "vault.gist_bootstrap_invalid",
            VaultError::HiddenInputUnavailable => "vault.hidden_input_unavailable",
            VaultError::NonTtyOutputRefused => "vault.non_tty_output_refused",
        }
    }
}

// ---------------------------------------------------------------------------
// 秘密输入
// ---------------------------------------------------------------------------

/// 交互式隐藏输入的端口。
///
/// 「关闭回显」在三个平台上的做法完全不同，而核心层不应该依赖任何终端库。因此这里
/// 只定义契约，实现由界面层注入（CLI 在 `envsync-cli` 里提供）。
pub trait HiddenPrompt {
    /// 显示 `label` 并读取一行不回显的输入。
    ///
    /// 返回值用 [`Zeroizing`] 包裹，离开作用域即清零。无法关闭回显时必须返回
    /// [`VaultError::HiddenInputUnavailable`]，**绝不**退化成明文回显。
    fn read_hidden(&mut self, label: &str) -> CoreResult<Zeroizing<Vec<u8>>>;
}

/// 一次待写入的秘密值。
///
/// **刻意不实现** `Debug`、`Display`、`Clone` 与任何序列化 trait，也**刻意不提供**
/// 从 `&str` / `String` 直接构造的入口：值只能来自 stdin、环境变量名或交互式隐藏输入。
/// 这三条路径的共同点是「值不会出现在命令行里」，而命令行会进入 shell history、
/// `ps aux` 与 CI 日志。
pub struct SecretInput {
    plaintext: Plaintext,
}

impl SecretInput {
    /// 从任意读取器读入（生产路径上是 stdin）。
    ///
    /// 会去掉**至多一个**结尾换行（`\n` 或 `\r\n`）：`echo -n` 与 `echo` 都能用，
    /// 而 `printf 'a\n\n'` 仍然保留第二个换行——多吃一个字节会静默改变秘密内容。
    pub fn from_reader<R: Read + ?Sized>(reader: &mut R) -> CoreResult<Self> {
        // 多读一个字节，用来把「恰好等于上限」和「超过上限」区分开。
        let mut buffer = Zeroizing::new(Vec::new());
        let read = reader
            .take((MAX_PLAINTEXT_LEN + 1) as u64)
            .read_to_end(&mut buffer)
            .map_err(|error| envsync_platform::PlatformError::io("读取秘密输入", &error))?;
        if read > MAX_PLAINTEXT_LEN {
            buffer.zeroize();
            return Err(VaultError::ValueTooLarge {
                limit: MAX_PLAINTEXT_LEN,
            }
            .into());
        }
        Self::from_bytes(buffer)
    }

    /// 从进程 stdin 读入。
    pub fn from_stdin() -> CoreResult<Self> {
        let stdin = std::io::stdin();
        let mut lock = stdin.lock();
        Self::from_reader(&mut lock)
    }

    /// 读取名为 `name` 的**环境变量的值**。
    ///
    /// 参数是变量**名**而不是值：`--from-env GITHUB_TOKEN` 出现在命令行里是安全的，
    /// `--value ghp_xxx` 不是。
    pub fn from_env_var(name: &str) -> CoreResult<Self> {
        let value = std::env::var(name).map_err(|_| VaultError::EnvVarMissing {
            name: name.to_owned(),
        })?;
        Self::from_bytes(Zeroizing::new(value.into_bytes()))
    }

    /// 通过交互式隐藏输入读取。
    pub fn from_hidden_prompt<P>(prompt: &mut P, label: &str) -> CoreResult<Self>
    where
        P: HiddenPrompt + ?Sized,
    {
        Self::from_bytes(prompt.read_hidden(label)?)
    }

    /// 值的字节长度。长度是元数据，不是秘密。
    pub fn len(&self) -> usize {
        self.plaintext.len()
    }

    /// 值是否为空。构造函数已经拒绝空值，因此恒为 `false`。
    pub fn is_empty(&self) -> bool {
        self.plaintext.is_empty()
    }

    /// 共同的字节校验与规范化。
    fn from_bytes(mut bytes: Zeroizing<Vec<u8>>) -> CoreResult<Self> {
        if bytes.ends_with(b"\n") {
            bytes.pop();
            if bytes.ends_with(b"\r") {
                bytes.pop();
            }
        }
        if bytes.is_empty() {
            return Err(VaultError::EmptyValue.into());
        }
        if bytes.len() > MAX_PLAINTEXT_LEN {
            bytes.zeroize();
            return Err(VaultError::ValueTooLarge {
                limit: MAX_PLAINTEXT_LEN,
            }
            .into());
        }
        Ok(SecretInput {
            plaintext: Plaintext::from_vec(bytes.to_vec()),
        })
    }

    /// 取出明文，交给密封函数。
    fn into_plaintext(self) -> Plaintext {
        self.plaintext
    }
}

// ---------------------------------------------------------------------------
// 头快照上的工作区级元数据
// ---------------------------------------------------------------------------

/// 该元数据键是否属于**工作区级**（因而必须被继承）。
///
/// 见 [`WORKSPACE_METADATA_PREFIX`]。
pub fn is_workspace_metadata_key(key: &str) -> bool {
    key.starts_with(WORKSPACE_METADATA_PREFIX)
}

/// 从父快照的元数据里挑出应当被继承的工作区级键。
///
/// 每一条产出新快照的路径（M0 的 `capture`、M1 的合并、M2 的 Vault 发布）都必须以它为
/// 起点，再覆盖本次真正要改的键。
pub fn inherited_workspace_metadata(parent: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    parent
        .iter()
        .filter(|(key, _)| is_workspace_metadata_key(key))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// 一个头快照上**已验证**的 Vault 状态。
///
/// 「已验证」是三件事的合取：成员链从 genesis 完整回放且属于本工作区；索引与链的纪元
/// 一致；索引带着一条由当前成员签出的背书。任何一条不成立都不会产出这个结构。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHead {
    /// 索引对象标识。
    pub index_object: ObjectId,
    /// 索引内容。
    pub index: VaultIndex,
    /// genesis 事件。
    pub genesis: MembershipEvent,
    /// genesis 之后的事件，按 sequence 升序。
    pub events: Vec<MembershipEvent>,
    /// 已验证的成员状态。
    pub state: MembershipState,
    /// 签出索引背书的设备。
    pub attested_by: DeviceId,
}

impl VaultHead {
    /// 由这份已验证状态推导反回滚检查点的**候选值**。
    ///
    /// `updated_at_unix_ms` 固定为 `0`：它只供审计，不参与
    /// [`crate::checkpoint::check_advance`] 的任何判定，在候选值里填一个本机时钟读数
    /// 只会让「同一份远端状态推导出的候选」变得不可复现。
    pub fn checkpoint(&self, workspace: WorkspaceId, reference: &WorkspaceRef) -> Checkpoint {
        Checkpoint {
            workspace,
            revision: reference.revision,
            snapshot: reference.head.unwrap_or_else(|| SnapshotId::of(b"")),
            membership_digest: self.state.head,
            membership_sequence: self.state.sequence,
            key_epoch: self.state.epoch,
            updated_at_unix_ms: 0,
        }
    }
}

/// 从一个头快照解析并**完整验证**它承载的 Vault 状态。
///
/// 返回 `None` 表示这个头快照上没有 Vault 索引指针——工作区存在，但还没跑过
/// `vault create`（或者跑过而指针丢了，那是
/// [`VaultService::vault_index_missing`] 负责报的事）。
///
/// 校验顺序刻意是「结构 → 归属 → 链 → 背书」：
///
/// 1. 索引能解码，且 `workspace` 等于本地工作区；
/// 2. 成员链从 genesis 完整回放，**并与本地工作区比对**（外来链在第一条事件就被拒）；
/// 3. 索引纪元与链纪元一致；
/// 4. 索引背书由当前成员链上的设备签出。
///
/// 第 4 步排在最后不是因为它最贵，而是因为它需要第 2 步的产物：「谁现在是成员」本身
/// 就是被验证的对象之一。
pub fn inspect_vault_head(
    workspace: WorkspaceId,
    body: &SnapshotBody,
    read_object: &mut dyn FnMut(ObjectId) -> CoreResult<Vec<u8>>,
) -> CoreResult<Option<VaultHead>> {
    let Some(raw) = body.metadata.get(VAULT_INDEX_METADATA_KEY) else {
        return Ok(None);
    };
    let index_object = raw.parse::<ObjectId>().map_err(|_| {
        CoreError::from(VaultError::IndexInconsistent {
            detail: "快照元数据里的索引对象标识无法解析",
        })
    })?;
    let index = VaultIndex::from_canonical_slice(&read_object(index_object)?)?;
    if index.workspace != workspace {
        return Err(VaultError::IndexInconsistent {
            detail: "索引属于另一个工作区",
        }
        .into());
    }

    let mut events = Vec::with_capacity(index.membership.len());
    for object in &index.membership {
        events.push(MembershipEvent::from_canonical_slice(&read_object(
            *object,
        )?)?);
    }
    let Some((genesis, rest)) = events.split_first() else {
        return Err(VaultError::IndexInconsistent {
            detail: "索引里没有 genesis 事件",
        }
        .into());
    };
    let state = membership::verify_membership_chain(genesis, rest, workspace)?;
    if state.epoch != index.epoch {
        return Err(VaultError::IndexInconsistent {
            detail: "索引纪元与成员链纪元不一致",
        }
        .into());
    }

    let attested_by = crate::attestation::verify_index_attestation(
        body.metadata
            .get(VAULT_ATTESTATION_METADATA_KEY)
            .map(String::as_str),
        workspace,
        index_object,
        Some(&state),
    )?
    // `Some(&state)` 这条路径要么报错，要么一定给出签发者。
    .ok_or_else(|| CoreError::Invariant("已验证的背书必须给出签发设备".to_owned()))?;

    Ok(Some(VaultHead {
        index_object,
        index,
        genesis: genesis.clone(),
        events: rest.to_vec(),
        state,
        attested_by,
    }))
}

/// 对外暴露的秘密元数据。
///
/// [`VaultService::list`] **只**返回它：调用方拿到的是「有哪些秘密、多新、被谁引用」，
/// 拿不到值。想拿值必须逐条走 [`VaultService::get`]，那是一个显眼的调用点。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMetadata {
    /// 逻辑标识。
    pub id: SecretId,
    /// 密封时使用的数据密钥纪元。
    pub epoch: u64,
    /// 最近一次写入时刻（Unix 毫秒）。
    pub updated_at_unix_ms: u64,
    /// 引用该秘密的资源。
    pub referenced_by: Vec<ResourceId>,
}

impl From<&SecretRef> for SecretMetadata {
    fn from(value: &SecretRef) -> Self {
        SecretMetadata {
            id: value.id.clone(),
            epoch: value.epoch,
            updated_at_unix_ms: value.updated_at_unix_ms,
            referenced_by: value.referenced_by.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// 密钥环
// ---------------------------------------------------------------------------

/// 工作区数据密钥环：`纪元 -> 数据密钥`，外加「当前纪元」指针。
///
/// 只存在于系统安全存储里；序列化形式（[`KeyRing::to_secret_bytes`]）是
/// [`Zeroizing`] 的，落地之后调用方持有的副本会被清零。**刻意不实现** `Debug` /
/// `Clone` / 任何序列化 trait。
pub struct KeyRing {
    current: KeyEpoch,
    keys: BTreeMap<u64, DataKey>,
}

impl KeyRing {
    /// 以单把密钥建立密钥环。
    pub fn new(epoch: KeyEpoch, key: DataKey) -> Self {
        let mut keys = BTreeMap::new();
        keys.insert(epoch.get(), key);
        KeyRing {
            current: epoch,
            keys,
        }
    }

    /// 当前纪元。
    pub fn current_epoch(&self) -> KeyEpoch {
        self.current
    }

    /// 当前纪元的数据密钥。
    pub fn current_key(&self) -> CoreResult<&DataKey> {
        self.key(self.current)
    }

    /// 指定纪元的数据密钥。
    pub fn key(&self, epoch: KeyEpoch) -> CoreResult<&DataKey> {
        self.keys
            .get(&epoch.get())
            .ok_or_else(|| VaultError::DataKeyMissing { epoch: epoch.get() }.into())
    }

    /// 是否已经持有某个纪元的密钥。
    pub fn contains(&self, epoch: KeyEpoch) -> bool {
        self.keys.contains_key(&epoch.get())
    }

    /// 放入一把密钥；已存在时保持原值不变。
    ///
    /// 「已存在不覆盖」是幂等恢复的基础：轮换在 `prepared` 阶段生成新纪元的密钥，
    /// 中断后重来一次必须拿回**同一把**，否则先前发出去的信封就全废了。
    pub fn insert(&mut self, epoch: KeyEpoch, key: DataKey) {
        self.keys.entry(epoch.get()).or_insert(key);
    }

    /// 把当前纪元指针推到 `epoch`；该纪元必须已经有密钥。
    pub fn promote(&mut self, epoch: KeyEpoch) -> CoreResult<()> {
        if !self.contains(epoch) {
            return Err(VaultError::DataKeyMissing { epoch: epoch.get() }.into());
        }
        if epoch.get() > self.current.get() {
            self.current = epoch;
        }
        Ok(())
    }

    /// 已持有的纪元，升序。
    pub fn epochs(&self) -> Vec<u64> {
        self.keys.keys().copied().collect()
    }

    /// 序列化成可以写进安全存储的字节。
    pub fn to_secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        let value = Value::Array(vec![
            Value::Uint(KEY_RING_FORMAT_VERSION as u64),
            Value::Uint(self.current.get()),
            Value::Array(
                self.keys
                    .iter()
                    .map(|(epoch, key)| {
                        Value::Array(vec![
                            Value::Uint(*epoch),
                            Value::Bytes(key.expose_bytes().to_vec()),
                        ])
                    })
                    .collect(),
            ),
        ]);
        Zeroizing::new(envsync_domain::cbor::encode(&value))
    }

    /// 从安全存储读回的字节还原。
    pub fn from_secret_bytes(bytes: &[u8]) -> CoreResult<Self> {
        let value = envsync_domain::cbor::decode_canonical(bytes)?;
        let items = value.as_array().map_err(CoreError::Codec)?;
        if items.len() != 3 {
            return Err(CoreError::Codec(CborError::ArityMismatch));
        }
        let format_version = u32::from_value(&items[0])?;
        if format_version != KEY_RING_FORMAT_VERSION {
            return Err(CoreError::Codec(CborError::UnsupportedFormatVersion {
                found: format_version,
                supported: KEY_RING_FORMAT_VERSION,
            }));
        }
        let current = KeyEpoch::new(items[1].as_uint().map_err(CoreError::Codec)?);
        let entries = items[2].as_array().map_err(CoreError::Codec)?;
        if entries.len() > MAX_KEY_EPOCHS {
            return Err(CoreError::Codec(CborError::InvalidValue(format!(
                "密钥环纪元数量 {} 超过上限 {MAX_KEY_EPOCHS}",
                entries.len()
            ))));
        }
        let mut keys = BTreeMap::new();
        for entry in entries {
            let pair = entry.as_array().map_err(CoreError::Codec)?;
            if pair.len() != 2 {
                return Err(CoreError::Codec(CborError::ArityMismatch));
            }
            let epoch = pair[0].as_uint().map_err(CoreError::Codec)?;
            let raw = Zeroizing::new(pair[1].as_bytes().map_err(CoreError::Codec)?.to_vec());
            keys.insert(epoch, DataKey::from_slice(&raw)?);
        }
        if keys.is_empty() {
            return Err(CoreError::Codec(CborError::InvalidValue(
                "密钥环为空".to_owned(),
            )));
        }
        Ok(KeyRing { current, keys })
    }
}

// ---------------------------------------------------------------------------
// 服务
// ---------------------------------------------------------------------------

/// 按配置打开后端。
///
/// 与 [`crate::service::EnvSyncService::open`] 用的是同一套映射，但**不做**「联系不上
/// 就降级为离线占位」那一步：Vault 的每一个操作都要读写后端，给它一个只会报错的占位
/// 后端只会把失败推迟到更难懂的位置。
pub fn open_backend(config: &crate::config::BackendConfig) -> CoreResult<Arc<dyn Backend>> {
    Ok(match config {
        crate::config::BackendConfig::Local { path } => {
            Arc::new(envsync_backend::LocalBackend::open(path.clone())?)
        }
        crate::config::BackendConfig::Git {
            remote_url,
            branch,
            cache_dir,
            auth,
        } => {
            let git = envsync_backend::GitConfig::new(
                remote_url.clone(),
                cache_dir.clone(),
                auth.clone(),
            )
            .with_branch(branch.clone());
            Arc::new(envsync_backend::GitBackend::open(git)?)
        }
    })
}

/// 打开 [`VaultService`] 所需的协作者。
///
/// 用一个结构体而不是十个位置参数：这些依赖会一起被测试替换，逐个列在签名里既容易
/// 传错顺序，也让「production 用哪套、测试用哪套」难以一眼看清。
pub struct VaultDeps {
    /// 工作区标识。
    pub workspace: WorkspaceId,
    /// 不受信任的后端。
    pub backend: Arc<dyn Backend>,
    /// 系统安全存储。
    ///
    /// 生产路径必须来自 [`envsync_platform::secure_store::open_system_store`]；
    /// 不可用时**安全失败**，绝不写明文 fallback。
    pub secure: Arc<dyn SecureStore>,
    /// 反回滚检查点存储。
    pub checkpoints: Arc<dyn CheckpointStore>,
    /// 时钟。
    pub clock: Arc<dyn Clock>,
}

/// Vault application service。
///
/// 生命周期：[`VaultService::open`] 之后要么是「已初始化」（后端上有 genesis 与索引），
/// 要么是「空工作区」（只能 [`VaultService::create`] 或 `device join`）。所有写操作都
/// 走同一条发布流水线，见模块文档的发布顺序。
pub struct VaultService {
    workspace: WorkspaceId,
    device: DeviceKeypair,
    backend: Arc<dyn Backend>,
    secure: Arc<dyn SecureStore>,
    checkpoints: Arc<dyn CheckpointStore>,
    clock: Arc<dyn Clock>,
    drafts: DraftStore,
    rotations: RotationJournal,
    /// genesis 事件；`None` 表示工作区尚未初始化。
    genesis: Option<MembershipEvent>,
    /// genesis 之后的全部事件，按 sequence 升序。
    events: Vec<MembershipEvent>,
    /// 已验证的成员状态。
    state: Option<MembershipState>,
    /// 当前索引。
    index: VaultIndex,
    /// 后端当前 Ref。
    head: WorkspaceRef,
    /// 已经在读取时重加密、但索引还没更新的秘密。见 [`VaultService::flush_rewraps`]。
    pending_rewrap: RefCell<BTreeMap<SecretId, (ObjectId, u64)>>,
}

impl VaultService {
    /// 打开服务。
    ///
    /// `state_dir` 用来存放本地草稿库与轮换 journal；不存在时创建。设备身份必须已经
    /// 在安全存储里（`envsync device init` 负责建立），否则返回
    /// [`VaultError::DeviceIdentityMissing`]。
    pub fn open(deps: VaultDeps, state_dir: &Path) -> CoreResult<Self> {
        std::fs::create_dir_all(state_dir)
            .map_err(|error| envsync_platform::PlatformError::io("创建状态目录", &error))?;
        let device = crate::device_admin::load_device(deps.secure.as_ref(), deps.workspace)?
            .ok_or(VaultError::DeviceIdentityMissing)?;
        Self::open_with_device(deps, state_dir, device)
    }

    /// 用一个已经在手的设备身份打开服务。
    ///
    /// `device join` 会先在本机生成身份、再打开服务，因此需要这条不回安全存储再读一次
    /// 的入口。
    pub fn open_with_device(
        deps: VaultDeps,
        state_dir: &Path,
        device: DeviceKeypair,
    ) -> CoreResult<Self> {
        std::fs::create_dir_all(state_dir)
            .map_err(|error| envsync_platform::PlatformError::io("创建状态目录", &error))?;
        let drafts = DraftStore::open(state_dir)?;
        let rotations = RotationJournal::open(state_dir.join("rotation.db"))?;
        let mut service = VaultService {
            workspace: deps.workspace,
            device,
            backend: deps.backend,
            secure: deps.secure,
            checkpoints: deps.checkpoints,
            clock: deps.clock,
            drafts,
            rotations,
            genesis: None,
            events: Vec::new(),
            state: None,
            index: VaultIndex::empty(deps.workspace, envsync_domain::GENESIS_EPOCH),
            head: WorkspaceRef::initial(deps.workspace),
            pending_rewrap: RefCell::new(BTreeMap::new()),
        };
        service.reload()?;
        Ok(service)
    }

    /// 本设备标识。
    pub fn device_id(&self) -> DeviceId {
        self.device.device_id()
    }

    /// 本设备公开材料。
    pub fn device_public(&self) -> DevicePublic {
        self.device.public()
    }

    /// 工作区标识。
    pub fn workspace(&self) -> WorkspaceId {
        self.workspace
    }

    /// 后端当前 Ref。
    pub fn head(&self) -> &WorkspaceRef {
        &self.head
    }

    /// 当前索引（只读）。
    pub fn index(&self) -> &VaultIndex {
        &self.index
    }

    /// 已验证的成员状态；工作区尚未初始化时返回 [`VaultError::NotInitialized`]。
    pub fn membership(&self) -> CoreResult<&MembershipState> {
        self.state.as_ref().ok_or(VaultError::NotInitialized.into())
    }

    /// genesis 事件对象标识；工作区尚未初始化时为 `None`。
    pub fn genesis_object(&self) -> Option<ObjectId> {
        self.genesis.as_ref().map(membership_object_id)
    }

    /// 是否已经初始化。
    pub fn is_initialized(&self) -> bool {
        self.genesis.is_some()
    }

    /// 本地轮换 journal。
    pub fn rotations(&self) -> &RotationJournal {
        &self.rotations
    }

    /// 当前反回滚检查点。
    pub fn checkpoint(&self) -> CoreResult<Option<Checkpoint>> {
        Ok(self.checkpoints.load(self.workspace)?)
    }

    // -- 生命周期 ----------------------------------------------------------

    /// 建立工作区：生成数据密钥、写 genesis 成员事件、给自己发一份信封。
    ///
    /// 本设备成为唯一管理员。重复调用返回 [`VaultError::AlreadyInitialized`]——重新
    /// 创建会产生第二个 genesis，也就是第二条互不相认的信任根。
    pub fn create(&mut self) -> CoreResult<()> {
        if self.is_initialized() {
            return Err(VaultError::AlreadyInitialized.into());
        }
        let now = self.clock.now_unix_ms();
        let epoch = KeyEpoch::INITIAL;

        // 数据密钥先落安全存储：先发布再存密钥的话，进程崩在中间就会留下一个谁也解不开
        // 的工作区。
        let ring = KeyRing::new(epoch, DataKey::generate()?);
        self.store_keyring(&ring)?;

        let genesis = membership::create_genesis(&self.device, self.workspace, now)?;
        let genesis_object = self.put_membership_event(&genesis)?;
        let envelope = self.publish_envelope(&self.device.public(), epoch, ring.current_key()?)?;

        let mut index = VaultIndex::empty(self.workspace, epoch.get());
        index.membership.push(genesis_object);
        index.envelopes.push(envelope);

        let state = membership::verify_membership_chain(&genesis, &[], self.workspace)?;
        self.genesis = Some(genesis);
        self.events.clear();
        self.state = Some(state);
        self.publish(index)?;
        Ok(())
    }

    /// 重新从后端读取 Ref、索引与成员链，并重新验证。
    ///
    /// 任何依赖「后端现在是什么样」的判断都必须先调用它；服务不缓存跨命令的状态。
    ///
    /// # 读路径也查反回滚检查点
    ///
    /// M2 早期只在 [`VaultService::publish`] 里推进检查点，读路径一次都不查。后果是后端
    /// 被回退之后 `vault get` / `vault list` / `device list` 会**安静地**返回旧状态——
    /// 已撤销的设备重新出现在成员名单里，新纪元里写的秘密凭空消失，而用户看不到任何异常，
    /// 只有下一次**写**才会撞上检查点。
    ///
    /// 现在这里做一次**只读**校验（[`crate::checkpoint::guard`]）：远端头相对本地检查点
    /// 一旦倒退或分叉就立刻失败（`CoreError::is_rollback_attack()` 为真，CLI 退出码 14）。
    /// **不推进**检查点——推进是发布成功之后的事，读一眼远端不该改变本机的信任根。
    pub fn reload(&mut self) -> CoreResult<()> {
        self.pending_rewrap.borrow_mut().clear();
        self.head = self.read_ref()?;
        let Some(head) = self.head.head else {
            self.forget_vault();
            return Ok(());
        };
        let body = self.load_snapshot(head)?;
        let observed = inspect_vault_head(self.workspace, &body, &mut |id| self.read_object(id))?;
        let Some(observed) = observed else {
            // 头快照来自非 Vault 的发布路径（例如 M0 的 `sync`）：工作区存在，但还没有
            // Vault。这不是错误，只是「还没创建」——而「本来有、现在没了」由
            // [`VaultService::vault_index_missing`] 单独识别并上报。
            self.forget_vault();
            return Ok(());
        };
        crate::checkpoint::guard(
            self.checkpoints.as_ref(),
            &observed.checkpoint(self.workspace, &self.head),
        )?;

        self.genesis = Some(observed.genesis);
        self.events = observed.events;
        self.state = Some(observed.state);
        self.index = observed.index;
        Ok(())
    }

    /// 把本机缓存的 Vault 状态清空（工作区还没有 Vault，或头快照上没有指针）。
    fn forget_vault(&mut self) {
        self.genesis = None;
        self.events.clear();
        self.state = None;
        self.index = VaultIndex::empty(self.workspace, envsync_domain::GENESIS_EPOCH);
    }

    /// 「本工作区本来有 Vault，当前头快照上却没有索引指针」。
    ///
    /// 判据是**本机**的两份证据，而不是后端说了什么：
    ///
    /// * 安全存储里有本工作区的密钥环——只有加入过 Vault 才会有；
    /// * 或者本机已经建立过反回滚检查点——只有 `vault create` / `device join` 会建立。
    ///
    /// 两者都拿不到时返回 `false`：一个从来没建过 Vault 的工作区，头快照上当然没有指针，
    /// 那不是异常。
    ///
    /// 存在的理由：普通同步继承工作区级元数据之前，一次 `envsync sync` 会把索引指针抹掉，
    /// 而 `vault list` 只会安静地返回一个空清单。即便继承已经修好，后端仍然可以单独把
    /// 指针拿掉——那时用户必须被告知，而不是看到一个空 Vault。
    pub fn vault_index_missing(&self) -> CoreResult<bool> {
        if self.is_initialized() {
            return Ok(false);
        }
        if self.load_keyring().is_ok() {
            return Ok(true);
        }
        Ok(self.checkpoints.load(self.workspace)?.is_some())
    }

    // -- 秘密 --------------------------------------------------------------

    /// 写入（或覆盖）一条秘密。
    ///
    /// 已有的 `referenced_by` 会被保留：引用关系由配置决定，`vault set` 只换值。
    pub fn set(&mut self, id: &SecretId, value: SecretInput) -> CoreResult<()> {
        let referenced_by = self
            .index
            .find(id)
            .map(|entry| entry.referenced_by.clone())
            .unwrap_or_default();
        self.set_with_references(id, value, referenced_by)
    }

    /// 写入一条秘密并显式指定引用它的资源。
    pub fn set_with_references(
        &mut self,
        id: &SecretId,
        value: SecretInput,
        mut referenced_by: Vec<ResourceId>,
    ) -> CoreResult<()> {
        self.require_member()?;
        if self.index.find(id).is_none() && self.index.secrets.len() >= MAX_SECRETS {
            return Err(VaultError::TooManySecrets { limit: MAX_SECRETS }.into());
        }
        let ring = self.load_keyring()?;
        let epoch = ring.current_epoch();
        let sealed = seal(
            ring.current_key()?,
            self.workspace,
            id,
            epoch,
            &value.into_plaintext(),
        )?;
        let object = self.put_sealed(&sealed)?;

        referenced_by.sort();
        referenced_by.dedup();
        let mut index = self.take_index_with_rewraps()?;
        index.upsert(SecretRef {
            id: id.clone(),
            object,
            epoch: epoch.get(),
            updated_at_unix_ms: self.clock.now_unix_ms(),
            referenced_by,
        });
        self.publish(index)
    }

    /// 读取一条秘密。
    ///
    /// 若该对象用的是**旧纪元**的密钥，读取成功之后会立刻用当前纪元重新密封并把新对象
    /// 写进后端（lazy rewrap）；索引的更新推迟到下一次写操作或
    /// [`VaultService::flush_rewraps`]——`get` 拿的是 `&self`，不该顺手做一次 CAS 发布。
    pub fn get(&self, id: &SecretId) -> CoreResult<Plaintext> {
        let entry = self
            .index
            .find(id)
            .ok_or_else(|| VaultError::SecretNotFound {
                id: id.as_str().to_owned(),
            })?;
        let sealed = SealedSecret::from_canonical_slice(&self.read_object(entry.object)?)?;
        // 后端可以给我们任意字节。header 必须与我们请求的东西一致，否则就是在拿另一条
        // 秘密冒充这一条。AAD 已经绑定了这些字段，这里的检查只是把失败提前到解密之前。
        if sealed.workspace() != self.workspace || sealed.secret() != id {
            return Err(VaultError::IndexInconsistent {
                detail: "密封对象的 header 与请求的秘密不符",
            }
            .into());
        }
        let ring = self.load_keyring()?;
        let plaintext = open_sealed(ring.key(sealed.epoch())?, &sealed)?;

        if sealed.epoch().get() < ring.current_epoch().get() {
            let current = ring.current_epoch();
            let resealed = seal(ring.current_key()?, self.workspace, id, current, &plaintext)?;
            let object = self.put_sealed(&resealed)?;
            self.pending_rewrap
                .borrow_mut()
                .insert(id.clone(), (object, current.get()));
            tracing::debug!(
                secret = %id,
                from_epoch = sealed.epoch().get(),
                to_epoch = current.get(),
                "旧纪元秘密已按 lazy rewrap 重新密封，等待索引更新"
            );
        }
        Ok(plaintext)
    }

    /// 列出全部秘密的**元数据**。
    ///
    /// 刻意不提供「列出并解密」的批量入口：那会让一次误操作把整个 vault 的明文倒进
    /// 某个日志里。
    pub fn list(&self) -> CoreResult<Vec<SecretMetadata>> {
        Ok(self
            .index
            .secrets
            .iter()
            .map(SecretMetadata::from)
            .collect())
    }

    /// 删除一条秘密，返回它是否存在过。
    ///
    /// 只从索引里摘掉引用：后端上的密封对象是不可变的，由 GC 负责回收。已经拿到旧
    /// 快照的人本来就能读到它，假装「删除即销毁」是自欺欺人。
    pub fn delete(&mut self, id: &SecretId) -> CoreResult<bool> {
        self.require_member()?;
        if self.index.find(id).is_none() {
            return Ok(false);
        }
        let mut index = self.take_index_with_rewraps()?;
        let removed = index.remove(id);
        self.publish(index)?;
        Ok(removed)
    }

    /// 把 [`VaultService::get`] 期间产生的 lazy rewrap 结果写进索引并发布。
    ///
    /// 返回实际更新的条数。没有待更新项时不做任何后端写入。
    pub fn flush_rewraps(&mut self) -> CoreResult<usize> {
        let pending = self.pending_rewrap.borrow().len();
        if pending == 0 {
            return Ok(0);
        }
        let index = self.take_index_with_rewraps()?;
        self.publish(index)?;
        Ok(pending)
    }

    /// 把待更新的 lazy rewrap 结果合并进索引副本。
    fn take_index_with_rewraps(&mut self) -> CoreResult<VaultIndex> {
        let mut index = self.index.clone();
        for (id, (object, epoch)) in self.pending_rewrap.borrow_mut().iter() {
            if let Some(entry) = index.secrets.iter_mut().find(|item| &item.id == id) {
                entry.object = *object;
                entry.epoch = *epoch;
            }
        }
        self.pending_rewrap.borrow_mut().clear();
        Ok(index)
    }

    // -- 密钥环 ------------------------------------------------------------

    /// 从安全存储读回密钥环。
    ///
    /// 「读不到」与「没有」在这里是两件事：[`SecureStore::get`] 的 `Err` 一路上抛，
    /// 只有 `Ok(None)` 才被翻译成 [`VaultError::DataKeyMissing`]。把读取失败当成
    /// 「还没初始化」会让上层生成一把新密钥并覆盖旧的。
    pub fn load_keyring(&self) -> CoreResult<KeyRing> {
        let key = SecureKey::workspace_scoped(self.workspace, SecurePurpose::WorkspaceDataKey);
        match self.secure.get(&key)? {
            Some(bytes) => KeyRing::from_secret_bytes(bytes.expose()),
            None => Err(VaultError::DataKeyMissing {
                epoch: self.index.epoch,
            }
            .into()),
        }
    }

    /// 把密钥环写回安全存储。
    pub fn store_keyring(&self, ring: &KeyRing) -> CoreResult<()> {
        let key = SecureKey::workspace_scoped(self.workspace, SecurePurpose::WorkspaceDataKey);
        let bytes = ring.to_secret_bytes();
        self.secure.put(&key, &bytes)?;
        Ok(())
    }

    // -- 后端读写 ----------------------------------------------------------

    /// 读取后端 Ref；从未发布过时返回初始 Ref。
    fn read_ref(&self) -> CoreResult<WorkspaceRef> {
        match self.backend.get_ref(self.workspace) {
            Ok(reference) => Ok(reference),
            Err(BackendError::RefNotFound(_)) => Ok(WorkspaceRef::initial(self.workspace)),
            Err(error) => Err(error.into()),
        }
    }

    /// 读取对象：优先本地草稿库，未命中再回后端并回填缓存。
    pub(crate) fn read_object(&self, id: ObjectId) -> CoreResult<Vec<u8>> {
        if let Some(bytes) = self.drafts.get(id)? {
            return Ok(bytes);
        }
        let bytes = self.backend.get_object(id)?;
        self.drafts.put(id, &bytes)?;
        Ok(bytes)
    }

    /// 写对象：后端与本地缓存各写一份。
    pub(crate) fn write_object(&self, id: ObjectId, bytes: &[u8]) -> CoreResult<()> {
        self.backend.put_object(id, bytes)?;
        self.drafts.put(id, bytes)?;
        Ok(())
    }

    /// 写一条成员事件对象。
    pub(crate) fn put_membership_event(&self, event: &MembershipEvent) -> CoreResult<ObjectId> {
        let bytes = event.to_canonical_vec();
        let id = membership_object_id(event);
        self.write_object(id, &bytes)?;
        Ok(id)
    }

    /// 写一个密封秘密对象。
    fn put_sealed(&self, sealed: &SealedSecret) -> CoreResult<ObjectId> {
        let bytes = sealed.to_canonical_vec();
        let id = ObjectId::for_bytes(ObjectKind::SealedSecret, &bytes);
        self.write_object(id, &bytes)?;
        Ok(id)
    }

    /// 为一台设备封装并发布当前纪元的数据密钥信封。
    pub(crate) fn publish_envelope(
        &self,
        recipient: &DevicePublic,
        epoch: KeyEpoch,
        key: &DataKey,
    ) -> CoreResult<ObjectId> {
        let envelope = seal_envelope(recipient, self.workspace, epoch, key)?;
        let bytes = envelope.to_canonical_vec();
        let id = ObjectId::for_bytes(ObjectKind::KeyEnvelope, &bytes);
        self.write_object(id, &bytes)?;
        Ok(id)
    }

    /// 在索引里找到发给本设备的信封并打开它，把数据密钥放进密钥环。
    ///
    /// `device join` 与轮换之后的「拿到新纪元密钥」都走这里。
    pub fn adopt_envelope(&self) -> CoreResult<KeyEpoch> {
        let epoch = KeyEpoch::new(self.index.epoch);
        let me = self.device.device_id();
        for object in &self.index.envelopes {
            let envelope = KeyEnvelope::from_canonical_slice(&self.read_object(*object)?)?;
            if envelope.recipient() != me || envelope.epoch() != epoch {
                continue;
            }
            let key = open_envelope(&self.device, &envelope)?;
            let mut ring = match self.load_keyring() {
                Ok(ring) => ring,
                // 首次加入：本机还没有密钥环，用这把密钥建一个。
                Err(CoreError::Vault(VaultError::DataKeyMissing { .. })) => {
                    let ring = KeyRing::new(epoch, key);
                    self.store_keyring(&ring)?;
                    return Ok(epoch);
                }
                Err(error) => return Err(error),
            };
            ring.insert(epoch, key);
            ring.promote(epoch)?;
            self.store_keyring(&ring)?;
            return Ok(epoch);
        }
        Err(VaultError::DataKeyMissing { epoch: epoch.get() }.into())
    }

    /// 读取一个快照主体。
    fn load_snapshot(&self, id: SnapshotId) -> CoreResult<SnapshotBody> {
        Ok(SnapshotBody::from_canonical_slice(
            &self.read_object(ObjectId::from(id))?,
        )?)
    }

    /// 发布一份新索引：写对象 → 只读反回滚校验 → 写快照 → CAS → 推进检查点。
    ///
    /// 幂等：若新快照与后端当前头完全相同，跳过 CAS 与检查点推进。
    ///
    /// # 校验在 CAS **之前**，推进在 CAS **之后**
    ///
    /// 这两句话不矛盾，它们说的是两件事：
    ///
    /// * **校验**（这个头是不是回滚过的）必须在 CAS 之前。M2 早期只在 CAS 之后推进检查点，
    ///   于是被骗的客户端会**先**把新头 CAS 上去、再发现自己接受的是一个回滚过的头——
    ///   后端的 revision 已经被推进了一格，攻击留下了既成事实。
    /// * **推进**（把新高水位线写进安全存储）必须在 CAS 之后。反过来的话，进程崩在两步
    ///   之间就会让本机拒绝自己刚刚试图发布的那个 revision，形成死结。
    pub(crate) fn publish(&mut self, index: VaultIndex) -> CoreResult<()> {
        let index_bytes = index.to_canonical_vec();
        let index_id = ObjectId::for_bytes(ObjectKind::Blob, &index_bytes);
        self.write_object(index_id, &index_bytes)?;

        let current = self.read_ref()?;
        // 沿用当前头的 State Root 与元数据：Vault 的发布**只换 vault 索引这一项**，
        // 不能把 M0/M1 的 `sync` 刚发上去的文件同步内容顺手抹掉。
        let (state_root, parents, mut metadata): (_, Vec<SnapshotId>, BTreeMap<String, String>) =
            match current.head {
                Some(head) => {
                    let body = self.load_snapshot(head)?;
                    // CAS 之前的最后一道闸门：确认我们正要在上面盖章的这个头，相对本机
                    // 检查点确实是前进而不是回退。用**后端当前头**重新推导，而不是用
                    // `self.state`——`invite` / `revoke` 在调用本方法之前已经把内存里的
                    // 成员状态推进了一格，拿它去比会把正常发布误判成分叉。
                    if let Some(observed) =
                        inspect_vault_head(self.workspace, &body, &mut |id| self.read_object(id))?
                    {
                        crate::checkpoint::guard(
                            self.checkpoints.as_ref(),
                            &observed.checkpoint(self.workspace, &current),
                        )?;
                    }
                    (body.state_root, vec![head], body.metadata)
                }
                None => {
                    // 空工作区：发布一个空 State Root，让快照结构保持完整。
                    let state = StateRoot::empty();
                    let bytes = state.to_canonical_vec();
                    self.write_object(ObjectId::from(state.id()), &bytes)?;
                    (state.id(), Vec::new(), BTreeMap::new())
                }
            };
        metadata.insert(VAULT_INDEX_METADATA_KEY.to_owned(), index_id.to_string());
        metadata.insert(
            VAULT_ATTESTATION_METADATA_KEY.to_owned(),
            crate::attestation::sign_index_attestation(&self.device, self.workspace, index_id)?,
        );

        let body = SnapshotBody::new(
            self.workspace,
            parents,
            state_root,
            self.device.device_id(),
            self.clock.now_unix_ms(),
            metadata,
        )
        .map_err(|error| CoreError::Domain(error.to_string()))?;
        let snapshot = body.id();

        if current.head == Some(snapshot) {
            // 内容没变（例如重放一次幂等恢复），不必推进 revision。
            self.index = index;
            self.head = current;
            return Ok(());
        }

        let body_bytes = body.to_canonical_vec();
        self.write_object(ObjectId::from(snapshot), &body_bytes)?;
        self.publish_snapshot_signature(snapshot)?;

        let next = current.advance(snapshot);
        self.backend
            .compare_and_swap_ref(self.workspace, current.revision, &next)?;

        let state = self.membership()?;
        advance_checkpoint(
            self.checkpoints.as_ref(),
            &Checkpoint {
                workspace: self.workspace,
                revision: next.revision,
                snapshot,
                membership_digest: state.head,
                membership_sequence: state.sequence,
                key_epoch: state.epoch,
                updated_at_unix_ms: self.clock.now_unix_ms(),
            },
        )?;

        self.index = index;
        self.head = next;
        Ok(())
    }

    /// 用本设备的 Ed25519 私钥给快照签名并发布签名对象。
    ///
    /// # 这是**审计对象**，不是读路径上的凭据
    ///
    /// 它覆盖快照标识，因此能证明「某台设备确实发布过这个快照」，适合事后取证与 GC 判断
    /// 归属。但它在读路径上**不可定位**：对象是内容寻址的，标识等于签名字节的摘要，而
    /// 读者手里没有签名字节；把标识写回快照元数据又会改变快照标识本身，形成循环。
    ///
    /// 读路径真正校验的是 [`VAULT_ATTESTATION_METADATA_KEY`] 上的索引背书，理由见
    /// [`crate::attestation`] 的模块文档。
    fn publish_snapshot_signature(&self, snapshot: SnapshotId) -> CoreResult<()> {
        let signature = self.device.sign(
            SNAPSHOT_SIGNATURE_DOMAIN,
            self.workspace,
            snapshot.to_hex().as_bytes(),
        )?;
        let object = SnapshotSignature {
            format_version: envsync_domain::SIGNATURE_FORMAT_VERSION,
            snapshot,
            device: self.device.device_id(),
            algorithm: "ed25519".to_owned(),
            signature: signature.as_bytes().to_vec(),
        };
        let bytes = object.to_canonical_vec();
        self.write_object(
            ObjectId::for_bytes(ObjectKind::SnapshotSignature, &bytes),
            &bytes,
        )
    }

    // -- 授权 --------------------------------------------------------------

    /// 要求本设备当前是成员。
    pub(crate) fn require_member(&self) -> CoreResult<()> {
        let state = self.membership()?;
        if !state.contains(&self.device.device_id()) {
            return Err(VaultError::NotAMember.into());
        }
        Ok(())
    }

    /// 要求本设备当前是管理员。
    pub(crate) fn require_admin(&self) -> CoreResult<()> {
        let state = self.membership()?;
        if !state.is_admin(&self.device.device_id()) {
            return Err(VaultError::AdminRequired.into());
        }
        Ok(())
    }

    /// 内部：签名用的设备句柄。
    pub(crate) fn keypair(&self) -> &DeviceKeypair {
        &self.device
    }

    /// 内部：追加一条已验证的成员事件到本地缓存。
    pub(crate) fn record_event(&mut self, event: MembershipEvent, state: MembershipState) {
        self.events.push(event);
        self.state = Some(state);
    }

    /// 内部：当前链上全部事件（genesis 之后）。
    pub(crate) fn events(&self) -> &[MembershipEvent] {
        &self.events
    }

    /// 内部：genesis 事件。
    pub(crate) fn genesis(&self) -> CoreResult<&MembershipEvent> {
        self.genesis
            .as_ref()
            .ok_or(VaultError::NotInitialized.into())
    }

    /// 内部：判断一批对象是否都已经在后端上。
    pub(crate) fn objects_present(&self, ids: &[ObjectId]) -> CoreResult<bool> {
        for id in ids {
            if !self.backend.has_object(*id)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// 内部：把索引里除某台设备之外的成员公钥收集出来。
    pub(crate) fn recipients_except(&self, excluded: DeviceId) -> CoreResult<Vec<DeviceId>> {
        let state = self.membership()?;
        Ok(state
            .members
            .keys()
            .copied()
            .filter(|device| *device != excluded)
            .collect())
    }

    /// 内部：查设备公开材料。
    pub(crate) fn member_public(&self, device: DeviceId) -> CoreResult<DevicePublic> {
        let state = self.membership()?;
        let record = state
            .member(&device)
            .ok_or(VaultError::NotAMemberDevice { device })?;
        Ok(DevicePublic {
            x25519: record.public.x25519(),
            ed25519: record.public.ed25519(),
        })
    }

    /// 内部：当前索引的可变副本。
    pub(crate) fn index_clone(&self) -> VaultIndex {
        self.index.clone()
    }

    /// 内部：尚未重加密到当前纪元的秘密逻辑标识。
    pub(crate) fn stale_secret_ids(&self, epoch: u64) -> Vec<String> {
        self.index
            .secrets
            .iter()
            .filter(|entry| entry.epoch < epoch)
            .map(|entry| entry.id.as_str().to_owned())
            .collect()
    }

    /// 内部：安全存储。
    pub(crate) fn secure(&self) -> &dyn SecureStore {
        self.secure.as_ref()
    }

    /// 内部：时钟。
    pub(crate) fn clock(&self) -> &dyn Clock {
        self.clock.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 取出失败结果里的错误。
    ///
    /// 不能用 `unwrap_err`：它要求 `T: Debug`，而 `SecretInput` **刻意不实现**
    /// `Debug`。这个小函数的存在本身就是那条约束仍然成立的证据。
    fn err<T>(result: CoreResult<T>) -> CoreError {
        match result {
            Ok(_) => panic!("期望失败，实际却成功了"),
            Err(error) => error,
        }
    }

    #[test]
    fn secret_input_strips_at_most_one_trailing_newline() {
        let input = SecretInput::from_reader(&mut &b"value\n"[..]).expect("读取");
        assert_eq!(input.len(), 5);
        let input = SecretInput::from_reader(&mut &b"value\r\n"[..]).expect("读取");
        assert_eq!(input.len(), 5);
        // 第二个换行属于秘密内容，不能被顺手吃掉。
        let input = SecretInput::from_reader(&mut &b"value\n\n"[..]).expect("读取");
        assert_eq!(input.len(), 6);
    }

    #[test]
    fn secret_input_rejects_empty_value() {
        let error = err(SecretInput::from_reader(&mut &b""[..]));
        assert_eq!(error.code(), "vault.empty_value");
        let error = err(SecretInput::from_reader(&mut &b"\n"[..]));
        assert_eq!(error.code(), "vault.empty_value");
    }

    #[test]
    fn secret_input_rejects_over_limit_value_without_retaining_the_buffer() {
        let oversized = vec![b'x'; MAX_PLAINTEXT_LEN + 1];
        let error = err(SecretInput::from_reader(&mut oversized.as_slice()));
        assert_eq!(error.code(), "vault.value_too_large");
    }

    #[test]
    fn secret_input_from_env_reports_the_name_not_the_value() {
        let error = err(SecretInput::from_env_var(
            "ENVSYNC_DEFINITELY_UNSET_VARIABLE",
        ));
        assert_eq!(error.code(), "vault.env_var_missing");
        assert!(error
            .to_string()
            .contains("ENVSYNC_DEFINITELY_UNSET_VARIABLE"));
    }

    #[test]
    fn key_ring_round_trips_and_keeps_the_first_key_for_an_epoch() {
        let mut ring = KeyRing::new(KeyEpoch::INITIAL, DataKey::from_bytes([7u8; 32]));
        ring.insert(KeyEpoch::new(2), DataKey::from_bytes([9u8; 32]));
        // 幂等恢复的基础：同一个纪元第二次插入不覆盖。
        ring.insert(KeyEpoch::new(2), DataKey::from_bytes([1u8; 32]));
        ring.promote(KeyEpoch::new(2)).expect("推进纪元");

        let bytes = ring.to_secret_bytes();
        let restored = KeyRing::from_secret_bytes(&bytes).expect("还原");
        assert_eq!(restored.current_epoch().get(), 2);
        assert_eq!(restored.epochs(), vec![1, 2]);
        // `DataKey` 不实现 `Debug`，因此只能用常量时间比较判等，不能用 `assert_eq!`。
        assert!(
            restored.key(KeyEpoch::new(2)).expect("密钥") == &DataKey::from_bytes([9u8; 32]),
            "同一纪元第二次插入不应覆盖第一把密钥"
        );
    }

    #[test]
    fn key_ring_refuses_to_promote_an_epoch_it_has_no_key_for() {
        let mut ring = KeyRing::new(KeyEpoch::INITIAL, DataKey::from_bytes([7u8; 32]));
        let error = ring.promote(KeyEpoch::new(5)).unwrap_err();
        assert_eq!(error.code(), "vault.data_key_missing");
    }

    #[test]
    fn vault_errors_never_carry_a_value() {
        // 逐个变体过一遍 Display：出现的只能是逻辑标识、纪元、上限这些公开元数据。
        let cases = [
            VaultError::NotInitialized,
            VaultError::AlreadyInitialized,
            VaultError::SecretNotFound {
                id: "ci/npm-token".to_owned(),
            },
            VaultError::EmptyValue,
            VaultError::ValueTooLarge { limit: 1 },
            VaultError::EnvVarMissing {
                name: "GITHUB_TOKEN".to_owned(),
            },
            VaultError::DataKeyMissing { epoch: 2 },
            VaultError::NotAMember,
            VaultError::AdminRequired,
            VaultError::HiddenInputUnavailable,
            VaultError::NonTtyOutputRefused,
        ];
        for case in cases {
            let text = format!("{case} {case:?}");
            assert!(!text.contains("hunter2"), "错误文本不得携带秘密值");
            assert!(!case.code().is_empty());
        }
    }
}
