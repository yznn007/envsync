//! GitHub Gist 使用的单文件密封 Bundle 线格式。
//!
//! Gist 本身不是不可变对象存储：整个工作区必须放进一个文件，服务端也可能读取文件正文。
//! 因此 v1 先把排序后的对象清单编码为 canonical CBOR，再按 1 MiB 上限分块，复用 M2
//! 的 [`envsync_crypto::sealed::SealedSecret`] 进行密封。外层仅保留 Gist CAS 所需的工作区、
//! revision、head、对象数、密文、摘要和设备签名；资源路径、普通资源正文、Vault Secret ID
//! 与快照 metadata 全部留在密文中。
//!
//! 解包顺序是刻意固定的：编码大小 → canonical 外层 / 版本 / 计数 → bundle 摘要 → 设备
//! 签名 → 分块解密 → 内层对象校验。v1 没有压缩格式，也没有任何解压器，因此不存在把小
//! Gist 扩张为大内存分配的压缩炸弹路径。

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use envsync_crypto::device::{verify, DeviceKeypair, DevicePublic, Signature};
use envsync_crypto::envelope::KeyEnvelope;
use envsync_crypto::sealed::{open, seal, SealedSecret, SecretId};
use envsync_crypto::suite::{DataKey, KeyEpoch, Plaintext, MAX_PLAINTEXT_LEN};
use envsync_crypto::vault::{VaultIndex, VAULT_INDEX_METADATA_KEY};
use envsync_crypto::CryptoError;
use envsync_domain::cbor::{decode_canonical, encode, CborCodec, CborError, Value};
use envsync_domain::{
    DeviceId, Digest32, ObjectId, ObjectKind, SnapshotId, WorkspaceId, WorkspaceRef,
};
use zeroize::Zeroizing;

/// Gist Bundle 的当前线格式版本。
pub const GIST_BUNDLE_FORMAT_VERSION: u32 = 1;
/// 单个 Gist 文件编码后的最大大小（5 MiB）。
pub const MAX_ENCODED_BUNDLE_LEN: usize = 5 * 1024 * 1024;
/// 单个 Bundle 可携带的对象记录上限。
///
/// Gist 是小规模同步后端；这个上限也限制了解包前能处理的密文目录大小。每条资源会贡献
/// 若干对象，因此它与资源条目上限分开计算。
pub const MAX_OBJECTS: usize = 512;
/// 一个已解密 State Root 中允许的资源条目上限。
pub const MAX_RESOURCES: usize = 256;

/// 编码后的 5 MiB 在无 padding Base64URL 下可能解出的最大字节数。
const MAX_WIRE_LEN: usize = (MAX_ENCODED_BUNDLE_LEN / 4) * 3;
/// 单个 Bundle 在最大 wire size 下需要的最大密文分块数。
const MAX_CHUNKS: usize = MAX_WIRE_LEN.div_ceil(MAX_PLAINTEXT_LEN);
/// 外层及其摘要使用的域分隔标签。
const BUNDLE_DIGEST_DOMAIN: &str = "envsync:gist-bundle:v1";
/// 设备签名的用途标签。
const BUNDLE_SIGNATURE_DOMAIN: &str = "gist-bundle";
/// 内层明文对象清单格式版本。
const PAYLOAD_FORMAT_VERSION: u32 = 1;
/// 分块 header 伪标识的域分隔标签；它不是用户 Secret ID。
const CHUNK_AAD_DOMAIN: &str = "envsync:gist-chunk-aad:v1";

/// Gist Bundle 的错误。
///
/// 所有错误只描述协议结构或公开标识，不回显远端正文、对象字节或密钥材料。
#[derive(Debug, thiserror::Error)]
pub enum GistBundleError {
    /// 调用方没有完整 M2 数据密钥、纪元或设备签名材料。
    #[error("Gist Bundle 需要已启用的 M2 密钥材料")]
    M2KeysRequired,
    /// 输入不是无 padding 的 Base64URL。
    #[error("Gist Bundle 不是有效的无 padding Base64URL")]
    InvalidEncoding,
    /// 编码或解码后的文件超过 5 MiB 上限。
    #[error("Gist Bundle 编码大小超过 {limit} 字节上限")]
    EncodedTooLarge {
        /// 固定上限。
        limit: usize,
    },
    /// 外层或内层格式版本未知。
    #[error("Gist Bundle 格式版本 {found} 不受支持（仅支持 {supported}）")]
    UnsupportedVersion {
        /// 收到的版本。
        found: u64,
        /// 当前支持的版本。
        supported: u32,
    },
    /// Bundle 声称的对象数量超过上限。
    #[error("Gist Bundle 对象数量 {found} 超过 {limit} 上限")]
    TooManyObjects {
        /// 收到的数量。
        found: u64,
        /// 固定上限。
        limit: usize,
    },
    /// 已解密 State Root 的资源条目超过上限。
    #[error("Gist Bundle 资源数量 {found} 超过 {limit} 上限")]
    TooManyResources {
        /// 收到的资源数量。
        found: usize,
        /// 固定上限。
        limit: usize,
    },
    /// 密文分块为空或数量超过由 wire size 推导的固定上限。
    #[error("Gist Bundle 密文分块数量 {found} 非法")]
    InvalidChunkCount {
        /// 收到的分块数量。
        found: usize,
    },
    /// 对象记录顺序不严格递增。
    #[error("Gist Bundle 对象记录未按标识严格排序")]
    UnsortedObjects,
    /// 一个对象标识出现多次。
    #[error("Gist Bundle 包含重复 Object ID")]
    DuplicateObjectId,
    /// 对象记录的字节不能产生其声明的内容寻址标识。
    #[error("Gist Bundle 对象摘要不匹配")]
    ObjectDigestMismatch,
    /// 当前 Ref 的快照、State Root 或受管 Blob 闭包不完整。
    #[error("Gist Bundle 缺少当前 Ref 所需对象")]
    IncompleteClosure,
    /// 外层引导区包含了非公开允许的对象，或对象本身不能按其公开 schema 解码。
    #[error("Gist Bundle 引导区不合法")]
    InvalidBootstrap,
    /// 引导区与已解密的 head Vault Index 不一致。
    #[error("Gist Bundle 引导区与当前 Vault 状态不一致")]
    BootstrapMismatch,
    /// head Vault Index、当前设备信封与密封 payload 的密钥纪元不一致。
    #[error("Gist Bundle 引导区密钥纪元不匹配")]
    BootstrapEpochMismatch,
    /// Ref 本身不满足领域结构约束。
    #[error("Gist Bundle 的工作区 Ref 非法")]
    InvalidReference,
    /// 内层明文 Ref 与已签名的外层公开元数据不一致。
    #[error("Gist Bundle 内外 Ref 元数据不一致")]
    ReferenceMismatch,
    /// 分块 header 不属于此 Bundle 的工作区、纪元或固定分块标识。
    #[error("Gist Bundle 密文分块 header 不匹配")]
    ChunkHeaderMismatch,
    /// Bundle 所属工作区与本地已注册工作区不一致。
    #[error("Gist Bundle 所属工作区与本地信任上下文不一致")]
    WorkspaceMismatch,
    /// 外层摘要不匹配，解密尚未开始。
    #[error("Gist Bundle 摘要校验失败")]
    DigestMismatch,
    /// 设备公钥、设备标识或签名校验失败，解密尚未开始。
    #[error("Gist Bundle 设备签名校验失败")]
    SignatureInvalid,
    /// 已验签的密文无法通过 AEAD 认证。
    #[error("Gist Bundle 密文认证失败")]
    AuthenticationFailed,
    /// canonical CBOR 结构不合法。
    #[error("Gist Bundle canonical CBOR 不合法：{0}")]
    Codec(#[from] CborError),
    /// M2 密封或签名原语失败。
    #[error("Gist Bundle 密码学操作失败：{0}")]
    Crypto(#[from] CryptoError),
}

impl GistBundleError {
    /// 稳定的机器可读错误码。
    pub fn code(&self) -> &'static str {
        match self {
            GistBundleError::M2KeysRequired => "gist_bundle.m2_keys_required",
            GistBundleError::InvalidEncoding => "gist_bundle.invalid_encoding",
            GistBundleError::EncodedTooLarge { .. } => "gist_bundle.encoded_too_large",
            GistBundleError::UnsupportedVersion { .. } => "gist_bundle.unsupported_version",
            GistBundleError::TooManyObjects { .. } => "gist_bundle.too_many_objects",
            GistBundleError::TooManyResources { .. } => "gist_bundle.too_many_resources",
            GistBundleError::InvalidChunkCount { .. } => "gist_bundle.invalid_chunk_count",
            GistBundleError::UnsortedObjects => "gist_bundle.unsorted_objects",
            GistBundleError::DuplicateObjectId => "gist_bundle.duplicate_object_id",
            GistBundleError::ObjectDigestMismatch => "gist_bundle.object_digest_mismatch",
            GistBundleError::IncompleteClosure => "gist_bundle.incomplete_closure",
            GistBundleError::InvalidBootstrap => "gist_bundle.invalid_bootstrap",
            GistBundleError::BootstrapMismatch => "gist_bundle.bootstrap_mismatch",
            GistBundleError::BootstrapEpochMismatch => "gist_bundle.bootstrap_epoch_mismatch",
            GistBundleError::InvalidReference => "gist_bundle.invalid_reference",
            GistBundleError::ReferenceMismatch => "gist_bundle.reference_mismatch",
            GistBundleError::ChunkHeaderMismatch => "gist_bundle.chunk_header_mismatch",
            GistBundleError::WorkspaceMismatch => "gist_bundle.workspace_mismatch",
            GistBundleError::DigestMismatch => "gist_bundle.digest_mismatch",
            GistBundleError::SignatureInvalid => "gist_bundle.signature_invalid",
            GistBundleError::AuthenticationFailed => "gist_bundle.authentication",
            GistBundleError::Codec(_) => "gist_bundle.codec",
            GistBundleError::Crypto(_) => "gist_bundle.crypto",
        }
    }
}

/// 用于创建 Bundle 的 M2 密钥材料。
///
/// 此类型只借用敏感密钥，既不实现 `Clone`，也不在 `Debug` 中输出任何材料。
pub struct GistBundleSigner<'a> {
    data_key: &'a DataKey,
    epoch: KeyEpoch,
    device: &'a DeviceKeypair,
}

impl fmt::Debug for GistBundleSigner<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GistBundleSigner(<M2 private material>)")
    }
}

impl<'a> GistBundleSigner<'a> {
    /// 从已加载的 M2 状态构造签名器。
    ///
    /// `None` 表示该工作区尚未完成 M2 初始化，因而不能选择 Gist 后端。
    pub fn from_m2(
        data_key: Option<&'a DataKey>,
        epoch: Option<KeyEpoch>,
        device: Option<&'a DeviceKeypair>,
    ) -> Result<Self, GistBundleError> {
        match (data_key, epoch, device) {
            (Some(data_key), Some(epoch), Some(device)) => Ok(GistBundleSigner {
                data_key,
                epoch,
                device,
            }),
            _ => Err(GistBundleError::M2KeysRequired),
        }
    }
}

/// 用于验签和解密 Bundle 的 M2 材料。
pub struct GistBundleVerifier<'a> {
    workspace: WorkspaceId,
    data_key: &'a DataKey,
    epoch: KeyEpoch,
    trusted_signers: BTreeMap<DeviceId, DevicePublic>,
}

impl fmt::Debug for GistBundleVerifier<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GistBundleVerifier")
            .finish_non_exhaustive()
    }
}

impl<'a> GistBundleVerifier<'a> {
    /// 从已验证的 M2 数据密钥、纪元与成员链公钥构造验证器。
    ///
    /// 传入 `None` 会拒绝：没有 M2 身份的工作区不得读取或配置 Gist Bundle。
    pub fn from_m2(
        workspace: Option<WorkspaceId>,
        data_key: Option<&'a DataKey>,
        epoch: Option<KeyEpoch>,
        trusted_signers: Option<BTreeMap<DeviceId, DevicePublic>>,
    ) -> Result<Self, GistBundleError> {
        match (workspace, data_key, epoch, trusted_signers) {
            (Some(workspace), Some(data_key), Some(epoch), Some(trusted_signers))
                if !trusted_signers.is_empty() =>
            {
                Ok(GistBundleVerifier {
                    workspace,
                    data_key,
                    epoch,
                    trusted_signers,
                })
            }
            _ => Err(GistBundleError::M2KeysRequired),
        }
    }
}

/// Bundle 中的一条不可变对象记录。
#[derive(Clone, PartialEq, Eq)]
pub struct GistBundleObject {
    /// 内容寻址对象标识。
    pub id: ObjectId,
    /// 对象的原始字节。
    ///
    /// 常规对象只存在于密封 payload；仅已验证的 `MembershipEvent` 与 `KeyEnvelope` 可以
    /// 出现在外层 bootstrap 中，以便新设备取得当前纪元密钥。
    pub bytes: Vec<u8>,
}

/// 从未验证的外层 Envelope 解析出的路由元数据。
///
/// 该结构仅帮助后端选择本地工作区、成员表和正确的 M2 密钥纪元。调用方在
/// [`unpack`] 成功前不得把任何字段当成受信状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GistBundleHeader {
    /// Bundle 声称所属的工作区。
    pub workspace: WorkspaceId,
    /// Bundle 声称的单调 revision。
    pub revision: u64,
    /// Bundle 声称的当前快照头。
    pub head: Option<SnapshotId>,
    /// 所有密文分块共同声明的 M2 数据密钥纪元。
    pub epoch: KeyEpoch,
    /// Bundle 声称的写入设备；必须在本地成员表中再次验证。
    pub signer: DeviceId,
    /// Bundle 内全部逻辑对象记录的声明数量（含 outer bootstrap）。
    pub object_count: u64,
}

/// 从未验证 Envelope 读取的最小密钥引导区。
///
/// 引导区允许新设备在尚未持有 `DataKey` 时取得成员链和发给自己的 HPKE 信封；它不是
/// 信任根。调用方必须先用邀请中的 genesis 或本地已验证锚点重放成员链，再打开信封，并
/// 在取得密钥后调用 [`unpack`] 验证外层 digest、签名和 AEAD payload。
#[derive(Clone, PartialEq, Eq)]
pub struct GistBundleBootstrap {
    /// Bundle 声称所属的工作区，未验证。
    pub workspace: WorkspaceId,
    /// Bundle 声称的 revision，未验证。
    pub revision: u64,
    /// Bundle 声称的 head，未验证。
    pub head: Option<SnapshotId>,
    /// 当前密封 payload 和信封共同声明的 M2 纪元，未验证。
    pub epoch: KeyEpoch,
    /// Bundle 声称的签名设备，未验证。
    pub signer: DeviceId,
    /// 仅限 `MembershipEvent` 的公开对象记录。
    pub membership: Vec<GistBundleObject>,
    /// 仅限当前纪元 `KeyEnvelope` 的公开对象记录。
    pub envelopes: Vec<GistBundleObject>,
}

impl fmt::Debug for GistBundleBootstrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GistBundleBootstrap(<untrusted>)")
            .field("workspace", &self.workspace)
            .field("revision", &self.revision)
            .field("head", &self.head)
            .field("epoch", &self.epoch)
            .field("signer", &self.signer)
            .field("membership_count", &self.membership.len())
            .field("envelope_count", &self.envelopes.len())
            .finish()
    }
}

impl GistBundleObject {
    /// 构造一条对象记录；[`pack`] 会在写入前重新校验摘要。
    pub fn new(id: ObjectId, bytes: Vec<u8>) -> Self {
        GistBundleObject { id, bytes }
    }
}

impl fmt::Debug for GistBundleObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GistBundleObject")
            .field("id", &self.id)
            .field("bytes", &format_args!("<{} bytes>", self.bytes.len()))
            .finish()
    }
}

/// 成功解包后的受信对象集合。
#[derive(PartialEq, Eq)]
pub struct UnpackedGistBundle {
    /// 已验签、已校验的当前工作区 Ref。
    pub reference: WorkspaceRef,
    /// 写入 Bundle 的已验证设备标识。
    pub signer: DeviceId,
    /// 密封 Bundle 使用的数据密钥纪元。
    pub epoch: KeyEpoch,
    /// 按 [`ObjectId`] 严格递增的对象记录。
    pub objects: Vec<GistBundleObject>,
}

impl fmt::Debug for UnpackedGistBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnpackedGistBundle")
            .field("reference", &self.reference)
            .field("signer", &self.signer)
            .field("epoch", &self.epoch)
            .field("object_count", &self.objects.len())
            .finish()
    }
}

/// 返回工作区唯一且不含路径分隔符的 Gist 文件名。
pub fn gist_bundle_filename(workspace: WorkspaceId) -> String {
    format!("envsync-{workspace}.bundle")
}

/// 只解析 Gist Bundle 外层的未验证路由元数据。
///
/// 这个函数会检查 Base64URL、canonical CBOR、版本、对象数和所有分块的纪元一致性，但
/// 不验证摘要或签名，也不会解密。它的返回值只能用于选择本地的可信成员表和正确密钥，
/// 随后仍必须调用 [`unpack`]。
pub fn inspect(encoded: &str) -> Result<GistBundleHeader, GistBundleError> {
    decode_envelope(encoded)?.header()
}

/// 读取未验证的公开密钥引导区。
///
/// 此函数不需要 `DataKey`，也不验证 digest 或设备签名。它只适用于 core 的设备加入/密钥
/// 轮换引导流程；常规读取仍必须在获得本地可信成员表和 DataKey 后调用 [`unpack`]。
pub fn inspect_bootstrap(encoded: &str) -> Result<GistBundleBootstrap, GistBundleError> {
    decode_envelope(encoded)?.bootstrap_view()
}

/// 仅供协议内部使用的公开 bootstrap 对象集合。
///
/// 两个列表都以 ObjectId 严格升序编码，以保证 bundle 字节稳定；成员链实际的 sequence
/// 顺序由对象内容决定，core 在建立信任时会重新按链规则验证。
#[derive(Clone, Default, PartialEq, Eq)]
struct Bootstrap {
    membership: Vec<GistBundleObject>,
    envelopes: Vec<GistBundleObject>,
}

impl Bootstrap {
    fn from_value(value: &Value) -> Result<Self, GistBundleError> {
        let items = value.as_array()?;
        if items.len() != 2 {
            return Err(CborError::ArityMismatch.into());
        }
        let membership = bootstrap_records(&items[0], ObjectKind::MembershipEvent)?;
        let envelopes = bootstrap_records(&items[1], ObjectKind::KeyEnvelope)?;
        Ok(Bootstrap {
            membership,
            envelopes,
        })
    }

    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Array(self.membership.iter().map(object_to_value).collect()),
            Value::Array(self.envelopes.iter().map(object_to_value).collect()),
        ])
    }

    fn all(&self) -> impl Iterator<Item = &GistBundleObject> {
        self.membership.iter().chain(&self.envelopes)
    }

    fn len(&self) -> usize {
        self.membership.len() + self.envelopes.len()
    }

    fn object_ids(&self) -> BTreeSet<ObjectId> {
        self.all().map(|object| object.id).collect()
    }

    fn validate(&self, workspace: WorkspaceId, epoch: KeyEpoch) -> Result<(), GistBundleError> {
        if self.membership.is_empty() != self.envelopes.is_empty() || self.len() > MAX_OBJECTS {
            return Err(GistBundleError::InvalidBootstrap);
        }
        let mut ids = BTreeSet::new();
        for object in &self.membership {
            if object.id.kind != ObjectKind::MembershipEvent
                || !object.id.verifies(&object.bytes)
                || !ids.insert(object.id)
            {
                return Err(GistBundleError::InvalidBootstrap);
            }
            let event = envsync_domain::MembershipEvent::from_canonical_slice(&object.bytes)
                .map_err(|_| GistBundleError::InvalidBootstrap)?;
            if event.workspace != workspace {
                return Err(GistBundleError::BootstrapMismatch);
            }
        }
        for object in &self.envelopes {
            if object.id.kind != ObjectKind::KeyEnvelope
                || !object.id.verifies(&object.bytes)
                || !ids.insert(object.id)
            {
                return Err(GistBundleError::InvalidBootstrap);
            }
            let envelope = KeyEnvelope::from_canonical_slice(&object.bytes)
                .map_err(|_| GistBundleError::InvalidBootstrap)?;
            if envelope.workspace() != workspace {
                return Err(GistBundleError::BootstrapMismatch);
            }
            if envelope.epoch() != epoch {
                return Err(GistBundleError::BootstrapEpochMismatch);
            }
        }
        Ok(())
    }

    fn view(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        head: Option<SnapshotId>,
        epoch: KeyEpoch,
        signer: DeviceId,
    ) -> GistBundleBootstrap {
        GistBundleBootstrap {
            workspace,
            revision,
            head,
            epoch,
            signer,
            membership: self.membership.clone(),
            envelopes: self.envelopes.clone(),
        }
    }
}

fn bootstrap_records(
    value: &Value,
    expected_kind: ObjectKind,
) -> Result<Vec<GistBundleObject>, GistBundleError> {
    let records = value.as_array()?;
    if records.len() > MAX_OBJECTS {
        return Err(GistBundleError::TooManyObjects {
            found: records.len() as u64,
            limit: MAX_OBJECTS,
        });
    }
    let objects = records
        .iter()
        .map(object_from_value)
        .collect::<Result<Vec<_>, _>>()?;
    if objects.iter().any(|object| object.id.kind != expected_kind) {
        return Err(GistBundleError::InvalidBootstrap);
    }
    validate_strict_object_order(&objects).map_err(|_| GistBundleError::InvalidBootstrap)?;
    Ok(objects)
}

struct PreparedObjects {
    private: Vec<GistBundleObject>,
    bootstrap: Bootstrap,
    total_count: u64,
}

/// 将一个工作区 Ref 及其全部对象打包为无 padding Base64URL 字符串。
///
/// 输入对象会按 ID 排序。每个对象摘要、当前 head 存在性、对象数和原始总长度都在加密
/// 前校验；由此拒绝重复、损坏或无法写入 5 MiB Gist 的输入。
pub fn pack(
    reference: &WorkspaceRef,
    objects: Vec<GistBundleObject>,
    signer: &GistBundleSigner<'_>,
) -> Result<String, GistBundleError> {
    reference
        .validate()
        .map_err(|_| GistBundleError::InvalidReference)?;
    let prepared = prepare_objects(reference, objects, signer.epoch)?;
    let plaintext = Zeroizing::new(
        PlainPayload {
            reference: reference.clone(),
            objects: prepared.private,
        }
        .to_canonical_vec(),
    );
    if plaintext.len() > MAX_WIRE_LEN {
        return Err(GistBundleError::EncodedTooLarge {
            limit: MAX_ENCODED_BUNDLE_LEN,
        });
    }

    let chunk_count = plaintext.len().div_ceil(MAX_PLAINTEXT_LEN);
    let signer_id = signer.device.device_id();
    let chunks = plaintext
        .chunks(MAX_PLAINTEXT_LEN)
        .enumerate()
        .map(|(index, bytes)| {
            let input = Plaintext::from_slice(bytes);
            let secret = chunk_secret_id(
                reference.workspace,
                reference.revision,
                reference.head,
                signer.epoch,
                signer_id,
                index,
                chunk_count,
            )?;
            seal(
                signer.data_key,
                reference.workspace,
                &secret,
                signer.epoch,
                &input,
            )
            .map_err(GistBundleError::Crypto)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let objects = SealedObjects {
        count: prepared.total_count,
        chunks,
    };
    let digest = bundle_digest(
        reference.workspace,
        reference.revision,
        reference.head,
        &objects,
        &prepared.bootstrap,
    );
    let signature = BundleSignature {
        signer: signer_id,
        value: signer
            .device
            .sign(
                BUNDLE_SIGNATURE_DOMAIN,
                reference.workspace,
                &signature_payload(digest, signer_id),
            )
            .map_err(GistBundleError::Crypto)?,
    };
    let envelope = Envelope {
        workspace: reference.workspace,
        revision: reference.revision,
        head: reference.head,
        objects,
        bootstrap: prepared.bootstrap,
        digest,
        signature,
    };
    let encoded = URL_SAFE_NO_PAD.encode(envelope.to_canonical_vec());
    if encoded.len() > MAX_ENCODED_BUNDLE_LEN {
        return Err(GistBundleError::EncodedTooLarge {
            limit: MAX_ENCODED_BUNDLE_LEN,
        });
    }
    Ok(encoded)
}

/// 验证并解开一个无 padding Base64URL Gist Bundle。
///
/// 任何摘要或签名失败都会在触及密文解密前返回错误。
pub fn unpack(
    encoded: &str,
    verifier: &GistBundleVerifier<'_>,
) -> Result<UnpackedGistBundle, GistBundleError> {
    let envelope = decode_envelope(encoded)?;
    if envelope.workspace != verifier.workspace {
        return Err(GistBundleError::WorkspaceMismatch);
    }
    let expected_digest = bundle_digest(
        envelope.workspace,
        envelope.revision,
        envelope.head,
        &envelope.objects,
        &envelope.bootstrap,
    );
    if expected_digest != envelope.digest {
        return Err(GistBundleError::DigestMismatch);
    }
    let Some(trusted_signer) = verifier.trusted_signers.get(&envelope.signature.signer) else {
        return Err(GistBundleError::SignatureInvalid);
    };
    if verify(
        trusted_signer,
        BUNDLE_SIGNATURE_DOMAIN,
        envelope.workspace,
        &signature_payload(envelope.digest, envelope.signature.signer),
        &envelope.signature.value,
    )
    .is_err()
    {
        return Err(GistBundleError::SignatureInvalid);
    }

    let envelope_epoch = envelope.epoch()?;
    if envelope_epoch != verifier.epoch {
        return Err(GistBundleError::ChunkHeaderMismatch);
    }
    envelope
        .bootstrap
        .validate(envelope.workspace, envelope_epoch)?;

    let mut clear = Zeroizing::new(Vec::new());
    for (index, chunk) in envelope.objects.chunks.iter().enumerate() {
        if chunk.workspace() != envelope.workspace
            || chunk.epoch() != verifier.epoch
            || chunk.secret()
                != &chunk_secret_id(
                    envelope.workspace,
                    envelope.revision,
                    envelope.head,
                    verifier.epoch,
                    envelope.signature.signer,
                    index,
                    envelope.objects.chunks.len(),
                )?
        {
            return Err(GistBundleError::ChunkHeaderMismatch);
        }
        let plaintext =
            open(verifier.data_key, chunk).map_err(|_| GistBundleError::AuthenticationFailed)?;
        let next_len =
            clear
                .len()
                .checked_add(plaintext.len())
                .ok_or(GistBundleError::EncodedTooLarge {
                    limit: MAX_ENCODED_BUNDLE_LEN,
                })?;
        if next_len > MAX_WIRE_LEN {
            return Err(GistBundleError::EncodedTooLarge {
                limit: MAX_ENCODED_BUNDLE_LEN,
            });
        }
        clear.extend_from_slice(plaintext.expose());
    }
    let payload = PlainPayload::from_canonical_slice(&clear)?;
    if payload.reference.workspace != envelope.workspace
        || payload.reference.revision != envelope.revision
        || payload.reference.head != envelope.head
    {
        return Err(GistBundleError::ReferenceMismatch);
    }
    let objects = merge_objects(payload.objects, &envelope.bootstrap)?;
    if u64::try_from(objects.len()).ok() != Some(envelope.objects.count) {
        return Err(GistBundleError::ReferenceMismatch);
    }
    let expected_bootstrap = validate_object_closure(&payload.reference, &objects, verifier.epoch)?;
    if expected_bootstrap != envelope.bootstrap {
        return Err(GistBundleError::BootstrapMismatch);
    }
    Ok(UnpackedGistBundle {
        reference: payload.reference,
        signer: envelope.signature.signer,
        epoch: verifier.epoch,
        objects,
    })
}

fn decode_envelope(encoded: &str) -> Result<Envelope, GistBundleError> {
    if encoded.len() > MAX_ENCODED_BUNDLE_LEN {
        return Err(GistBundleError::EncodedTooLarge {
            limit: MAX_ENCODED_BUNDLE_LEN,
        });
    }
    let wire = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|_| GistBundleError::InvalidEncoding)?;
    if wire.len() > MAX_WIRE_LEN {
        return Err(GistBundleError::EncodedTooLarge {
            limit: MAX_ENCODED_BUNDLE_LEN,
        });
    }
    Envelope::from_canonical_slice(&wire)
}

fn prepare_objects(
    reference: &WorkspaceRef,
    mut objects: Vec<GistBundleObject>,
    epoch: KeyEpoch,
) -> Result<PreparedObjects, GistBundleError> {
    if objects.len() > MAX_OBJECTS {
        return Err(GistBundleError::TooManyObjects {
            found: objects.len() as u64,
            limit: MAX_OBJECTS,
        });
    }
    let total_len = objects.iter().try_fold(0usize, |total, object| {
        total.checked_add(object.bytes.len())
    });
    if total_len.is_none_or(|total| total > MAX_WIRE_LEN) {
        return Err(GistBundleError::EncodedTooLarge {
            limit: MAX_ENCODED_BUNDLE_LEN,
        });
    }
    for object in &objects {
        if !object.id.verifies(&object.bytes) {
            return Err(GistBundleError::ObjectDigestMismatch);
        }
    }
    objects.sort_by_key(|object| object.id);
    validate_strict_object_order(&objects)?;
    let bootstrap = validate_object_closure(reference, &objects, epoch)?;
    let bootstrap_ids = bootstrap.object_ids();
    let private = objects
        .into_iter()
        .filter(|object| !bootstrap_ids.contains(&object.id))
        .collect::<Vec<_>>();
    let total_count = u64::try_from(bootstrap_ids.len() + private.len()).map_err(|_| {
        GistBundleError::TooManyObjects {
            found: u64::MAX,
            limit: MAX_OBJECTS,
        }
    })?;
    Ok(PreparedObjects {
        private,
        bootstrap,
        total_count,
    })
}

/// 验证当前 Ref 可达的完整对象闭包，并从 head Vault Index 推导公开 bootstrap。
///
/// 从 head 递归遍历父快照；每个快照都必须携带它的 State Root、受管资源 Blob，以及（若
/// 存在）Vault Index 所列的成员事件、当前信封、密封秘密和恢复包。对象摘要在此之前已经
/// 验证，故“存在”同时保证对象种类和内容寻址标识一致。错误不回显缺失对象的标识，以免
/// 让错误边界成为密文内容的侧信道。
fn validate_object_closure(
    reference: &WorkspaceRef,
    objects: &[GistBundleObject],
    expected_epoch: KeyEpoch,
) -> Result<Bootstrap, GistBundleError> {
    let Some(head) = reference.head else {
        return Ok(Bootstrap::default());
    };

    let by_id = objects
        .iter()
        .map(|object| (object.id, object))
        .collect::<BTreeMap<_, _>>();
    let mut pending = vec![head];
    let mut visited = BTreeSet::new();
    let mut bootstrap = Bootstrap::default();

    while let Some(snapshot_id) = pending.pop() {
        if !visited.insert(snapshot_id) {
            continue;
        }
        let snapshot = by_id
            .get(&ObjectId::from(snapshot_id))
            .ok_or(GistBundleError::IncompleteClosure)?;
        let body = envsync_domain::SnapshotBody::from_canonical_slice(&snapshot.bytes)
            .map_err(|_| GistBundleError::InvalidReference)?;
        if body.workspace != reference.workspace {
            return Err(GistBundleError::ReferenceMismatch);
        }
        let state = by_id
            .get(&ObjectId::from(body.state_root))
            .ok_or(GistBundleError::IncompleteClosure)?;
        let state = envsync_domain::StateRoot::from_canonical_slice(&state.bytes)
            .map_err(|_| GistBundleError::InvalidReference)?;
        if state.len() > MAX_RESOURCES {
            return Err(GistBundleError::TooManyResources {
                found: state.len(),
                limit: MAX_RESOURCES,
            });
        }
        for entry in state.entries.values() {
            if let Some(blob) = entry.blob {
                if !by_id.contains_key(&ObjectId::from(blob)) {
                    return Err(GistBundleError::IncompleteClosure);
                }
            }
        }
        if let Some(raw_index) = body.metadata.get(VAULT_INDEX_METADATA_KEY) {
            let index_id = raw_index
                .parse::<ObjectId>()
                .map_err(|_| GistBundleError::InvalidReference)?;
            let index_object = required_object(&by_id, index_id, ObjectKind::Blob)?;
            let index = VaultIndex::from_canonical_slice(&index_object.bytes)
                .map_err(|_| GistBundleError::InvalidReference)?;
            if index.workspace != reference.workspace {
                return Err(GistBundleError::ReferenceMismatch);
            }
            validate_vault_index_closure(reference.workspace, &index, &by_id)?;
            if snapshot_id == head {
                let index_epoch = KeyEpoch::new(index.epoch);
                if index_epoch != expected_epoch {
                    return Err(GistBundleError::BootstrapEpochMismatch);
                }
                bootstrap = bootstrap_from_vault_index(&index, &by_id, index_epoch)?;
            }
        }
        pending.extend(body.parents);
    }
    Ok(bootstrap)
}

fn required_object<'a>(
    by_id: &'a BTreeMap<ObjectId, &'a GistBundleObject>,
    id: ObjectId,
    expected_kind: ObjectKind,
) -> Result<&'a GistBundleObject, GistBundleError> {
    let object = by_id
        .get(&id)
        .copied()
        .ok_or(GistBundleError::IncompleteClosure)?;
    if object.id.kind != expected_kind {
        return Err(GistBundleError::InvalidReference);
    }
    Ok(object)
}

fn validate_vault_index_closure(
    workspace: WorkspaceId,
    index: &VaultIndex,
    by_id: &BTreeMap<ObjectId, &GistBundleObject>,
) -> Result<(), GistBundleError> {
    if index.membership.is_empty() || index.envelopes.is_empty() {
        return Err(GistBundleError::IncompleteClosure);
    }
    let epoch = KeyEpoch::new(index.epoch);
    for id in &index.membership {
        let object = required_object(by_id, *id, ObjectKind::MembershipEvent)?;
        let event = envsync_domain::MembershipEvent::from_canonical_slice(&object.bytes)
            .map_err(|_| GistBundleError::InvalidReference)?;
        if event.workspace != workspace {
            return Err(GistBundleError::ReferenceMismatch);
        }
    }
    for id in &index.envelopes {
        let object = required_object(by_id, *id, ObjectKind::KeyEnvelope)?;
        let envelope = KeyEnvelope::from_canonical_slice(&object.bytes)
            .map_err(|_| GistBundleError::InvalidReference)?;
        if envelope.workspace() != workspace {
            return Err(GistBundleError::ReferenceMismatch);
        }
        if envelope.epoch() != epoch {
            return Err(GistBundleError::BootstrapEpochMismatch);
        }
    }
    for secret in &index.secrets {
        let object = required_object(by_id, secret.object, ObjectKind::SealedSecret)?;
        let sealed = SealedSecret::from_canonical_slice(&object.bytes)
            .map_err(|_| GistBundleError::InvalidReference)?;
        if sealed.workspace() != workspace {
            return Err(GistBundleError::ReferenceMismatch);
        }
    }
    if let Some(recovery) = index.recovery {
        required_object(by_id, recovery, ObjectKind::Blob)?;
    }
    Ok(())
}

fn bootstrap_from_vault_index(
    index: &VaultIndex,
    by_id: &BTreeMap<ObjectId, &GistBundleObject>,
    epoch: KeyEpoch,
) -> Result<Bootstrap, GistBundleError> {
    let mut membership = index
        .membership
        .iter()
        .map(|id| required_object(by_id, *id, ObjectKind::MembershipEvent).cloned())
        .collect::<Result<Vec<_>, _>>()?;
    let mut envelopes = index
        .envelopes
        .iter()
        .map(|id| required_object(by_id, *id, ObjectKind::KeyEnvelope).cloned())
        .collect::<Result<Vec<_>, _>>()?;
    membership.sort_by_key(|object| object.id);
    envelopes.sort_by_key(|object| object.id);
    let bootstrap = Bootstrap {
        membership,
        envelopes,
    };
    bootstrap.validate(index.workspace, epoch)?;
    Ok(bootstrap)
}

fn merge_objects(
    mut private: Vec<GistBundleObject>,
    bootstrap: &Bootstrap,
) -> Result<Vec<GistBundleObject>, GistBundleError> {
    private.extend(bootstrap.all().cloned());
    private.sort_by_key(|object| object.id);
    validate_strict_object_order(&private)?;
    Ok(private)
}

fn validate_strict_object_order(objects: &[GistBundleObject]) -> Result<(), GistBundleError> {
    for pair in objects.windows(2) {
        match pair[0].id.cmp(&pair[1].id) {
            Ordering::Less => {}
            Ordering::Equal => return Err(GistBundleError::DuplicateObjectId),
            Ordering::Greater => return Err(GistBundleError::UnsortedObjects),
        }
    }
    Ok(())
}

fn chunk_secret_id(
    workspace: WorkspaceId,
    revision: u64,
    head: Option<SnapshotId>,
    epoch: KeyEpoch,
    signer: DeviceId,
    index: usize,
    count: usize,
) -> Result<SecretId, GistBundleError> {
    let identity = Value::Array(vec![
        Value::Uint(GIST_BUNDLE_FORMAT_VERSION as u64),
        workspace.to_value(),
        Value::Uint(revision),
        head.to_value(),
        epoch.to_value(),
        signer.to_value(),
        Value::Uint(index as u64),
        Value::Uint(count as u64),
    ]);
    let digest = Digest32::domain_hash(CHUNK_AAD_DOMAIN, &encode(&identity));
    SecretId::parse(&format!("gist/{}", digest.to_hex())).map_err(GistBundleError::Crypto)
}

fn bundle_digest(
    workspace: WorkspaceId,
    revision: u64,
    head: Option<SnapshotId>,
    objects: &SealedObjects,
    bootstrap: &Bootstrap,
) -> Digest32 {
    Digest32::domain_hash(
        BUNDLE_DIGEST_DOMAIN,
        &encode(&unsigned_envelope_value(
            workspace, revision, head, objects, bootstrap,
        )),
    )
}

fn signature_payload(digest: Digest32, signer: DeviceId) -> Vec<u8> {
    encode(&Value::Array(vec![
        Value::Uint(GIST_BUNDLE_FORMAT_VERSION as u64),
        digest.to_value(),
        signer.to_value(),
    ]))
}

fn unsigned_envelope_value(
    workspace: WorkspaceId,
    revision: u64,
    head: Option<SnapshotId>,
    objects: &SealedObjects,
    bootstrap: &Bootstrap,
) -> Value {
    Value::Array(vec![
        Value::Uint(GIST_BUNDLE_FORMAT_VERSION as u64),
        workspace.to_value(),
        Value::Uint(revision),
        head.to_value(),
        objects.to_value(),
        bootstrap.to_value(),
    ])
}

struct Envelope {
    workspace: WorkspaceId,
    revision: u64,
    head: Option<SnapshotId>,
    objects: SealedObjects,
    bootstrap: Bootstrap,
    digest: Digest32,
    signature: BundleSignature,
}

impl Envelope {
    fn epoch(&self) -> Result<KeyEpoch, GistBundleError> {
        let epoch = self
            .objects
            .chunks
            .first()
            .ok_or(GistBundleError::InvalidChunkCount { found: 0 })?
            .epoch();
        if self
            .objects
            .chunks
            .iter()
            .any(|chunk| chunk.epoch() != epoch)
        {
            return Err(GistBundleError::ChunkHeaderMismatch);
        }
        Ok(epoch)
    }

    fn header(&self) -> Result<GistBundleHeader, GistBundleError> {
        let epoch = self.epoch()?;
        self.bootstrap.validate(self.workspace, epoch)?;
        Ok(GistBundleHeader {
            workspace: self.workspace,
            revision: self.revision,
            head: self.head,
            epoch,
            signer: self.signature.signer,
            object_count: self.objects.count,
        })
    }

    fn bootstrap_view(&self) -> Result<GistBundleBootstrap, GistBundleError> {
        let epoch = self.epoch()?;
        self.bootstrap.validate(self.workspace, epoch)?;
        Ok(self.bootstrap.view(
            self.workspace,
            self.revision,
            self.head,
            epoch,
            self.signature.signer,
        ))
    }

    fn to_canonical_vec(&self) -> Vec<u8> {
        encode(&Value::Array(vec![
            Value::Uint(GIST_BUNDLE_FORMAT_VERSION as u64),
            self.workspace.to_value(),
            Value::Uint(self.revision),
            self.head.to_value(),
            self.objects.to_value(),
            self.bootstrap.to_value(),
            self.digest.to_value(),
            self.signature.to_value(),
        ]))
    }

    fn from_canonical_slice(bytes: &[u8]) -> Result<Self, GistBundleError> {
        let value = decode_canonical(bytes)?;
        let items = value.as_array()?;
        if items.len() != 8 {
            return Err(CborError::ArityMismatch.into());
        }
        let version = items[0].as_uint()?;
        if version != GIST_BUNDLE_FORMAT_VERSION as u64 {
            return Err(GistBundleError::UnsupportedVersion {
                found: version,
                supported: GIST_BUNDLE_FORMAT_VERSION,
            });
        }
        Ok(Envelope {
            workspace: WorkspaceId::from_value(&items[1])?,
            revision: u64::from_value(&items[2])?,
            head: Option::<SnapshotId>::from_value(&items[3])?,
            objects: SealedObjects::from_value(&items[4])?,
            bootstrap: Bootstrap::from_value(&items[5])?,
            digest: Digest32::from_value(&items[6])?,
            signature: BundleSignature::from_value(&items[7])?,
        })
    }
}

struct SealedObjects {
    count: u64,
    chunks: Vec<SealedSecret>,
}

impl SealedObjects {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Uint(self.count),
            Value::Array(self.chunks.iter().map(CborCodec::to_value).collect()),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, GistBundleError> {
        let items = value.as_array()?;
        if items.len() != 2 {
            return Err(CborError::ArityMismatch.into());
        }
        let count = items[0].as_uint()?;
        if count > MAX_OBJECTS as u64 {
            return Err(GistBundleError::TooManyObjects {
                found: count,
                limit: MAX_OBJECTS,
            });
        }
        let encoded_chunks = items[1].as_array()?;
        if encoded_chunks.is_empty() || encoded_chunks.len() > MAX_CHUNKS {
            return Err(GistBundleError::InvalidChunkCount {
                found: encoded_chunks.len(),
            });
        }
        let chunks = encoded_chunks
            .iter()
            .map(SealedSecret::from_value)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SealedObjects { count, chunks })
    }
}

struct BundleSignature {
    signer: DeviceId,
    value: Signature,
}

impl BundleSignature {
    fn to_value(&self) -> Value {
        Value::Array(vec![self.signer.to_value(), self.value.to_value()])
    }

    fn from_value(value: &Value) -> Result<Self, GistBundleError> {
        let items = value.as_array()?;
        if items.len() != 2 {
            return Err(CborError::ArityMismatch.into());
        }
        Ok(BundleSignature {
            signer: DeviceId::from_value(&items[0])?,
            value: Signature::from_value(&items[1])?,
        })
    }
}

struct PlainPayload {
    reference: WorkspaceRef,
    objects: Vec<GistBundleObject>,
}

impl PlainPayload {
    fn to_canonical_vec(&self) -> Vec<u8> {
        encode(&Value::Array(vec![
            Value::Uint(PAYLOAD_FORMAT_VERSION as u64),
            self.reference.to_value(),
            Value::Array(self.objects.iter().map(object_to_value).collect()),
        ]))
    }

    fn from_canonical_slice(bytes: &[u8]) -> Result<Self, GistBundleError> {
        let value = decode_canonical(bytes)?;
        let items = value.as_array()?;
        if items.len() != 3 {
            return Err(CborError::ArityMismatch.into());
        }
        let version = items[0].as_uint()?;
        if version != PAYLOAD_FORMAT_VERSION as u64 {
            return Err(GistBundleError::UnsupportedVersion {
                found: version,
                supported: PAYLOAD_FORMAT_VERSION,
            });
        }
        let reference = WorkspaceRef::from_value(&items[1])?;
        reference
            .validate()
            .map_err(|_| GistBundleError::InvalidReference)?;
        let records = items[2].as_array()?;
        if records.len() > MAX_OBJECTS {
            return Err(GistBundleError::TooManyObjects {
                found: records.len() as u64,
                limit: MAX_OBJECTS,
            });
        }
        let objects = records
            .iter()
            .map(object_from_value)
            .collect::<Result<Vec<_>, _>>()?;
        validate_strict_object_order(&objects)?;
        for object in &objects {
            if !object.id.verifies(&object.bytes) {
                return Err(GistBundleError::ObjectDigestMismatch);
            }
        }
        Ok(PlainPayload { reference, objects })
    }
}

fn object_to_value(object: &GistBundleObject) -> Value {
    Value::Array(vec![
        Value::Text(object.id.kind.as_str().to_owned()),
        object.id.digest.to_value(),
        Value::Bytes(object.bytes.clone()),
    ])
}

fn object_from_value(value: &Value) -> Result<GistBundleObject, GistBundleError> {
    let items = value.as_array()?;
    if items.len() != 3 {
        return Err(CborError::ArityMismatch.into());
    }
    let kind = ObjectKind::parse(items[0].as_text()?)
        .ok_or_else(|| CborError::InvalidValue("未知对象种类".to_owned()))?;
    let id = ObjectId {
        kind,
        digest: Digest32::from_value(&items[1])?,
    };
    Ok(GistBundleObject {
        id,
        bytes: items[2].as_bytes()?.to_vec(),
    })
}
