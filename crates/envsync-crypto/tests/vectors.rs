//! Task 1 验收：算法套件解析、格式版本拒绝、固定测试向量与 canary 泄露测试。
//!
//! # 关于本文件里的密钥
//!
//! 下面出现的**所有**密钥、种子、salt、nonce 与恢复短语都是硬编码的**测试专用假值**
//! （`0x2a` 之类的填充模式），不是、也永远不会是任何真实凭据。它们存在的唯一理由是让
//! 密文成为确定性的，从而可以逐字节断言线格式不被意外改动。
//!
//! # 关于这些向量的性质
//!
//! 这些是**本实现自产的回归向量**（regression vectors），用途是「格式冻结」：任何对
//! 字段顺序、域标签、派生链或编码规则的改动都会让它们失败。它们**不是**来自 RFC 9180
//! 官方测试向量的互操作性证明——那一项应在 M2 收尾（Task 10 的
//! `docs/security/test-vectors/`）用官方 A.3 向量补上。

use envsync_crypto::device::{verify, DeviceKeypair, Signature};
use envsync_crypto::envelope::{open_envelope, seal_envelope_with_ephemeral_for_tests};
use envsync_crypto::recovery::{Argon2Params, RecoveryPackage, RecoveryPhrase};
use envsync_crypto::sealed::{open, seal, seal_with_nonce_for_tests, SealedSecret, SecretId};
use envsync_crypto::suite::{
    CryptoSuite, DataKey, KeyEpoch, Plaintext, SealedFormatVersion, KEY_LEN, MAX_PLAINTEXT_LEN,
    NONCE_LEN, SIGNATURE_LEN, TAG_LEN,
};
use envsync_crypto::CryptoError;
use envsync_domain::cbor::{decode_canonical, encode, CborCodec, Value};
use envsync_domain::id::WorkspaceId;

// ---------------------------------------------------------------------------
// 固定测试输入（全部为假值）
// ---------------------------------------------------------------------------

/// 仅供测试的固定工作区标识。
const TEST_WORKSPACE: &str = "11111111-1111-4111-8111-111111111111";
/// 仅供测试的固定数据密钥。
const TEST_DATA_KEY: [u8; KEY_LEN] = [0x2a; KEY_LEN];
/// 仅供测试的固定 nonce。
const TEST_NONCE: [u8; NONCE_LEN] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
/// 仅供测试的固定 X25519 私钥种子。
const TEST_DEVICE_X25519_SECRET: [u8; 32] = [0x51; 32];
/// 仅供测试的固定 Ed25519 私钥种子。
const TEST_DEVICE_ED25519_SECRET: [u8; 32] = [0x52; 32];
/// 仅供测试的固定 HPKE 临时私钥。
const TEST_EPHEMERAL_SECRET: [u8; 32] = [0x53; 32];
/// 仅供测试的固定信封数据密钥。
const TEST_ENVELOPE_DATA_KEY: [u8; KEY_LEN] = [0x33; KEY_LEN];
/// 仅供测试的固定 128-bit 恢复熵。
const TEST_RECOVERY_ENTROPY: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
/// 仅供测试的固定 Argon2id salt。
const TEST_RECOVERY_SALT: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
/// 仅供测试的固定恢复包 nonce。
const TEST_RECOVERY_NONCE: [u8; NONCE_LEN] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
];

fn workspace() -> WorkspaceId {
    TEST_WORKSPACE.parse().unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `unwrap_err` 要求成功类型实现 `Debug`，而 `DataKey`/`Plaintext`/`RecoveryPhrase`
/// 刻意不实现——这个小助手就是那条约束在测试里的代价。
#[track_caller]
fn expect_err<T>(result: Result<T, CryptoError>) -> CryptoError {
    match result {
        Ok(_) => panic!("期望失败，但操作成功了"),
        Err(error) => error,
    }
}

// ---------------------------------------------------------------------------
// Task 1 Step 1：套件与版本解析
// ---------------------------------------------------------------------------

#[test]
fn the_only_m2_suite_parses() {
    assert_eq!(
        CryptoSuite::ESV1_NAME,
        "ESV1_X25519_HKDF_SHA256_CHACHA20POLY1305_ED25519"
    );
    assert_eq!(
        CryptoSuite::parse(CryptoSuite::ESV1_NAME).unwrap(),
        CryptoSuite::Esv1
    );
    assert_eq!(CryptoSuite::Esv1.as_str(), CryptoSuite::ESV1_NAME);
    assert_eq!(CryptoSuite::Esv1.to_string(), CryptoSuite::ESV1_NAME);
}

#[test]
fn unknown_suites_are_rejected() {
    for name in [
        "",
        "esv1_x25519_hkdf_sha256_chacha20poly1305_ed25519", // 大小写不同即不同
        "ESV1_X25519_HKDF_SHA256_CHACHA20POLY1305_ED25519 ",
        "ESV0_X25519_HKDF_SHA256_CHACHA20POLY1305_ED25519",
        "ESV1_P256_HKDF_SHA256_AES128GCM_ECDSA",
        "ESV2_X25519_HKDF_SHA512_XCHACHA20POLY1305_ED25519",
    ] {
        assert_eq!(
            CryptoSuite::parse(name),
            Err(CryptoError::UnsupportedSuite),
            "套件名 `{name}` 不应被接受"
        );
    }
}

#[test]
fn unknown_suite_is_rejected_on_the_wire_too() {
    let bogus = encode(&Value::Text("ESV9_UNKNOWN".to_owned()));
    assert!(CryptoSuite::from_canonical_slice(&bogus).is_err());
}

#[test]
fn only_format_version_one_is_accepted() {
    assert_eq!(SealedFormatVersion::parse(1).unwrap().get(), 1);
    for raw in [0u32, 2, 3, 99, u32::MAX] {
        assert_eq!(
            SealedFormatVersion::parse(raw),
            Err(CryptoError::UnsupportedFormatVersion {
                found: raw,
                supported: 1,
            }),
            "版本 {raw} 不应被接受"
        );
    }
}

#[test]
fn unknown_format_version_is_rejected_on_the_wire() {
    for raw in [0u64, 2, u32::MAX as u64] {
        let bogus = encode(&Value::Uint(raw));
        assert!(SealedFormatVersion::from_canonical_slice(&bogus).is_err());
    }
}

#[test]
fn documented_constants_match_the_suite() {
    assert_eq!(KEY_LEN, 32);
    assert_eq!(NONCE_LEN, 12);
    assert_eq!(TAG_LEN, 16);
    assert_eq!(SIGNATURE_LEN, 64);
    assert_eq!(MAX_PLAINTEXT_LEN, 1024 * 1024);
}

// ---------------------------------------------------------------------------
// Task 1 Step 4：固定 decode 向量
// ---------------------------------------------------------------------------

#[test]
fn sealed_secret_wire_vector_is_frozen() {
    let sealed = seal_with_nonce_for_tests(
        &DataKey::from_bytes(TEST_DATA_KEY),
        workspace(),
        &SecretId::parse("ci/npm-token").unwrap(),
        KeyEpoch::INITIAL,
        &Plaintext::from_slice(b"test-vector-value"),
        TEST_NONCE,
    )
    .unwrap();

    let expected = concat!(
        "87017830455356315f5832353531395f484b44465f5348413235365f434841434841",
        "3230504f4c59313330355f4544323535313950111111111111411181111111111111",
        "116c63692f6e706d2d746f6b656e014c000102030405060708090a0b5821ead841e4",
        "9c115d9ae1962c8960a290b592b7828847ab31164e821d6e92d0dfbebe",
    );
    assert_eq!(hex(&sealed.to_canonical_vec()), expected);

    // 向量可以被解码回来并正确解密。
    let bytes = sealed.to_canonical_vec();
    assert!(decode_canonical(&bytes).is_ok());
    let decoded = SealedSecret::from_canonical_slice(&bytes).unwrap();
    let plaintext = open(&DataKey::from_bytes(TEST_DATA_KEY), &decoded).unwrap();
    assert_eq!(plaintext.expose(), b"test-vector-value");
}

#[test]
fn device_identity_vector_is_frozen() {
    let device =
        DeviceKeypair::from_secret_bytes(TEST_DEVICE_X25519_SECRET, TEST_DEVICE_ED25519_SECRET)
            .unwrap();
    assert_eq!(
        hex(&device.public().x25519),
        "ad908a8a708aca07588cda7c4ed3e44d4966a80a9abb2f1e4bbac53c67414e34"
    );
    assert_eq!(
        hex(&device.public().ed25519),
        "2012cb90ca60e8e5d8daf66e2272d2233e0486d557e8c66141ed8920177d7eb7"
    );
    assert_eq!(
        device.device_id().to_hex(),
        "e3009d665bf8f968e99bc47aa11152c3ab0c7c0cfb1d57d554628e1d912364ec"
    );

    // Ed25519 是确定性签名，因此签名也可以冻结。
    let signature = device
        .sign("membership-event", workspace(), b"test-vector-payload")
        .unwrap();
    assert_eq!(
        hex(signature.as_bytes()),
        concat!(
            "1b79f0414676e668652d52a419cabef324728c191cc206b6e5b4800fe582f19a",
            "c7f4daa7ad6102677ac6d36e445137db4f33c3c51572942b658de473c875d10a",
        )
    );
    verify(
        &device.public(),
        "membership-event",
        workspace(),
        b"test-vector-payload",
        &signature,
    )
    .unwrap();
}

#[test]
fn key_envelope_wire_vector_is_frozen() {
    let device =
        DeviceKeypair::from_secret_bytes(TEST_DEVICE_X25519_SECRET, TEST_DEVICE_ED25519_SECRET)
            .unwrap();
    let envelope = seal_envelope_with_ephemeral_for_tests(
        &device.public(),
        workspace(),
        KeyEpoch::INITIAL,
        &DataKey::from_bytes(TEST_ENVELOPE_DATA_KEY),
        TEST_EPHEMERAL_SECRET,
    )
    .unwrap();

    let expected = concat!(
        "87017830455356315f5832353531395f484b44465f5348413235365f434841434841",
        "3230504f4c59313330355f4544323535313950111111111111411181111111111111",
        "115820e3009d665bf8f968e99bc47aa11152c3ab0c7c0cfb1d57d554628e1d912364",
        "ec015820261cd9cd2e935f9c2455876a80f02a4d6786b8ab877f07227737ca0b577b",
        "f161583072cb3419df3055b2698f2f81c43ae31d47f8b33ae5fdedba3d2395bd9cd7",
        "d262fb9f6488ee3ac51d6027bb4d0301ebee",
    );
    assert_eq!(hex(&envelope.to_canonical_vec()), expected);

    let recovered = open_envelope(&device, &envelope).unwrap();
    assert!(recovered == DataKey::from_bytes(TEST_ENVELOPE_DATA_KEY));
}

#[test]
fn recovery_phrase_vector_is_frozen() {
    let phrase = RecoveryPhrase::from_entropy_for_tests(TEST_RECOVERY_ENTROPY);
    assert_eq!(
        &*phrase.render_for_tests(),
        "008J-4CT4-ANK7-F24S-NAXW-SQFE-ZYGH-7XZ2"
    );
}

#[test]
fn recovery_package_wire_vector_is_frozen() {
    let phrase = RecoveryPhrase::from_entropy_for_tests(TEST_RECOVERY_ENTROPY);
    let package = RecoveryPackage::create_with_salt_nonce_for_tests(
        &phrase,
        Argon2Params::recommended(),
        &Plaintext::from_slice(b"test-vector-recovery-material"),
        TEST_RECOVERY_SALT,
        TEST_RECOVERY_NONCE,
    )
    .unwrap();

    let expected = concat!(
        "88017830455356315f5832353531395f484b44465f5348413235365f434841434841",
        "3230504f4c59313330355f454432353531391a0001000003015010111213141516171",
        "8191a1b1c1d1e1f4c202122232425262728292a2b582d5738ea57411d21938dc1d6c8",
        "e51365ab2a04a7a6d9c4f3ffa048b26fc5b4aa84b84a51d35ae6630566e2f9c65b",
    );
    assert_eq!(hex(&package.to_canonical_vec()), expected);
    assert!(
        package.open(&phrase).unwrap() == Plaintext::from_slice(b"test-vector-recovery-material")
    );
}

#[test]
fn production_api_never_produces_the_fixed_nonce_vector() {
    // 生产 API 自己生成 nonce：同样的输入两次得到不同密文，也不会撞上测试向量的 nonce。
    let key = DataKey::from_bytes(TEST_DATA_KEY);
    let secret = SecretId::parse("ci/npm-token").unwrap();
    let a = seal(
        &key,
        workspace(),
        &secret,
        KeyEpoch::INITIAL,
        &Plaintext::from_slice(b"test-vector-value"),
    )
    .unwrap();
    let b = seal(
        &key,
        workspace(),
        &secret,
        KeyEpoch::INITIAL,
        &Plaintext::from_slice(b"test-vector-value"),
    )
    .unwrap();
    assert_ne!(a.nonce(), b.nonce());
    assert_ne!(*a.nonce(), TEST_NONCE);
}

// ---------------------------------------------------------------------------
// canary：任何错误路径都不得泄露明文
// ---------------------------------------------------------------------------

/// 贯穿所有错误路径的探针字符串。它不是凭据，只是一个「如果出现在任何诊断输出里就说明
/// 有泄露」的标记。
const CANARY: &str = "CANARY-8f2b1d-PLAINTEXT-MUST-NEVER-BE-LOGGED";

/// 收集一个错误的全部可观测文本：`Display`、`Debug` 与整条 `source` 链。
fn observable_text(error: &CryptoError) -> String {
    use std::error::Error;
    let mut text = format!("{error}\n{error:?}");
    let mut source: Option<&dyn Error> = error.source();
    while let Some(current) = source {
        text.push('\n');
        text.push_str(&format!("{current}\n{current:?}"));
        source = current.source();
    }
    text
}

/// 走遍所有会接触到明文的失败路径，收集产生的错误。
fn errors_from_every_failure_path() -> Vec<(&'static str, CryptoError)> {
    let canary = CANARY.as_bytes();
    let plaintext = Plaintext::from_slice(canary);
    let key = DataKey::from_bytes(TEST_DATA_KEY);
    let wrong_key = DataKey::from_bytes([0x2b; KEY_LEN]);
    let secret = SecretId::parse("ci/npm-token").unwrap();
    let mut out = Vec::new();

    // 1) sealed：错误密钥。
    let sealed = seal(&key, workspace(), &secret, KeyEpoch::INITIAL, &plaintext).unwrap();
    out.push(("sealed/wrong-key", expect_err(open(&wrong_key, &sealed))));

    // 2) sealed：密文被篡改。
    let mut ciphertext = sealed.ciphertext().to_vec();
    ciphertext[0] ^= 0x01;
    let tampered = SealedSecret::from_parts_for_tests(sealed.header().clone(), ciphertext);
    out.push(("sealed/tampered", expect_err(open(&key, &tampered))));

    // 3) sealed：AAD 被篡改（换 workspace）。
    let mut header = sealed.header().clone();
    header.workspace = "22222222-2222-4222-8222-222222222222".parse().unwrap();
    let moved = SealedSecret::from_parts_for_tests(header, sealed.ciphertext().to_vec());
    out.push(("sealed/cross-workspace", expect_err(open(&key, &moved))));

    // 4) sealed：明文超限。
    let oversized: Vec<u8> = canary
        .iter()
        .copied()
        .cycle()
        .take(MAX_PLAINTEXT_LEN + 1)
        .collect();
    out.push((
        "sealed/too-large",
        seal(
            &key,
            workspace(),
            &secret,
            KeyEpoch::INITIAL,
            &Plaintext::from_slice(&oversized),
        )
        .unwrap_err(),
    ));

    // 5) sealed：把明文当逻辑名（含空格，不合法）。
    let canary_name = format!("{CANARY} raw value");
    out.push((
        "secret-id/invalid",
        SecretId::parse(&canary_name).unwrap_err(),
    ));

    // 6) 签名：错误 signer。
    let signer = DeviceKeypair::generate().unwrap();
    let impostor = DeviceKeypair::generate().unwrap();
    let signature = signer.sign("vault-secret", workspace(), canary).unwrap();
    out.push((
        "signature/wrong-signer",
        verify(
            &impostor.public(),
            "vault-secret",
            workspace(),
            canary,
            &signature,
        )
        .unwrap_err(),
    ));

    // 7) 签名：域标签本身是明文（含控制字符且超长，非法）。
    let canary_domain = format!("{CANARY}\n{CANARY}");
    out.push((
        "signature/bad-domain",
        signer
            .sign(&canary_domain, workspace(), canary)
            .unwrap_err(),
    ));

    // 8) 签名：签名字节被篡改。
    let mut bytes = *signature.as_bytes();
    bytes[0] ^= 0x01;
    out.push((
        "signature/tampered",
        verify(
            &signer.public(),
            "vault-secret",
            workspace(),
            canary,
            &Signature::from_bytes(bytes),
        )
        .unwrap_err(),
    ));

    // 9) 信封：非目标设备。
    let envelope = seal_envelope_with_ephemeral_for_tests(
        &signer.public(),
        workspace(),
        KeyEpoch::INITIAL,
        &key,
        TEST_EPHEMERAL_SECRET,
    )
    .unwrap();
    out.push((
        "envelope/wrong-device",
        expect_err(open_envelope(&impostor, &envelope)),
    ));

    // 10) 恢复包：错误口令。
    let phrase = RecoveryPhrase::from_entropy_for_tests(TEST_RECOVERY_ENTROPY);
    let wrong_phrase = RecoveryPhrase::from_entropy_for_tests([0x5a; 16]);
    let package = RecoveryPackage::create_with_salt_nonce_for_tests(
        &phrase,
        Argon2Params::recommended(),
        &plaintext,
        TEST_RECOVERY_SALT,
        TEST_RECOVERY_NONCE,
    )
    .unwrap();
    out.push((
        "recovery/wrong-phrase",
        expect_err(package.open(&wrong_phrase)),
    ));

    // 11) 恢复短语：把明文当短语解析。
    out.push((
        "recovery/phrase-malformed",
        expect_err(RecoveryPhrase::parse(CANARY)),
    ));

    // 12) 恢复包：参数越界。
    out.push((
        "recovery/params-weak",
        Argon2Params::new(1, 1, 1).unwrap_err(),
    ));
    out.push((
        "recovery/params-huge",
        Argon2Params::new(u32::MAX, u32::MAX, u32::MAX).unwrap_err(),
    ));

    // 13) 解码：把明文塞进 CBOR 的 SecretId 字段。
    let bogus = encode(&Value::Array(vec![
        Value::Uint(1),
        Value::Text(CryptoSuite::ESV1_NAME.to_owned()),
        workspace().to_value(),
        Value::Text(canary_name.clone()),
        Value::Uint(1),
        Value::Bytes(TEST_NONCE.to_vec()),
        Value::Bytes(vec![0u8; TAG_LEN]),
    ]));
    out.push((
        "decode/plaintext-in-secret-id",
        CryptoError::from(SealedSecret::from_canonical_slice(&bogus).unwrap_err()),
    ));

    out
}

#[test]
fn no_error_path_leaks_the_canary_plaintext() {
    let errors = errors_from_every_failure_path();
    // 确保确实覆盖了所有列出的路径，避免将来某条路径被悄悄删掉。
    assert_eq!(errors.len(), 14);

    for (path, error) in &errors {
        let text = observable_text(error);
        assert!(
            !text.contains(CANARY),
            "错误路径 `{path}` 在诊断输出里泄露了 canary 明文：{text}"
        );
        // 连片段也不该出现。
        assert!(
            !text.contains("PLAINTEXT-MUST-NEVER"),
            "错误路径 `{path}` 泄露了 canary 片段：{text}"
        );
        // 诊断文本必须非空（否则这个测试就成了空断言）。
        assert!(!text.is_empty());
    }
}

#[test]
fn the_canary_test_would_actually_catch_a_leak() {
    // 反向自检：如果某个错误真的携带了明文，`observable_text` 必须能看到它。
    let leaky = CryptoError::Encoding(envsync_domain::cbor::CborError::InvalidValue(
        CANARY.to_owned(),
    ));
    assert!(observable_text(&leaky).contains(CANARY));
}

#[test]
fn sealed_object_debug_shows_no_plaintext() {
    let key = DataKey::from_bytes(TEST_DATA_KEY);
    let sealed = seal(
        &key,
        workspace(),
        &SecretId::parse("ci/npm-token").unwrap(),
        KeyEpoch::INITIAL,
        &Plaintext::from_slice(CANARY.as_bytes()),
    )
    .unwrap();
    let text = format!("{sealed:?}");
    assert!(!text.contains(CANARY));
    // header 里的逻辑名是元数据，可以出现；密文只以字节数组形式出现。
    assert!(text.contains("ci/npm-token"));
}
