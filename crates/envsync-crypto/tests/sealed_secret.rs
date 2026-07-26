//! Task 4 验收：密封秘密对象。
//!
//! 本文件所有密钥都是**仅供测试的固定假密钥**，不是任何真实凭据。

use envsync_crypto::sealed::{open, seal, SealedHeader, SealedSecret, SecretId};
use envsync_crypto::suite::{
    CryptoSuite, DataKey, KeyEpoch, Plaintext, SealedFormatVersion, MAX_PLAINTEXT_LEN, NONCE_LEN,
    TAG_LEN,
};
use envsync_crypto::CryptoError;
use envsync_domain::cbor::{decode_canonical, encode, CborCodec, Value};
use envsync_domain::id::WorkspaceId;

/// 仅供测试的固定数据密钥。
fn test_key() -> DataKey {
    DataKey::from_bytes([0x2a; 32])
}

/// 仅供测试的另一把固定数据密钥。
fn other_key() -> DataKey {
    DataKey::from_bytes([0x2b; 32])
}

fn workspace_a() -> WorkspaceId {
    "11111111-1111-4111-8111-111111111111".parse().unwrap()
}

fn workspace_b() -> WorkspaceId {
    "22222222-2222-4222-8222-222222222222".parse().unwrap()
}

fn secret_a() -> SecretId {
    SecretId::parse("ci/npm-token").unwrap()
}

fn secret_b() -> SecretId {
    SecretId::parse("ci/pypi-token").unwrap()
}

fn seal_value(value: &[u8]) -> SealedSecret {
    seal(
        &test_key(),
        workspace_a(),
        &secret_a(),
        KeyEpoch::INITIAL,
        &Plaintext::from_slice(value),
    )
    .unwrap()
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

#[test]
fn round_trip_empty_value() {
    let sealed = seal_value(b"");
    let plaintext = open(&test_key(), &sealed).unwrap();
    assert!(plaintext.is_empty());
    // 空明文仍然有 16 字节 tag。
    assert_eq!(sealed.ciphertext().len(), TAG_LEN);
}

#[test]
fn round_trip_binary_value() {
    let value: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let sealed = seal_value(&value);
    let plaintext = open(&test_key(), &sealed).unwrap();
    assert_eq!(plaintext.expose(), &value[..]);
}

#[test]
fn round_trip_at_one_mib_boundary() {
    let value = vec![0x5au8; MAX_PLAINTEXT_LEN];
    let sealed = seal_value(&value);
    assert_eq!(sealed.ciphertext().len(), MAX_PLAINTEXT_LEN + TAG_LEN);
    let plaintext = open(&test_key(), &sealed).unwrap();
    assert_eq!(plaintext.len(), MAX_PLAINTEXT_LEN);
}

#[test]
fn above_one_mib_is_rejected() {
    let value = vec![0x5au8; MAX_PLAINTEXT_LEN + 1];
    let err = seal(
        &test_key(),
        workspace_a(),
        &secret_a(),
        KeyEpoch::INITIAL,
        &Plaintext::from_slice(&value),
    )
    .unwrap_err();
    assert_eq!(
        err,
        CryptoError::PlaintextTooLarge {
            limit: MAX_PLAINTEXT_LEN
        }
    );
}

#[test]
fn nonce_is_fresh_for_every_seal() {
    let a = seal_value(b"same value");
    let b = seal_value(b"same value");
    assert_ne!(a.nonce(), b.nonce());
    // 相同明文 + 相同密钥不产生相同密文：不泄露「两条秘密是否相等」。
    assert_ne!(a.ciphertext(), b.ciphertext());
}

#[test]
fn wrong_key_fails() {
    let sealed = seal_value(b"value");
    assert_eq!(
        expect_err(open(&other_key(), &sealed)),
        CryptoError::Authentication
    );
}

#[test]
fn flipping_any_ciphertext_or_tag_bit_fails() {
    let sealed = seal_value(b"0123456789abcdef");
    let ciphertext = sealed.ciphertext().to_vec();
    assert_eq!(ciphertext.len(), 16 + TAG_LEN);
    for byte in 0..ciphertext.len() {
        for bit in 0..8u32 {
            let mut mutated = ciphertext.clone();
            mutated[byte] ^= 1 << bit;
            let tampered =
                SealedSecret::from_parts_for_tests(sealed.header().clone(), mutated.clone());
            assert_eq!(
                expect_err(open(&test_key(), &tampered)),
                CryptoError::Authentication,
                "密文字节 {byte} 的第 {bit} 位被翻转后仍然解密成功"
            );
        }
    }
}

#[test]
fn flipping_any_nonce_bit_fails() {
    let sealed = seal_value(b"value");
    for byte in 0..NONCE_LEN {
        for bit in 0..8u32 {
            let mut header = sealed.header().clone();
            header.nonce[byte] ^= 1 << bit;
            let tampered = SealedSecret::from_parts_for_tests(header, sealed.ciphertext().to_vec());
            assert_eq!(
                expect_err(open(&test_key(), &tampered)),
                CryptoError::Authentication,
                "nonce 字节 {byte} 的第 {bit} 位被翻转后仍然解密成功"
            );
        }
    }
}

#[test]
fn cross_workspace_decryption_fails() {
    let sealed = seal_value(b"value");
    let mut header = sealed.header().clone();
    header.workspace = workspace_b();
    let tampered = SealedSecret::from_parts_for_tests(header, sealed.ciphertext().to_vec());
    assert_eq!(
        expect_err(open(&test_key(), &tampered)),
        CryptoError::Authentication
    );
}

#[test]
fn cross_secret_id_decryption_fails() {
    let sealed = seal_value(b"value");
    let mut header = sealed.header().clone();
    header.secret = secret_b();
    let tampered = SealedSecret::from_parts_for_tests(header, sealed.ciphertext().to_vec());
    assert_eq!(
        expect_err(open(&test_key(), &tampered)),
        CryptoError::Authentication
    );
}

#[test]
fn cross_epoch_decryption_fails() {
    let sealed = seal_value(b"value");
    let mut header = sealed.header().clone();
    header.epoch = KeyEpoch::new(2);
    let tampered = SealedSecret::from_parts_for_tests(header, sealed.ciphertext().to_vec());
    assert_eq!(
        expect_err(open(&test_key(), &tampered)),
        CryptoError::Authentication
    );
}

#[test]
fn aad_is_exactly_the_header_without_ciphertext() {
    let sealed = seal_value(b"value");
    let header = SealedHeader {
        version: SealedFormatVersion::V1,
        suite: CryptoSuite::Esv1,
        workspace: workspace_a(),
        secret: secret_a(),
        epoch: KeyEpoch::INITIAL,
        nonce: *sealed.nonce(),
    };
    assert_eq!(sealed.aad(), header.to_canonical_vec());

    // 完整对象 = header 的 6 个字段 + ciphertext，共 7 个。
    let value = decode_canonical(&sealed.to_canonical_vec()).unwrap();
    assert_eq!(value.as_array().unwrap().len(), 7);
    assert_eq!(
        decode_canonical(&sealed.aad())
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        6
    );
}

#[test]
fn wire_format_round_trips_and_is_canonical() {
    let sealed = seal_value(b"value");
    let bytes = sealed.to_canonical_vec();
    assert!(decode_canonical(&bytes).is_ok());
    let decoded = SealedSecret::from_canonical_slice(&bytes).unwrap();
    assert_eq!(decoded, sealed);
    assert_eq!(open(&test_key(), &decoded).unwrap().expose(), b"value");
}

#[test]
fn unknown_wire_version_is_rejected_at_decode() {
    let sealed = seal_value(b"value");
    let mut value = sealed.to_value();
    if let Value::Array(items) = &mut value {
        items[0] = Value::Uint(99);
    }
    let bytes = encode(&value);
    assert!(SealedSecret::from_canonical_slice(&bytes).is_err());
}

#[test]
fn oversized_ciphertext_is_rejected_at_decode() {
    let sealed = seal_value(b"value");
    let mut value = sealed.to_value();
    if let Value::Array(items) = &mut value {
        items[6] = Value::Bytes(vec![0u8; MAX_PLAINTEXT_LEN + TAG_LEN + 1]);
    }
    let bytes = encode(&value);
    assert!(SealedSecret::from_canonical_slice(&bytes).is_err());
}

#[test]
fn truncated_ciphertext_is_rejected() {
    let sealed = seal_value(b"value");
    let tampered = SealedSecret::from_parts_for_tests(sealed.header().clone(), vec![0u8; 4]);
    assert_eq!(
        expect_err(open(&test_key(), &tampered)),
        CryptoError::InvalidLength {
            field: "ciphertext",
            expected: TAG_LEN,
            found: 4,
        }
    );
}

#[test]
fn secret_id_is_a_logical_name_not_a_plaintext_digest() {
    // 同一个逻辑名可以承载完全不同的值；不同逻辑名可以承载相同的值。
    // 两者都不会因为「值相等」而暴露任何关联。
    let a = seal_value(b"identical value");
    let b = seal(
        &test_key(),
        workspace_a(),
        &secret_b(),
        KeyEpoch::INITIAL,
        &Plaintext::from_slice(b"identical value"),
    )
    .unwrap();
    assert_ne!(a.secret(), b.secret());
    assert_ne!(a.ciphertext(), b.ciphertext());

    // 逻辑名由调用者给定，与明文无关。
    assert_eq!(a.secret().as_str(), "ci/npm-token");
}
