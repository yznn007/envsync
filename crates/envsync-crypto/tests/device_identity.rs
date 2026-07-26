//! Task 2 验收：设备身份与签名。
//!
//! 本文件出现的所有密钥都是**测试期临时生成或固定的假密钥**，不是任何真实凭据。

use envsync_crypto::device::{
    signing_input, verify, DeviceKeypair, DevicePublic, Signature, SIGNATURE_DOMAIN_PREFIX,
    SIGNATURE_FORMAT_VERSION,
};
use envsync_crypto::CryptoError;
use envsync_domain::cbor::{decode, decode_canonical, CborCodec, CborError};
use envsync_domain::id::{DeviceId, WorkspaceId};

/// 仅供测试的固定工作区标识。
fn workspace_a() -> WorkspaceId {
    "11111111-1111-4111-8111-111111111111".parse().unwrap()
}

/// 仅供测试的固定工作区标识。
fn workspace_b() -> WorkspaceId {
    "22222222-2222-4222-8222-222222222222".parse().unwrap()
}

#[test]
fn generate_produces_two_independent_keys() {
    let keypair = DeviceKeypair::generate().unwrap();
    let public = keypair.public();
    // 两把公钥都是 32 字节，且互不相同（同一台设备不会复用同一份材料）。
    assert_ne!(public.x25519, public.ed25519);
    assert_ne!(public.x25519, [0u8; 32]);
    assert_ne!(public.ed25519, [0u8; 32]);
    public.validate().unwrap();

    // 两次生成必然不同。
    let other = DeviceKeypair::generate().unwrap();
    assert_ne!(other.public(), public);
}

#[test]
fn device_id_is_derived_from_both_public_keys() {
    let keypair = DeviceKeypair::generate().unwrap();
    let public = keypair.public();
    let expected = DeviceId::derive(&public.device_id_input());
    assert_eq!(public.device_id(), expected);
    assert_eq!(keypair.device_id(), expected);
}

#[test]
fn flipping_any_public_key_bit_changes_device_id() {
    let keypair = DeviceKeypair::generate().unwrap();
    let base = keypair.public();
    let base_id = base.device_id();

    for byte in 0..32usize {
        for bit in 0..8u32 {
            let mut mutated = base;
            mutated.x25519[byte] ^= 1 << bit;
            assert_ne!(mutated.device_id(), base_id, "x25519[{byte}] bit {bit}");

            let mut mutated = base;
            mutated.ed25519[byte] ^= 1 << bit;
            assert_ne!(mutated.device_id(), base_id, "ed25519[{byte}] bit {bit}");
        }
    }
}

#[test]
fn signature_round_trips() {
    let keypair = DeviceKeypair::generate().unwrap();
    let signature = keypair
        .sign("membership-event", workspace_a(), b"payload")
        .unwrap();
    verify(
        &keypair.public(),
        "membership-event",
        workspace_a(),
        b"payload",
        &signature,
    )
    .unwrap();
}

#[test]
fn cross_workspace_replay_is_rejected() {
    let keypair = DeviceKeypair::generate().unwrap();
    let signature = keypair
        .sign("membership-event", workspace_a(), b"payload")
        .unwrap();
    assert_eq!(
        verify(
            &keypair.public(),
            "membership-event",
            workspace_b(),
            b"payload",
            &signature
        ),
        Err(CryptoError::SignatureInvalid)
    );
}

#[test]
fn modified_payload_is_rejected() {
    let keypair = DeviceKeypair::generate().unwrap();
    let signature = keypair
        .sign("membership-event", workspace_a(), b"payload")
        .unwrap();
    assert_eq!(
        verify(
            &keypair.public(),
            "membership-event",
            workspace_a(),
            b"payloae",
            &signature
        ),
        Err(CryptoError::SignatureInvalid)
    );
}

#[test]
fn different_domain_is_rejected() {
    let keypair = DeviceKeypair::generate().unwrap();
    let signature = keypair
        .sign("membership-event", workspace_a(), b"payload")
        .unwrap();
    assert_eq!(
        verify(
            &keypair.public(),
            "snapshot",
            workspace_a(),
            b"payload",
            &signature
        ),
        Err(CryptoError::SignatureInvalid)
    );
}

#[test]
fn wrong_signer_is_rejected() {
    let signer = DeviceKeypair::generate().unwrap();
    let impostor = DeviceKeypair::generate().unwrap();
    let signature = signer
        .sign("membership-event", workspace_a(), b"payload")
        .unwrap();
    assert_eq!(
        verify(
            &impostor.public(),
            "membership-event",
            workspace_a(),
            b"payload",
            &signature
        ),
        Err(CryptoError::SignatureInvalid)
    );
}

#[test]
fn flipping_any_signature_bit_is_rejected() {
    let keypair = DeviceKeypair::generate().unwrap();
    let signature = keypair
        .sign("membership-event", workspace_a(), b"payload")
        .unwrap();
    for byte in 0..64usize {
        let mut bytes = *signature.as_bytes();
        bytes[byte] ^= 0x01;
        let mutated = Signature::from_bytes(bytes);
        assert!(
            verify(
                &keypair.public(),
                "membership-event",
                workspace_a(),
                b"payload",
                &mutated
            )
            .is_err(),
            "签名字节 {byte} 被翻转后仍然通过验证"
        );
    }
}

#[test]
fn non_canonical_signed_payload_is_rejected() {
    let keypair = DeviceKeypair::generate().unwrap();
    let canonical = signing_input("membership-event", workspace_a(), b"payload").unwrap();
    assert!(decode_canonical(&canonical).is_ok());

    // 待签数组的第 2 个元素是 uint(1)（格式版本），紧跟在 0x86 数组头与域前缀文本之后。
    let version_offset = 1 + 1 + 1 + SIGNATURE_DOMAIN_PREFIX.len();
    assert_eq!(canonical[version_offset], 0x01);

    // 用「非最短整数编码」表达同一个逻辑值 1：语义相同，字节不同。
    let mut non_canonical = canonical.clone();
    non_canonical.splice(version_offset..version_offset + 1, [0x18, 0x01]);
    assert_ne!(non_canonical, canonical);
    // 严格解码器本身就拒绝它。
    assert_eq!(decode(&non_canonical), Err(CborError::NonMinimalInteger));

    // 即使攻击者拿到私钥对非 canonical 字节签名，verify 也不会接受：
    // verify 重新计算 canonical 编码，而不是相信输入。
    let forged = keypair.sign_raw_for_tests(&non_canonical);
    assert_eq!(
        verify(
            &keypair.public(),
            "membership-event",
            workspace_a(),
            b"payload",
            &forged
        ),
        Err(CryptoError::SignatureInvalid)
    );
}

#[test]
fn unknown_signature_version_is_rejected_before_crypto() {
    let keypair = DeviceKeypair::generate().unwrap();
    let signature = keypair
        .sign("membership-event", workspace_a(), b"payload")
        .unwrap();
    assert_eq!(signature.version(), SIGNATURE_FORMAT_VERSION);

    // 在 CBOR 层把版本改成 2：解码即失败，不会进入密码学路径。
    let mut value = signature.to_value();
    if let envsync_domain::cbor::Value::Array(items) = &mut value {
        items[0] = envsync_domain::cbor::Value::Uint(2);
    }
    let bytes = envsync_domain::cbor::encode(&value);
    assert_eq!(
        Signature::from_canonical_slice(&bytes),
        Err(CborError::UnsupportedFormatVersion {
            found: 2,
            supported: SIGNATURE_FORMAT_VERSION,
        })
    );
}

#[test]
fn invalid_domain_label_is_rejected() {
    let keypair = DeviceKeypair::generate().unwrap();
    assert_eq!(
        keypair.sign("", workspace_a(), b"payload").unwrap_err(),
        CryptoError::DomainLabelInvalid
    );
    assert_eq!(
        keypair
            .sign("with\ttab", workspace_a(), b"payload")
            .unwrap_err(),
        CryptoError::DomainLabelInvalid
    );
}

#[test]
fn invalid_public_key_encoding_is_rejected() {
    // `[0x02; 32]` 不是任何 Edwards 点的合法压缩表示。
    let bogus = DevicePublic {
        x25519: [0u8; 32],
        ed25519: [0x02; 32],
    };
    assert_eq!(bogus.validate(), Err(CryptoError::InvalidPublicKey));
}

#[test]
fn small_order_public_key_cannot_verify() {
    // 全零是一个**合法编码**（单位元），但它是小阶点：任何人都能为它伪造签名。
    // `verify_strict` 会拒绝这类弱公钥，因此签名验证必须失败。
    let weak = DevicePublic {
        x25519: [0u8; 32],
        ed25519: [0u8; 32],
    };
    assert!(weak.validate().is_ok(), "全零是合法编码");
    assert_eq!(
        verify(
            &weak,
            "membership-event",
            workspace_a(),
            b"payload",
            &Signature::from_bytes([0u8; 64])
        ),
        Err(CryptoError::SignatureInvalid)
    );
}

#[test]
fn device_public_round_trips_through_canonical_cbor() {
    let keypair = DeviceKeypair::generate().unwrap();
    let public = keypair.public();
    let bytes = public.to_canonical_vec();
    assert_eq!(DevicePublic::from_canonical_slice(&bytes).unwrap(), public);
    assert!(decode_canonical(&bytes).is_ok());
}

#[test]
fn secret_material_survives_export_and_import() {
    let keypair = DeviceKeypair::generate().unwrap();
    let exported = keypair.export_secret_bytes();
    let x = <[u8; 32]>::try_from(&exported[..32]).unwrap();
    let ed = <[u8; 32]>::try_from(&exported[32..]).unwrap();
    let restored = DeviceKeypair::from_secret_bytes(x, ed).unwrap();
    assert_eq!(restored.device_id(), keypair.device_id());

    // 还原后的设备产生的签名可以用原设备的公钥验证。
    let signature = restored
        .sign("membership-event", workspace_a(), b"payload")
        .unwrap();
    verify(
        &keypair.public(),
        "membership-event",
        workspace_a(),
        b"payload",
        &signature,
    )
    .unwrap();
}
