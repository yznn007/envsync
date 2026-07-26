//! Task 5 验收：HPKE 设备信封。
//!
//! 本文件所有密钥都是**测试期生成或固定的假密钥**，不是任何真实凭据。

use envsync_crypto::device::DeviceKeypair;
use envsync_crypto::envelope::{
    envelope_info, open_envelope, seal_envelope, KeyEnvelope, ENVELOPE_CIPHERTEXT_LEN,
};
use envsync_crypto::suite::{CryptoSuite, DataKey, KeyEpoch, SealedFormatVersion};
use envsync_crypto::CryptoError;
use envsync_domain::cbor::{decode_canonical, CborCodec};
use envsync_domain::id::WorkspaceId;

fn workspace_a() -> WorkspaceId {
    "11111111-1111-4111-8111-111111111111".parse().unwrap()
}

fn workspace_b() -> WorkspaceId {
    "22222222-2222-4222-8222-222222222222".parse().unwrap()
}

/// 仅供测试的固定数据密钥。
fn test_data_key() -> DataKey {
    DataKey::from_bytes([0x33; 32])
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
fn only_the_target_device_can_open() {
    let alice = DeviceKeypair::generate().unwrap();
    let bob = DeviceKeypair::generate().unwrap();
    let key = test_data_key();

    let envelope = seal_envelope(&alice.public(), workspace_a(), KeyEpoch::INITIAL, &key).unwrap();
    assert_eq!(envelope.recipient(), alice.device_id());
    assert_eq!(envelope.ciphertext().len(), ENVELOPE_CIPHERTEXT_LEN);

    let recovered = open_envelope(&alice, &envelope).unwrap();
    assert!(recovered == key);

    // 非目标设备在做任何密码学运算前就被拒绝。
    assert_eq!(
        expect_err(open_envelope(&bob, &envelope)),
        CryptoError::RecipientMismatch
    );
}

#[test]
fn swapping_two_devices_envelopes_fails() {
    let alice = DeviceKeypair::generate().unwrap();
    let bob = DeviceKeypair::generate().unwrap();
    let key = test_data_key();

    let for_alice = seal_envelope(&alice.public(), workspace_a(), KeyEpoch::INITIAL, &key).unwrap();
    let for_bob = seal_envelope(&bob.public(), workspace_a(), KeyEpoch::INITIAL, &key).unwrap();
    assert_ne!(for_alice.ciphertext(), for_bob.ciphertext());

    // 把 Bob 的封装内容贴上 Alice 的收件人标签：收件人检查通过，但 KEM 与 AAD 都对不上。
    let forged = KeyEnvelope::from_parts_for_tests(
        SealedFormatVersion::V1,
        CryptoSuite::Esv1,
        workspace_a(),
        alice.device_id(),
        KeyEpoch::INITIAL,
        *for_bob.enc(),
        for_bob.ciphertext().to_vec(),
    );
    assert_eq!(
        expect_err(open_envelope(&alice, &forged)),
        CryptoError::Authentication
    );
}

#[test]
fn epoch_downgrade_fails() {
    let alice = DeviceKeypair::generate().unwrap();
    let key = test_data_key();
    let envelope = seal_envelope(&alice.public(), workspace_a(), KeyEpoch::new(7), &key).unwrap();

    for downgraded in [KeyEpoch::new(6), KeyEpoch::new(1), KeyEpoch::new(8)] {
        let forged = KeyEnvelope::from_parts_for_tests(
            SealedFormatVersion::V1,
            CryptoSuite::Esv1,
            workspace_a(),
            alice.device_id(),
            downgraded,
            *envelope.enc(),
            envelope.ciphertext().to_vec(),
        );
        assert_eq!(
            expect_err(open_envelope(&alice, &forged)),
            CryptoError::Authentication,
            "epoch 被改为 {downgraded} 后仍然解开"
        );
    }
}

#[test]
fn cross_workspace_replay_fails() {
    let alice = DeviceKeypair::generate().unwrap();
    let key = test_data_key();
    let envelope = seal_envelope(&alice.public(), workspace_a(), KeyEpoch::INITIAL, &key).unwrap();

    let forged = KeyEnvelope::from_parts_for_tests(
        SealedFormatVersion::V1,
        CryptoSuite::Esv1,
        workspace_b(),
        alice.device_id(),
        KeyEpoch::INITIAL,
        *envelope.enc(),
        envelope.ciphertext().to_vec(),
    );
    assert_eq!(
        expect_err(open_envelope(&alice, &forged)),
        CryptoError::Authentication
    );
}

#[test]
fn flipping_any_ciphertext_bit_fails() {
    let alice = DeviceKeypair::generate().unwrap();
    let envelope = seal_envelope(
        &alice.public(),
        workspace_a(),
        KeyEpoch::INITIAL,
        &test_data_key(),
    )
    .unwrap();

    for byte in 0..ENVELOPE_CIPHERTEXT_LEN {
        let mut ciphertext = envelope.ciphertext().to_vec();
        ciphertext[byte] ^= 0x01;
        let forged = KeyEnvelope::from_parts_for_tests(
            SealedFormatVersion::V1,
            CryptoSuite::Esv1,
            workspace_a(),
            alice.device_id(),
            KeyEpoch::INITIAL,
            *envelope.enc(),
            ciphertext,
        );
        assert_eq!(
            expect_err(open_envelope(&alice, &forged)),
            CryptoError::Authentication,
            "密文字节 {byte} 被翻转后仍然解开"
        );
    }
}

#[test]
fn flipping_any_enc_bit_fails() {
    let alice = DeviceKeypair::generate().unwrap();
    let envelope = seal_envelope(
        &alice.public(),
        workspace_a(),
        KeyEpoch::INITIAL,
        &test_data_key(),
    )
    .unwrap();

    for byte in 0..32usize {
        let mut enc = *envelope.enc();
        enc[byte] ^= 0x01;
        let forged = KeyEnvelope::from_parts_for_tests(
            SealedFormatVersion::V1,
            CryptoSuite::Esv1,
            workspace_a(),
            alice.device_id(),
            KeyEpoch::INITIAL,
            enc,
            envelope.ciphertext().to_vec(),
        );
        assert!(
            open_envelope(&alice, &forged).is_err(),
            "enc 字节 {byte} 被翻转后仍然解开"
        );
    }
}

#[test]
fn every_seal_uses_a_fresh_ephemeral_key() {
    let alice = DeviceKeypair::generate().unwrap();
    let key = test_data_key();
    let a = seal_envelope(&alice.public(), workspace_a(), KeyEpoch::INITIAL, &key).unwrap();
    let b = seal_envelope(&alice.public(), workspace_a(), KeyEpoch::INITIAL, &key).unwrap();
    assert_ne!(a.enc(), b.enc());
    assert_ne!(a.ciphertext(), b.ciphertext());
    // 两个信封都能被目标设备打开，得到同一把数据密钥。
    assert!(open_envelope(&alice, &a).unwrap() == open_envelope(&alice, &b).unwrap());
}

#[test]
fn new_epoch_envelope_does_not_unlock_old_epoch_object() {
    let alice = DeviceKeypair::generate().unwrap();
    let old_key = DataKey::from_bytes([0x01; 32]); // 仅供测试
    let new_key = DataKey::from_bytes([0x02; 32]); // 仅供测试

    let old = seal_envelope(&alice.public(), workspace_a(), KeyEpoch::new(1), &old_key).unwrap();
    let new = seal_envelope(&alice.public(), workspace_a(), KeyEpoch::new(2), &new_key).unwrap();

    assert!(open_envelope(&alice, &old).unwrap() == old_key);
    assert!(open_envelope(&alice, &new).unwrap() == new_key);
    assert!(open_envelope(&alice, &new).unwrap() != old_key);
}

#[test]
fn info_binds_workspace_recipient_and_epoch() {
    let alice = DeviceKeypair::generate().unwrap();
    let bob = DeviceKeypair::generate().unwrap();

    let base = envelope_info(
        SealedFormatVersion::V1,
        workspace_a(),
        alice.device_id(),
        KeyEpoch::INITIAL,
    );
    assert!(decode_canonical(&base).is_ok());
    assert_ne!(
        base,
        envelope_info(
            SealedFormatVersion::V1,
            workspace_b(),
            alice.device_id(),
            KeyEpoch::INITIAL
        )
    );
    assert_ne!(
        base,
        envelope_info(
            SealedFormatVersion::V1,
            workspace_a(),
            bob.device_id(),
            KeyEpoch::INITIAL
        )
    );
    assert_ne!(
        base,
        envelope_info(
            SealedFormatVersion::V1,
            workspace_a(),
            alice.device_id(),
            KeyEpoch::new(2)
        )
    );
}

#[test]
fn wire_format_round_trips_and_is_canonical() {
    let alice = DeviceKeypair::generate().unwrap();
    let envelope = seal_envelope(
        &alice.public(),
        workspace_a(),
        KeyEpoch::INITIAL,
        &test_data_key(),
    )
    .unwrap();

    let bytes = envelope.to_canonical_vec();
    assert!(decode_canonical(&bytes).is_ok());
    let decoded = KeyEnvelope::from_canonical_slice(&bytes).unwrap();
    assert_eq!(decoded, envelope);
    assert!(open_envelope(&alice, &decoded).unwrap() == test_data_key());
}

#[test]
fn wrong_ciphertext_length_is_rejected_at_decode() {
    let alice = DeviceKeypair::generate().unwrap();
    let envelope = seal_envelope(
        &alice.public(),
        workspace_a(),
        KeyEpoch::INITIAL,
        &test_data_key(),
    )
    .unwrap();
    let short = KeyEnvelope::from_parts_for_tests(
        SealedFormatVersion::V1,
        CryptoSuite::Esv1,
        workspace_a(),
        alice.device_id(),
        KeyEpoch::INITIAL,
        *envelope.enc(),
        vec![0u8; ENVELOPE_CIPHERTEXT_LEN - 1],
    );
    assert!(KeyEnvelope::from_canonical_slice(&short.to_canonical_vec()).is_err());
    assert_eq!(
        expect_err(open_envelope(&alice, &short)),
        CryptoError::InvalidLength {
            field: "envelope_ciphertext",
            expected: ENVELOPE_CIPHERTEXT_LEN,
            found: ENVELOPE_CIPHERTEXT_LEN - 1,
        }
    );
}

#[test]
fn small_order_ephemeral_key_is_rejected() {
    let alice = DeviceKeypair::generate().unwrap();
    // 全零的 `enc` 会让 X25519 得到全零共享秘密（非贡献性），必须拒绝。
    let forged = KeyEnvelope::from_parts_for_tests(
        SealedFormatVersion::V1,
        CryptoSuite::Esv1,
        workspace_a(),
        alice.device_id(),
        KeyEpoch::INITIAL,
        [0u8; 32],
        vec![0u8; ENVELOPE_CIPHERTEXT_LEN],
    );
    assert_eq!(
        expect_err(open_envelope(&alice, &forged)),
        CryptoError::NonContributoryKeyExchange
    );
}
