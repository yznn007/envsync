//! Task 7 验收：Argon2id 恢复包与恢复短语。
//!
//! 本文件所有熵、salt、nonce 与口令都是**仅供测试的固定假值**，不是任何真实凭据。

use envsync_crypto::recovery::{
    Argon2Params, RecoveryPackage, RecoveryPhrase, RECOVERY_ENTROPY_LEN, RECOVERY_PHRASE_GROUP,
    RECOVERY_PHRASE_SYMBOLS,
};
use envsync_crypto::suite::{Plaintext, MAX_PLAINTEXT_LEN, TAG_LEN};
use envsync_crypto::CryptoError;
use envsync_domain::cbor::{decode_canonical, encode, CborCodec, Value};

/// 仅供测试的固定 128-bit 熵。
const TEST_ENTROPY: [u8; RECOVERY_ENTROPY_LEN] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
/// 仅供测试的另一份固定熵（用来扮演「错误口令」）。
const OTHER_ENTROPY: [u8; RECOVERY_ENTROPY_LEN] = [0x5a; RECOVERY_ENTROPY_LEN];

/// Base32-Crockford 字母表，与实现保持一致。
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn payload() -> Plaintext {
    // 假的「恢复材料」：真实场景里是恢复身份私钥 + 工作区数据密钥的 canonical 编码。
    Plaintext::from_slice(b"test-only-recovery-material")
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
// 参数边界
// ---------------------------------------------------------------------------

#[test]
fn parameters_below_project_floor_are_rejected() {
    // 下限：memory >= 64 MiB, time >= 3, parallelism >= 1。
    assert!(Argon2Params::new(64 * 1024, 3, 1).is_ok());

    for (memory, time, parallelism) in [
        (64 * 1024 - 1, 3, 1),
        (32 * 1024, 3, 1),
        (64 * 1024, 2, 1),
        (64 * 1024, 0, 1),
        (64 * 1024, 3, 0),
    ] {
        assert!(
            matches!(
                Argon2Params::new(memory, time, parallelism),
                Err(CryptoError::KdfParametersTooWeak { .. })
            ),
            "参数 ({memory}, {time}, {parallelism}) 低于下限却被接受"
        );
    }
}

#[test]
fn parameters_above_machine_ceiling_are_rejected() {
    // 上限：memory <= 2 GiB, time <= 32, parallelism <= 16。
    assert!(Argon2Params::new(2 * 1024 * 1024, 32, 16).is_ok());

    for (memory, time, parallelism) in [
        (2 * 1024 * 1024 + 1, 3, 1),
        (u32::MAX, 3, 1),
        (64 * 1024, 33, 1),
        (64 * 1024, u32::MAX, 1),
        (64 * 1024, 3, 17),
    ] {
        assert!(
            matches!(
                Argon2Params::new(memory, time, parallelism),
                Err(CryptoError::KdfParametersTooLarge { .. })
            ),
            "参数 ({memory}, {time}, {parallelism}) 超过上限却被接受"
        );
    }
}

#[test]
fn recommended_parameters_equal_the_project_floor() {
    let params = Argon2Params::recommended();
    assert_eq!(params.memory_kib(), Argon2Params::MIN_MEMORY_KIB);
    assert_eq!(params.time_cost(), Argon2Params::MIN_TIME_COST);
    assert_eq!(params.parallelism(), Argon2Params::MIN_PARALLELISM);
    assert_eq!(Argon2Params::MIN_MEMORY_KIB, 64 * 1024);
}

// ---------------------------------------------------------------------------
// 往返与错误口令
// ---------------------------------------------------------------------------

#[test]
fn round_trip_with_correct_phrase() {
    let phrase = RecoveryPhrase::from_entropy_for_tests(TEST_ENTROPY);
    let package =
        RecoveryPackage::create(&phrase, Argon2Params::recommended(), &payload()).unwrap();

    assert_eq!(package.params(), Argon2Params::recommended());
    assert_eq!(package.ciphertext().len(), payload().len() + TAG_LEN);

    let opened = package.open(&phrase).unwrap();
    assert!(opened == payload());
}

#[test]
fn wrong_phrase_returns_the_same_authentication_failure() {
    let phrase = RecoveryPhrase::from_entropy_for_tests(TEST_ENTROPY);
    let wrong = RecoveryPhrase::from_entropy_for_tests(OTHER_ENTROPY);
    let package =
        RecoveryPackage::create(&phrase, Argon2Params::recommended(), &payload()).unwrap();

    assert_eq!(
        expect_err(package.open(&wrong)),
        CryptoError::Authentication
    );

    // 参数在合法区间内被改动时，返回的错误与「口令不对」完全相同——不给区分 oracle。
    let tampered = RecoveryPackage::from_parts_for_tests(
        Argon2Params::new(128 * 1024, 3, 1).unwrap(),
        *package.salt(),
        *package.nonce(),
        package.ciphertext().to_vec(),
    );
    assert_eq!(
        expect_err(tampered.open(&phrase)),
        CryptoError::Authentication
    );

    // 密文被改也是同一个错误。
    let mut ciphertext = package.ciphertext().to_vec();
    ciphertext[0] ^= 0x01;
    let tampered = RecoveryPackage::from_parts_for_tests(
        package.params(),
        *package.salt(),
        *package.nonce(),
        ciphertext,
    );
    assert_eq!(
        expect_err(tampered.open(&phrase)),
        CryptoError::Authentication
    );
}

#[test]
fn salt_and_nonce_are_fresh_for_every_package() {
    let phrase = RecoveryPhrase::from_entropy_for_tests(TEST_ENTROPY);
    let a = RecoveryPackage::create(&phrase, Argon2Params::recommended(), &payload()).unwrap();
    let b = RecoveryPackage::create(&phrase, Argon2Params::recommended(), &payload()).unwrap();
    assert_ne!(a.salt(), b.salt());
    assert_ne!(a.nonce(), b.nonce());
    assert_ne!(a.ciphertext(), b.ciphertext());
}

#[test]
fn wire_format_round_trips_and_is_canonical() {
    let phrase = RecoveryPhrase::from_entropy_for_tests(TEST_ENTROPY);
    let package =
        RecoveryPackage::create(&phrase, Argon2Params::recommended(), &payload()).unwrap();
    let bytes = package.to_canonical_vec();
    assert!(decode_canonical(&bytes).is_ok());
    let decoded = RecoveryPackage::from_canonical_slice(&bytes).unwrap();
    assert_eq!(decoded, package);
    assert!(decoded.open(&phrase).unwrap() == payload());
}

// ---------------------------------------------------------------------------
// 畸形包：拒绝而不是耗尽资源
// ---------------------------------------------------------------------------

/// 用给定的 KDF 参数手工拼一个恢复包的 CBOR 编码（绕过 `Argon2Params` 的构造检查）。
fn forge_package_bytes(memory_kib: u32, time_cost: u32, parallelism: u32) -> Vec<u8> {
    encode(&Value::Array(vec![
        Value::Uint(1),
        Value::Text(envsync_crypto::suite::CryptoSuite::ESV1_NAME.to_owned()),
        Value::Uint(memory_kib as u64),
        Value::Uint(time_cost as u64),
        Value::Uint(parallelism as u64),
        Value::Bytes(vec![0u8; 16]),
        Value::Bytes(vec![0u8; 12]),
        Value::Bytes(vec![0u8; TAG_LEN]),
    ]))
}

#[test]
fn malformed_package_never_requests_more_than_two_gib_or_endless_iterations() {
    // 每一个畸形参数都在**解码期**被拒绝：从来不会有一次 Argon2 分配发生。
    for (memory, time, parallelism) in [
        (u32::MAX, u32::MAX, u32::MAX),
        (4 * 1024 * 1024, 3, 1),   // 4 GiB
        (64 * 1024, 1_000_000, 1), // 无限迭代
        (64 * 1024, 3, 4096),
        (0, 0, 0),
    ] {
        let bytes = forge_package_bytes(memory, time, parallelism);
        let start = std::time::Instant::now();
        let result = RecoveryPackage::from_canonical_slice(&bytes);
        assert!(
            result.is_err(),
            "畸形参数 ({memory}, {time}, {parallelism}) 被接受了"
        );
        // 拒绝必须是「立即」的：没有分配、没有迭代。
        assert!(
            start.elapsed() < std::time::Duration::from_millis(200),
            "拒绝畸形参数耗时过长，说明真的开始跑 KDF 了"
        );
    }
}

#[test]
fn oversized_ciphertext_is_rejected_at_decode() {
    let bytes = encode(&Value::Array(vec![
        Value::Uint(1),
        Value::Text(envsync_crypto::suite::CryptoSuite::ESV1_NAME.to_owned()),
        Value::Uint(64 * 1024),
        Value::Uint(3),
        Value::Uint(1),
        Value::Bytes(vec![0u8; 16]),
        Value::Bytes(vec![0u8; 12]),
        Value::Bytes(vec![0u8; MAX_PLAINTEXT_LEN + TAG_LEN + 1]),
    ]));
    assert!(RecoveryPackage::from_canonical_slice(&bytes).is_err());
}

#[test]
fn unknown_wire_version_is_rejected() {
    let phrase = RecoveryPhrase::from_entropy_for_tests(TEST_ENTROPY);
    let package =
        RecoveryPackage::create(&phrase, Argon2Params::recommended(), &payload()).unwrap();
    let mut value = package.to_value();
    if let Value::Array(items) = &mut value {
        items[0] = Value::Uint(42);
    }
    assert!(RecoveryPackage::from_canonical_slice(&encode(&value)).is_err());
}

// ---------------------------------------------------------------------------
// 恢复短语编码
// ---------------------------------------------------------------------------

#[test]
fn phrase_is_displayed_exactly_once() {
    let mut phrase = RecoveryPhrase::generate().unwrap();
    assert!(!phrase.is_revealed());
    let shown = phrase.display_once().unwrap();
    assert_eq!(
        shown.chars().filter(|c| *c != '-').count(),
        RECOVERY_PHRASE_SYMBOLS
    );
    assert!(phrase.is_revealed());
    assert_eq!(
        phrase.display_once().unwrap_err(),
        CryptoError::RecoveryPhraseAlreadyRevealed
    );
}

#[test]
fn phrase_grouping_is_stable() {
    let phrase = RecoveryPhrase::from_entropy_for_tests(TEST_ENTROPY);
    let text = phrase.render_for_tests();
    let groups: Vec<&str> = text.split('-').collect();
    assert_eq!(
        groups.len(),
        RECOVERY_PHRASE_SYMBOLS / RECOVERY_PHRASE_GROUP
    );
    for group in groups {
        assert_eq!(group.len(), RECOVERY_PHRASE_GROUP);
        assert!(group.bytes().all(|b| ALPHABET.contains(&b)));
    }
}

#[test]
fn phrase_round_trips_through_text() {
    let phrase = RecoveryPhrase::from_entropy_for_tests(TEST_ENTROPY);
    let text = phrase.render_for_tests();
    let parsed = RecoveryPhrase::parse(&text).unwrap();

    // 用「能不能解开同一个包」来验证熵一致——短语本身不暴露内容。
    let package =
        RecoveryPackage::create(&phrase, Argon2Params::recommended(), &payload()).unwrap();
    assert!(package.open(&parsed).unwrap() == payload());
}

#[test]
fn checksum_detects_every_single_character_substitution() {
    let phrase = RecoveryPhrase::from_entropy_for_tests(TEST_ENTROPY);
    let text = phrase.render_for_tests();
    let symbols: Vec<char> = text.chars().filter(|c| *c != '-').collect();
    assert_eq!(symbols.len(), RECOVERY_PHRASE_SYMBOLS);

    let mut checked = 0usize;
    for position in 0..RECOVERY_PHRASE_SYMBOLS {
        for &candidate in ALPHABET.iter() {
            let candidate = candidate as char;
            if candidate == symbols[position] {
                continue;
            }
            let mut mutated = symbols.clone();
            mutated[position] = candidate;
            let text: String = mutated.into_iter().collect();
            assert_eq!(
                RecoveryPhrase::parse(&text).map(|_| ()).unwrap_err(),
                CryptoError::RecoveryPhraseChecksum,
                "位置 {position} 被替换为 {candidate} 后校验位没有报警"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, RECOVERY_PHRASE_SYMBOLS * 31);
}

#[test]
fn malformed_phrases_are_rejected() {
    let phrase = RecoveryPhrase::from_entropy_for_tests(TEST_ENTROPY);
    let text = phrase.render_for_tests();
    let symbols: String = text.chars().filter(|c| *c != '-').collect();

    // 长度不对。
    assert_eq!(
        expect_err(RecoveryPhrase::parse(&symbols[..31])),
        CryptoError::RecoveryPhraseMalformed
    );
    assert_eq!(
        expect_err(RecoveryPhrase::parse(&format!("{symbols}0"))),
        CryptoError::RecoveryPhraseMalformed
    );
    assert_eq!(
        expect_err(RecoveryPhrase::parse("")),
        CryptoError::RecoveryPhraseMalformed
    );
    // 字母表之外的字符（`U` 被 Crockford 排除）。
    let mut bad = symbols.clone();
    bad.replace_range(0..1, "U");
    assert_eq!(
        expect_err(RecoveryPhrase::parse(&bad)),
        CryptoError::RecoveryPhraseMalformed
    );
    // 删除一个字符（长度校验先命中）。
    let mut deleted = symbols.clone();
    deleted.remove(5);
    assert_eq!(
        expect_err(RecoveryPhrase::parse(&deleted)),
        CryptoError::RecoveryPhraseMalformed
    );
}

#[test]
fn phrase_parsing_normalizes_case_separators_and_crockford_aliases() {
    let phrase = RecoveryPhrase::from_entropy_for_tests(TEST_ENTROPY);
    let text = phrase.render_for_tests();
    let package =
        RecoveryPackage::create(&phrase, Argon2Params::recommended(), &payload()).unwrap();

    for variant in [
        text.to_lowercase(),
        text.replace('-', " "),
        text.replace('-', ""),
        format!("  {}  ", *text),
        text.replace('0', "O").replace('1', "I"),
        text.replace('0', "o").replace('1', "l"),
    ] {
        let parsed = RecoveryPhrase::parse(&variant).unwrap();
        assert!(
            package.open(&parsed).unwrap() == payload(),
            "变体 `{variant}` 未能还原同一份熵"
        );
    }
}

#[test]
fn generated_phrases_are_distinct() {
    let mut a = RecoveryPhrase::generate().unwrap();
    let mut b = RecoveryPhrase::generate().unwrap();
    assert_ne!(*a.display_once().unwrap(), *b.display_once().unwrap());
}
