//! YAML 语义三方合并（仅安全数据模型、单文档）。
//!
//! ## 接受的子集
//!
//! - **只接受单文档**：出现 `---` 分隔的第二个文档即
//!   [`MergeError::UnsupportedConstruct`]。
//! - **拒绝自定义 tag**（`!Foo`）：自定义 tag 会把 YAML 变成可执行的类型系统入口，
//!   合并器不做任何 tag 语义推断。
//! - **拒绝 alias 环 / alias 爆炸**：由底层解析器的重复展开保护捕获，映射为
//!   `UnsupportedConstruct`。
//! - **拒绝重复 key** → [`MergeError::DuplicateKey`]。
//!
//! ## 合并规则
//!
//! - mapping 按 key 递归合并；**sequence 是原子值**。
//! - 键全部为字符串的 mapping 才递归；含非字符串键的 mapping 按原子值处理。
//!
//! ## 已知限制
//!
//! `serde_yaml_ng` 的数据模型不保留注释与锚点，因此 **YAML 合并结果会丢失注释与
//! 锚点**（TOML/INI/Git config 合并器则保留注释）。需要保留注释的 YAML 资源应配置
//! 为文本合并。

use envsync_domain::StructuredFormat;
use serde_yaml_ng::{Mapping, Value};

use super::{
    classify, merge_tree, structured_conflict, Budget, MergeError, MergeInput, MergeProvenance,
    MergeResult, Plain, Presence, TreeValue,
};

const FORMAT: StructuredFormat = StructuredFormat::Yaml;

impl TreeValue for Value {
    fn entries(&self) -> Option<Vec<(String, Self)>> {
        let mapping = match self {
            Value::Mapping(mapping) => mapping,
            _ => return None,
        };
        let mut entries = Vec::with_capacity(mapping.len());
        for (key, value) in mapping {
            match key {
                Value::String(key) => entries.push((key.clone(), value.clone())),
                // 含非字符串键的 mapping 不递归，整体按原子值处理。
                _ => return None,
            }
        }
        Some(entries)
    }

    fn from_entries(entries: Vec<(String, Self)>) -> Self {
        let mut mapping = Mapping::with_capacity(entries.len());
        for (key, value) in entries {
            mapping.insert(Value::String(key), value);
        }
        Value::Mapping(mapping)
    }
}

/// YAML 三方合并入口。
pub fn merge_yaml(input: &MergeInput<'_>) -> Result<MergeResult, MergeError> {
    let (base, ours, theirs) = match classify(input) {
        Presence::Decided(result) => return Ok(result),
        Presence::Both { base, ours, theirs } => (base, ours, theirs),
    };

    let base_value = base.map(parse_strict).transpose()?;
    let ours_value = parse_strict(ours)?;
    let theirs_value = parse_strict(theirs)?;

    let mut conflicts = Vec::new();
    let mut provenance = MergeProvenance::default();
    let merged = merge_tree(
        base_value.as_ref(),
        Some(&ours_value),
        Some(&theirs_value),
        "",
        &mut conflicts,
        &mut provenance,
    );

    if !conflicts.is_empty() {
        return Ok(MergeResult::Conflict(structured_conflict(
            input, &conflicts,
        )));
    }
    let merged = merged.unwrap_or(Value::Null);

    let text = serde_yaml_ng::to_string(&merged).map_err(|_| MergeError::Parse {
        format: FORMAT,
        detail: "serialize failed".to_owned(),
    })?;
    let bytes = text.into_bytes();
    let reparsed = parse_strict(&bytes)?;
    if to_plain(&reparsed) != to_plain(&merged) {
        return Err(MergeError::RenderVerificationFailed { format: FORMAT });
    }

    Ok(MergeResult::Clean {
        bytes,
        provenance: provenance.note("yaml 按 key 递归合并，sequence 按原子值处理"),
    })
}

/// 严格解析：单文档、无自定义 tag、无重复 key，并施加深度与节点上限。
pub(crate) fn parse_strict(bytes: &[u8]) -> Result<Value, MergeError> {
    let value: Value = serde_yaml_ng::from_slice(bytes).map_err(|err| classify_error(&err))?;
    let mut budget = Budget::new();
    check_supported(&value, 1, &mut budget)?;
    Ok(value)
}

/// 把解析错误映射成结构化的 [`MergeError`]，只保留位置信息。
fn classify_error(err: &serde_yaml_ng::Error) -> MergeError {
    let text = err.to_string();
    if text.contains("more than one document") {
        return MergeError::UnsupportedConstruct {
            format: FORMAT,
            detail: "multiple documents in one stream".to_owned(),
        };
    }
    if text.contains("recursion limit") || text.contains("repetition limit") {
        return MergeError::UnsupportedConstruct {
            format: FORMAT,
            detail: "alias cycle or excessive alias expansion".to_owned(),
        };
    }
    if let Some(rest) = text.split("duplicate entry ").nth(1) {
        let pointer = duplicate_pointer(rest);
        return MergeError::DuplicateKey { pointer };
    }
    let location = err
        .location()
        .map(|loc| format!("line {} column {}", loc.line(), loc.column()))
        .unwrap_or_else(|| "unknown location".to_owned());
    MergeError::Parse {
        format: FORMAT,
        detail: location,
    }
}

/// 从 `duplicate entry with key "x" at line ...` 里抽出键名。
///
/// 底层错误只带叶子键名，不带完整路径，因此这里给出的 pointer 是**叶子键**。
fn duplicate_pointer(rest: &str) -> String {
    let head = rest.split(" at line ").next().unwrap_or(rest).trim();
    let key = head
        .strip_prefix("with key ")
        .map(|k| k.trim().trim_matches('"'))
        .unwrap_or(head);
    super::child_pointer("", key)
}

/// 遍历检查：拒绝自定义 tag，同时统计深度与节点数。
fn check_supported(value: &Value, depth: usize, budget: &mut Budget) -> Result<(), MergeError> {
    budget.charge(depth)?;
    match value {
        Value::Tagged(_) => Err(MergeError::UnsupportedConstruct {
            format: FORMAT,
            detail: "custom tag".to_owned(),
        }),
        Value::Sequence(items) => {
            for item in items {
                check_supported(item, depth + 1, budget)?;
            }
            Ok(())
        }
        Value::Mapping(mapping) => {
            for (key, item) in mapping {
                check_supported(key, depth + 1, budget)?;
                check_supported(item, depth + 1, budget)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// 转成与格式无关的语义模型，用于渲染后校验。
pub(crate) fn to_plain(value: &Value) -> Plain {
    match value {
        Value::Null => Plain::Null,
        Value::Bool(b) => Plain::Bool(*b),
        Value::Number(n) => Plain::Num(n.to_string()),
        Value::String(s) => Plain::Str(s.clone()),
        Value::Sequence(items) => Plain::Seq(items.iter().map(to_plain).collect()),
        Value::Mapping(mapping) => Plain::map(
            mapping
                .iter()
                .map(|(k, v)| (plain_key(k), to_plain(v)))
                .collect(),
        ),
        // `check_supported` 已经拒绝过 tagged 值，这里只是保持全覆盖。
        Value::Tagged(tagged) => Plain::Seq(vec![
            Plain::Str(format!("!{}", tagged.tag)),
            to_plain(&tagged.value),
        ]),
    }
}

/// 把任意 YAML 键规范化为确定性字符串，供比较使用（带类型前缀避免跨类型碰撞）。
fn plain_key(value: &Value) -> String {
    match value {
        Value::Null => "~".to_owned(),
        Value::Bool(b) => format!("b:{b}"),
        Value::Number(n) => format!("n:{n}"),
        Value::String(s) => format!("s:{s}"),
        Value::Sequence(items) => {
            let parts: Vec<String> = items.iter().map(plain_key).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Mapping(mapping) => {
            let mut parts: Vec<String> = mapping
                .iter()
                .map(|(k, v)| format!("{}={}", plain_key(k), plain_key(v)))
                .collect();
            parts.sort();
            format!("{{{}}}", parts.join(","))
        }
        Value::Tagged(tagged) => format!("!{}:{}", tagged.tag, plain_key(&tagged.value)),
    }
}
