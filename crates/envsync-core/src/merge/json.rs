//! JSON 语义三方合并。
//!
//! ## 合并规则
//!
//! - **对象按 key 递归三方合并**：双方改动不同的 key 时两边改动都保留。
//! - **数组是原子值**：不做元素级合并，整体取一侧，双方改成不同数组即冲突。
//! - **`null` 是一个值**，不代表删除；删除只由「键不存在」表达。
//! - 一侧删除 key、另一侧修改同一 key → 冲突，诊断记录该 key 的 **JSON Pointer**。
//! - **重复 key 被拒绝**：`serde_json` 默认后者覆盖前者，这里用自定义
//!   `DeserializeSeed` 自行检测并返回 [`MergeError::DuplicateKey`]。
//!
//! ## 输出与校验
//!
//! 输出为 `serde_json` 的 pretty 形式并以换行结尾；键顺序为字典序（`serde_json`
//! 的 `Map` 底层是 `BTreeMap`，因此 **JSON 注释/键顺序不被保留**，这是已知取舍）。
//! 渲染完成后会重新解析一次并比对语义模型，不一致返回
//! [`MergeError::RenderVerificationFailed`]。

use std::cell::Cell;
use std::fmt;

use envsync_domain::StructuredFormat;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use super::{
    child_pointer, classify, merge_tree, structured_conflict, MergeError, MergeInput,
    MergeProvenance, MergeResult, Plain, Presence, TreeValue, MAX_NODES, MAX_PARSE_DEPTH,
};

const FORMAT: StructuredFormat = StructuredFormat::Json;

/// 自定义错误里用来回传结构化失败原因的标记。
const DUP_SENTINEL: &str = "envsync-duplicate-key@";
const DEPTH_SENTINEL: &str = "envsync-depth-limit";
const NODE_SENTINEL: &str = "envsync-node-limit";

impl TreeValue for Value {
    fn entries(&self) -> Option<Vec<(String, Self)>> {
        match self {
            Value::Object(map) => Some(map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
            _ => None,
        }
    }

    fn from_entries(entries: Vec<(String, Self)>) -> Self {
        let mut map = Map::new();
        for (key, value) in entries {
            map.insert(key, value);
        }
        Value::Object(map)
    }
}

/// JSON 三方合并入口。
pub fn merge_json(input: &MergeInput<'_>) -> Result<MergeResult, MergeError> {
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

    let bytes = render(&merged)?;
    let reparsed = parse_strict(&bytes)?;
    if to_plain(&reparsed) != to_plain(&merged) {
        return Err(MergeError::RenderVerificationFailed { format: FORMAT });
    }

    Ok(MergeResult::Clean {
        bytes,
        provenance: provenance.note("json 按 key 递归合并，数组按原子值处理"),
    })
}

/// 渲染为 pretty JSON，并保证以换行结尾。
fn render(value: &Value) -> Result<Vec<u8>, MergeError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|err| MergeError::Parse {
        format: FORMAT,
        detail: format!("serialize failed: {}", err.classify_name()),
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// `serde_json::Error` 的分类名，避免把正文带进诊断。
trait ClassifyName {
    fn classify_name(&self) -> &'static str;
}

impl ClassifyName for serde_json::Error {
    fn classify_name(&self) -> &'static str {
        match self.classify() {
            serde_json::error::Category::Io => "io",
            serde_json::error::Category::Syntax => "syntax",
            serde_json::error::Category::Data => "data",
            serde_json::error::Category::Eof => "eof",
        }
    }
}

/// 严格解析：检测重复 key，并施加深度与节点上限。
pub(crate) fn parse_strict(bytes: &[u8]) -> Result<Value, MergeError> {
    let budget = Cell::new(0usize);
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let seed = NodeSeed {
        pointer: String::new(),
        depth: 1,
        budget: &budget,
    };
    let value = match seed.deserialize(&mut deserializer) {
        Ok(value) => value,
        Err(err) => return Err(classify_error(&err)),
    };
    deserializer.end().map_err(|err| MergeError::Parse {
        format: FORMAT,
        detail: format!(
            "trailing content at line {} column {}",
            err.line(),
            err.column()
        ),
    })?;
    Ok(value)
}

/// 把 serde 错误映射回结构化的 [`MergeError`]，同时保证不泄漏正文。
fn classify_error(err: &serde_json::Error) -> MergeError {
    let text = err.to_string();
    if let Some(rest) = text.split(DUP_SENTINEL).nth(1) {
        let pointer = rest.split(" at line ").next().unwrap_or(rest).trim();
        return MergeError::DuplicateKey {
            pointer: pointer.to_owned(),
        };
    }
    if text.contains(DEPTH_SENTINEL) {
        return MergeError::DepthLimitExceeded {
            limit: MAX_PARSE_DEPTH,
        };
    }
    if text.contains(NODE_SENTINEL) {
        return MergeError::NodeLimitExceeded { limit: MAX_NODES };
    }
    MergeError::Parse {
        format: FORMAT,
        detail: format!(
            "{} error at line {} column {}",
            err.classify_name(),
            err.line(),
            err.column()
        ),
    }
}

/// 带路径、深度与预算的节点解析种子。
struct NodeSeed<'a> {
    pointer: String,
    depth: usize,
    budget: &'a Cell<usize>,
}

impl<'de> DeserializeSeed<'de> for NodeSeed<'_> {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.depth > MAX_PARSE_DEPTH {
            return Err(de::Error::custom(DEPTH_SENTINEL));
        }
        let used = self.budget.get() + 1;
        if used > MAX_NODES {
            return Err(de::Error::custom(NODE_SENTINEL));
        }
        self.budget.set(used);
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for NodeSeed<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut items = Vec::new();
        loop {
            let child = NodeSeed {
                pointer: child_pointer(&self.pointer, &items.len().to_string()),
                depth: self.depth + 1,
                budget: self.budget,
            };
            match seq.next_element_seed(child)? {
                Some(value) => items.push(value),
                None => break,
            }
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let pointer = child_pointer(&self.pointer, &key);
            if object.contains_key(&key) {
                return Err(de::Error::custom(format!("{DUP_SENTINEL}{pointer}")));
            }
            let child = NodeSeed {
                pointer,
                depth: self.depth + 1,
                budget: self.budget,
            };
            let value = map.next_value_seed(child)?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

/// 转成与格式无关的语义模型，用于渲染后校验。
pub(crate) fn to_plain(value: &Value) -> Plain {
    match value {
        Value::Null => Plain::Null,
        Value::Bool(b) => Plain::Bool(*b),
        Value::Number(n) => Plain::Num(n.to_string()),
        Value::String(s) => Plain::Str(s.clone()),
        Value::Array(items) => Plain::Seq(items.iter().map(to_plain).collect()),
        Value::Object(map) => {
            Plain::map(map.iter().map(|(k, v)| (k.clone(), to_plain(v))).collect())
        }
    }
}
