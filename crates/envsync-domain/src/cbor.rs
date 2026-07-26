//! 严格 canonical CBOR 编解码器。
//!
//! EnvSync 的所有持久化对象都必须是**确定性**的：相同的逻辑内容必须产生逐字节相同的
//! 编码，进而产生相同的内容摘要。通用 CBOR 库允许多种等价表示（不定长度、非最短整数
//! 编码、任意 map 键顺序），无法满足这一要求，因此本模块实现一个受限子集：
//!
//! * 只允许确定长度（definite length）编码；
//! * 整数必须使用最短形式；
//! * map 的键必须按其 canonical 编码字节严格升序排列，且不允许重复；
//! * 不支持浮点数、tag、undefined 和其他 simple value；
//! * 解码时对深度和节点数设上限，防止恶意输入造成栈溢出或内存耗尽。
//!
//! 解码器会拒绝任何不满足上述规则的输入，因此“解码后重新编码必然得到原字节”这一
//! 性质由构造保证（`decode_canonical` 额外做一次断言式校验作为纵深防御）。
//!
//! 结构体统一编码为 CBOR **数组**（字段按声明顺序排列），而不是 map。这样字段顺序由
//! 类型定义固定，天然确定；同时省去键名开销。语义上的 map（例如 State Root 中的
//! `ResourceId -> ResourceEntry`）才使用 CBOR map，并强制按键排序。

use std::collections::BTreeMap;
use std::fmt;

/// 解码时允许的最大嵌套深度。
pub const MAX_DEPTH: usize = 64;
/// 解码时允许的最大节点数量，用于阻止“解压炸弹”式的恶意输入。
pub const MAX_NODES: usize = 4_000_000;

/// CBOR 编解码错误。
///
/// 错误信息只描述结构问题，不包含被解析的数据内容，避免把秘密写进日志。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CborError {
    /// 输入在解析途中结束。
    #[error("CBOR 输入过早结束")]
    UnexpectedEof,
    /// 顶层解析完成后仍有剩余字节。
    #[error("CBOR 输入存在 {0} 个多余字节")]
    TrailingBytes(usize),
    /// 遇到本子集不支持的 major type 或 simple value。
    #[error("不支持的 CBOR 类型：major={major}, info={info}")]
    UnsupportedType {
        /// CBOR major type。
        major: u8,
        /// CBOR additional information。
        info: u8,
    },
    /// 使用了不定长度编码。
    #[error("不允许不定长度 CBOR 编码")]
    IndefiniteLength,
    /// 整数没有使用最短编码形式。
    #[error("整数未使用最短 CBOR 编码形式")]
    NonMinimalInteger,
    /// map 的键没有按 canonical 顺序排列。
    #[error("CBOR map 键顺序非 canonical")]
    UnsortedMapKeys,
    /// map 中存在重复键。
    #[error("CBOR map 存在重复键")]
    DuplicateMapKey,
    /// 嵌套层数超过 [`MAX_DEPTH`]。
    #[error("CBOR 嵌套深度超过上限 {MAX_DEPTH}")]
    DepthLimitExceeded,
    /// 节点数量超过 [`MAX_NODES`]。
    #[error("CBOR 节点数量超过上限 {MAX_NODES}")]
    NodeLimitExceeded,
    /// 声明的长度超出剩余输入。
    #[error("CBOR 声明长度超出输入范围")]
    LengthOutOfRange,
    /// 文本串不是合法 UTF-8。
    #[error("CBOR 文本串不是合法 UTF-8")]
    InvalidUtf8,
    /// 重新编码结果与输入不一致（纵深防御断言失败）。
    #[error("CBOR 表示非 canonical：重新编码结果与输入不一致")]
    NotCanonical,
    /// 实际类型与期望类型不符。
    #[error("CBOR 类型不符：期望 {expected}")]
    TypeMismatch {
        /// 期望的类型名称。
        expected: &'static str,
    },
    /// 数组元素个数与结构体字段数不符。
    #[error("CBOR 数组元素个数与结构定义不符")]
    ArityMismatch,
    /// 整数超出目标类型范围。
    #[error("CBOR 整数超出目标类型范围")]
    IntegerOutOfRange,
    /// 字节串长度与定长数组不符。
    #[error("CBOR 字节串长度不符：期望 {expected} 字节")]
    LengthMismatch {
        /// 期望的字节数。
        expected: usize,
    },
    /// 枚举判别式未知。
    #[error("未知的枚举判别式 `{0}`")]
    UnknownVariant(String),
    /// 领域层面的取值非法（例如 ID 校验失败）。
    #[error("CBOR 值不满足领域约束：{0}")]
    InvalidValue(String),
    /// 遇到未知的格式版本号，必须拒绝而不是静默降级。
    #[error("未知的对象格式版本 {found}，本实现支持 {supported}")]
    UnsupportedFormatVersion {
        /// 输入中的版本号。
        found: u32,
        /// 当前实现支持的版本号。
        supported: u32,
    },
}

/// canonical CBOR 值。
///
/// 该枚举刻意不包含浮点、tag 和 undefined，从类型层面排除不确定的表示。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// 无符号整数（major type 0）。
    Uint(u64),
    /// 负整数（major type 1），逻辑值为 `-1 - n`。
    Nint(u64),
    /// 字节串（major type 2）。
    Bytes(Vec<u8>),
    /// UTF-8 文本串（major type 3）。
    Text(String),
    /// 数组（major type 4）。
    Array(Vec<Value>),
    /// 映射（major type 5），键已按 canonical 字节升序排序且唯一。
    Map(Vec<(Value, Value)>),
    /// 布尔值。
    Bool(bool),
    /// 空值。
    Null,
}

impl Value {
    /// 由任意键值对构造 map，自动按 canonical 顺序排序并检测重复键。
    pub fn map_from(pairs: impl IntoIterator<Item = (Value, Value)>) -> Result<Value, CborError> {
        let mut items: Vec<(Value, Value)> = pairs.into_iter().collect();
        // 使用 cached key：避免比较过程中反复对同一个键做编码。
        items.sort_by_cached_key(|(key, _)| encode(key));
        for pair in items.windows(2) {
            if pair[0].0 == pair[1].0 {
                return Err(CborError::DuplicateMapKey);
            }
        }
        Ok(Value::Map(items))
    }

    /// 按键查找 map 中的值。
    pub fn get(&self, key: &Value) -> Option<&Value> {
        match self {
            Value::Map(items) => items.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// 取出数组内容，类型不符时报错。
    pub fn as_array(&self) -> Result<&[Value], CborError> {
        match self {
            Value::Array(items) => Ok(items),
            _ => Err(CborError::TypeMismatch { expected: "array" }),
        }
    }

    /// 取出字节串内容，类型不符时报错。
    pub fn as_bytes(&self) -> Result<&[u8], CborError> {
        match self {
            Value::Bytes(bytes) => Ok(bytes),
            _ => Err(CborError::TypeMismatch { expected: "bytes" }),
        }
    }

    /// 取出文本串内容，类型不符时报错。
    pub fn as_text(&self) -> Result<&str, CborError> {
        match self {
            Value::Text(text) => Ok(text),
            _ => Err(CborError::TypeMismatch { expected: "text" }),
        }
    }

    /// 取出无符号整数，类型不符时报错。
    pub fn as_uint(&self) -> Result<u64, CborError> {
        match self {
            Value::Uint(value) => Ok(*value),
            _ => Err(CborError::TypeMismatch { expected: "uint" }),
        }
    }

    /// 取出布尔值，类型不符时报错。
    pub fn as_bool(&self) -> Result<bool, CborError> {
        match self {
            Value::Bool(value) => Ok(*value),
            _ => Err(CborError::TypeMismatch { expected: "bool" }),
        }
    }
}

impl fmt::Display for Value {
    /// 仅用于诊断的简短表示，不输出字节串和文本串的内容。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Uint(v) => write!(f, "uint({v})"),
            Value::Nint(v) => write!(f, "nint(-{})", *v as u128 + 1),
            Value::Bytes(b) => write!(f, "bytes[{}]", b.len()),
            Value::Text(t) => write!(f, "text[{}]", t.len()),
            Value::Array(a) => write!(f, "array[{}]", a.len()),
            Value::Map(m) => write!(f, "map[{}]", m.len()),
            Value::Bool(b) => write!(f, "bool({b})"),
            Value::Null => write!(f, "null"),
        }
    }
}

// ---------------------------------------------------------------------------
// 编码
// ---------------------------------------------------------------------------

/// 将值编码为 canonical CBOR 字节串。
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    encode_into(value, &mut out);
    out
}

fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Uint(v) => write_head(out, 0, *v),
        Value::Nint(v) => write_head(out, 1, *v),
        Value::Bytes(bytes) => {
            write_head(out, 2, bytes.len() as u64);
            out.extend_from_slice(bytes);
        }
        Value::Text(text) => {
            write_head(out, 3, text.len() as u64);
            out.extend_from_slice(text.as_bytes());
        }
        Value::Array(items) => {
            write_head(out, 4, items.len() as u64);
            for item in items {
                encode_into(item, out);
            }
        }
        Value::Map(items) => {
            write_head(out, 5, items.len() as u64);
            for (key, val) in items {
                encode_into(key, out);
                encode_into(val, out);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
    }
}

/// 写入 major type 头部，始终使用最短形式。
fn write_head(out: &mut Vec<u8>, major: u8, argument: u64) {
    let base = major << 5;
    if argument < 24 {
        out.push(base | argument as u8);
    } else if argument <= u8::MAX as u64 {
        out.push(base | 24);
        out.push(argument as u8);
    } else if argument <= u16::MAX as u64 {
        out.push(base | 25);
        out.extend_from_slice(&(argument as u16).to_be_bytes());
    } else if argument <= u32::MAX as u64 {
        out.push(base | 26);
        out.extend_from_slice(&(argument as u32).to_be_bytes());
    } else {
        out.push(base | 27);
        out.extend_from_slice(&argument.to_be_bytes());
    }
}

// ---------------------------------------------------------------------------
// 解码
// ---------------------------------------------------------------------------

/// 严格解码 canonical CBOR，要求输入被完整消费。
pub fn decode(bytes: &[u8]) -> Result<Value, CborError> {
    let mut parser = Parser {
        input: bytes,
        pos: 0,
        nodes: 0,
    };
    let value = parser.parse(0)?;
    let rest = parser.input.len() - parser.pos;
    if rest != 0 {
        return Err(CborError::TrailingBytes(rest));
    }
    Ok(value)
}

/// 在 [`decode`] 的基础上追加一次“重新编码必须逐字节相同”的断言。
///
/// 解码器本身已经拒绝一切非 canonical 表示，这里的再校验属于纵深防御：即便解码器
/// 未来出现回归，非 canonical 的对象也不会被接受进入内容寻址存储。
pub fn decode_canonical(bytes: &[u8]) -> Result<Value, CborError> {
    let value = decode(bytes)?;
    if encode(&value) != bytes {
        return Err(CborError::NotCanonical);
    }
    Ok(value)
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    nodes: usize,
}

impl<'a> Parser<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], CborError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(CborError::LengthOutOfRange)?;
        if end > self.input.len() {
            return Err(CborError::UnexpectedEof);
        }
        let slice = &self.input[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, CborError> {
        Ok(self.take(1)?[0])
    }

    /// 读取头部参数，并要求使用最短编码形式。
    fn argument(&mut self, info: u8) -> Result<u64, CborError> {
        match info {
            0..=23 => Ok(info as u64),
            24 => {
                let v = self.byte()? as u64;
                if v < 24 {
                    return Err(CborError::NonMinimalInteger);
                }
                Ok(v)
            }
            25 => {
                let raw = self.take(2)?;
                let v = u16::from_be_bytes([raw[0], raw[1]]) as u64;
                if v <= u8::MAX as u64 {
                    return Err(CborError::NonMinimalInteger);
                }
                Ok(v)
            }
            26 => {
                let raw = self.take(4)?;
                let v = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as u64;
                if v <= u16::MAX as u64 {
                    return Err(CborError::NonMinimalInteger);
                }
                Ok(v)
            }
            27 => {
                let raw = self.take(8)?;
                let v = u64::from_be_bytes([
                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                ]);
                if v <= u32::MAX as u64 {
                    return Err(CborError::NonMinimalInteger);
                }
                Ok(v)
            }
            31 => Err(CborError::IndefiniteLength),
            _ => Err(CborError::UnsupportedType { major: 0, info }),
        }
    }

    fn parse(&mut self, depth: usize) -> Result<Value, CborError> {
        if depth > MAX_DEPTH {
            return Err(CborError::DepthLimitExceeded);
        }
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(CborError::NodeLimitExceeded);
        }

        let head = self.byte()?;
        let major = head >> 5;
        let info = head & 0x1f;

        match major {
            0 => Ok(Value::Uint(self.argument(info)?)),
            1 => Ok(Value::Nint(self.argument(info)?)),
            2 => {
                let len = self.checked_len(info)?;
                Ok(Value::Bytes(self.take(len)?.to_vec()))
            }
            3 => {
                let len = self.checked_len(info)?;
                let raw = self.take(len)?;
                let text = std::str::from_utf8(raw).map_err(|_| CborError::InvalidUtf8)?;
                Ok(Value::Text(text.to_owned()))
            }
            4 => {
                let len = self.checked_len(info)?;
                let mut items = Vec::with_capacity(len.min(1024));
                for _ in 0..len {
                    items.push(self.parse(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let len = self.checked_len(info)?;
                let mut items: Vec<(Value, Value)> = Vec::with_capacity(len.min(1024));
                let mut previous_key: Option<Vec<u8>> = None;
                for _ in 0..len {
                    let key = self.parse(depth + 1)?;
                    let encoded_key = encode(&key);
                    if let Some(previous) = &previous_key {
                        match encoded_key.cmp(previous) {
                            std::cmp::Ordering::Less => return Err(CborError::UnsortedMapKeys),
                            std::cmp::Ordering::Equal => return Err(CborError::DuplicateMapKey),
                            std::cmp::Ordering::Greater => {}
                        }
                    }
                    previous_key = Some(encoded_key);
                    let value = self.parse(depth + 1)?;
                    items.push((key, value));
                }
                Ok(Value::Map(items))
            }
            7 => match info {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                _ => Err(CborError::UnsupportedType { major: 7, info }),
            },
            _ => Err(CborError::UnsupportedType { major, info }),
        }
    }

    /// 解析长度参数，并保证其不超过剩余输入，避免恶意长度导致的巨额预分配。
    fn checked_len(&mut self, info: u8) -> Result<usize, CborError> {
        let len = self.argument(info)?;
        let remaining = (self.input.len() - self.pos) as u64;
        // 数组/map 的每个元素至少占 1 字节，因此声明长度不可能超过剩余字节数。
        if len > remaining {
            return Err(CborError::LengthOutOfRange);
        }
        Ok(len as usize)
    }
}

// ---------------------------------------------------------------------------
// 类型映射
// ---------------------------------------------------------------------------

/// 领域类型与 canonical CBOR 值之间的双向映射。
pub trait CborCodec: Sized {
    /// 转换为 CBOR 值。
    fn to_value(&self) -> Value;
    /// 从 CBOR 值还原，值不合法时报错。
    fn from_value(value: &Value) -> Result<Self, CborError>;

    /// 直接编码为 canonical CBOR 字节串。
    fn to_canonical_vec(&self) -> Vec<u8> {
        encode(&self.to_value())
    }

    /// 从 canonical CBOR 字节串解码，输入非 canonical 时报错。
    fn from_canonical_slice(bytes: &[u8]) -> Result<Self, CborError> {
        Self::from_value(&decode_canonical(bytes)?)
    }
}

impl CborCodec for u64 {
    fn to_value(&self) -> Value {
        Value::Uint(*self)
    }
    fn from_value(value: &Value) -> Result<Self, CborError> {
        value.as_uint()
    }
}

impl CborCodec for u32 {
    fn to_value(&self) -> Value {
        Value::Uint(*self as u64)
    }
    fn from_value(value: &Value) -> Result<Self, CborError> {
        u32::try_from(value.as_uint()?).map_err(|_| CborError::IntegerOutOfRange)
    }
}

impl CborCodec for u16 {
    fn to_value(&self) -> Value {
        Value::Uint(*self as u64)
    }
    fn from_value(value: &Value) -> Result<Self, CborError> {
        u16::try_from(value.as_uint()?).map_err(|_| CborError::IntegerOutOfRange)
    }
}

impl CborCodec for i64 {
    fn to_value(&self) -> Value {
        if *self >= 0 {
            Value::Uint(*self as u64)
        } else {
            Value::Nint((-(*self + 1)) as u64)
        }
    }
    fn from_value(value: &Value) -> Result<Self, CborError> {
        match value {
            Value::Uint(v) => i64::try_from(*v).map_err(|_| CborError::IntegerOutOfRange),
            Value::Nint(v) => {
                let magnitude = i64::try_from(*v).map_err(|_| CborError::IntegerOutOfRange)?;
                Ok(-magnitude - 1)
            }
            _ => Err(CborError::TypeMismatch {
                expected: "integer",
            }),
        }
    }
}

impl CborCodec for bool {
    fn to_value(&self) -> Value {
        Value::Bool(*self)
    }
    fn from_value(value: &Value) -> Result<Self, CborError> {
        value.as_bool()
    }
}

impl CborCodec for String {
    fn to_value(&self) -> Value {
        Value::Text(self.clone())
    }
    fn from_value(value: &Value) -> Result<Self, CborError> {
        Ok(value.as_text()?.to_owned())
    }
}

impl CborCodec for Vec<u8> {
    fn to_value(&self) -> Value {
        Value::Bytes(self.clone())
    }
    fn from_value(value: &Value) -> Result<Self, CborError> {
        Ok(value.as_bytes()?.to_vec())
    }
}

impl<const N: usize> CborCodec for [u8; N] {
    fn to_value(&self) -> Value {
        Value::Bytes(self.to_vec())
    }
    fn from_value(value: &Value) -> Result<Self, CborError> {
        let bytes = value.as_bytes()?;
        <[u8; N]>::try_from(bytes).map_err(|_| CborError::LengthMismatch { expected: N })
    }
}

impl<T: CborCodec> CborCodec for Option<T> {
    fn to_value(&self) -> Value {
        match self {
            Some(inner) => inner.to_value(),
            None => Value::Null,
        }
    }
    fn from_value(value: &Value) -> Result<Self, CborError> {
        match value {
            Value::Null => Ok(None),
            other => Ok(Some(T::from_value(other)?)),
        }
    }
}

impl<T: CborCodec> CborCodec for Vec<T> {
    fn to_value(&self) -> Value {
        Value::Array(self.iter().map(CborCodec::to_value).collect())
    }
    fn from_value(value: &Value) -> Result<Self, CborError> {
        value.as_array()?.iter().map(T::from_value).collect()
    }
}

impl<K, V> CborCodec for BTreeMap<K, V>
where
    K: CborCodec + Ord,
    V: CborCodec,
{
    fn to_value(&self) -> Value {
        // BTreeMap 已按键的逻辑序排列；这里仍然经过 `map_from` 以键的 canonical
        // 编码字节重新排序，保证与解码端的排序规则完全一致。
        Value::map_from(self.iter().map(|(k, v)| (k.to_value(), v.to_value())))
            .expect("BTreeMap 的键互不相同")
    }
    fn from_value(value: &Value) -> Result<Self, CborError> {
        match value {
            Value::Map(items) => {
                let mut out = BTreeMap::new();
                for (key, val) in items {
                    if out
                        .insert(K::from_value(key)?, V::from_value(val)?)
                        .is_some()
                    {
                        return Err(CborError::DuplicateMapKey);
                    }
                }
                Ok(out)
            }
            _ => Err(CborError::TypeMismatch { expected: "map" }),
        }
    }
}

/// 为“字段固定、编码为 CBOR 数组”的结构体生成 [`CborCodec`] 实现。
///
/// 字段顺序即编码顺序，新增字段必须同时提升所属对象的格式版本号。
#[macro_export]
macro_rules! cbor_struct {
    ($name:ty { $($field:ident : $ty:ty),+ $(,)? }) => {
        impl $crate::cbor::CborCodec for $name {
            fn to_value(&self) -> $crate::cbor::Value {
                $crate::cbor::Value::Array(vec![
                    $( $crate::cbor::CborCodec::to_value(&self.$field) ),+
                ])
            }

            fn from_value(
                value: &$crate::cbor::Value,
            ) -> ::core::result::Result<Self, $crate::cbor::CborError> {
                let items = value.as_array()?;
                let mut iter = items.iter();
                let decoded = Self {
                    $( $field: {
                        let item = iter.next().ok_or($crate::cbor::CborError::ArityMismatch)?;
                        <$ty as $crate::cbor::CborCodec>::from_value(item)?
                    } ),+
                };
                if iter.next().is_some() {
                    return ::core::result::Result::Err($crate::cbor::CborError::ArityMismatch);
                }
                ::core::result::Result::Ok(decoded)
            }
        }
    };
}

/// 为“仅含无载荷变体”的枚举生成 [`CborCodec`] 实现，编码为稳定的文本判别式。
#[macro_export]
macro_rules! cbor_unit_enum {
    ($name:ty { $($variant:path => $tag:literal),+ $(,)? }) => {
        impl $crate::cbor::CborCodec for $name {
            fn to_value(&self) -> $crate::cbor::Value {
                let tag = match self {
                    $( $variant => $tag ),+
                };
                $crate::cbor::Value::Text(tag.to_owned())
            }

            fn from_value(
                value: &$crate::cbor::Value,
            ) -> ::core::result::Result<Self, $crate::cbor::CborError> {
                match value.as_text()? {
                    $( $tag => ::core::result::Result::Ok($variant), )+
                    other => ::core::result::Result::Err(
                        $crate::cbor::CborError::UnknownVariant(other.to_owned()),
                    ),
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_use_shortest_form() {
        assert_eq!(encode(&Value::Uint(0)), vec![0x00]);
        assert_eq!(encode(&Value::Uint(23)), vec![0x17]);
        assert_eq!(encode(&Value::Uint(24)), vec![0x18, 0x18]);
        assert_eq!(encode(&Value::Uint(256)), vec![0x19, 0x01, 0x00]);
        assert_eq!(
            encode(&Value::Uint(65_536)),
            vec![0x1a, 0x00, 0x01, 0x00, 0x00]
        );
    }

    #[test]
    fn rejects_non_minimal_integer() {
        // 0x18 0x00 表示“用 1 字节编码 0”，非最短形式。
        assert_eq!(decode(&[0x18, 0x00]), Err(CborError::NonMinimalInteger));
        // 0x19 0x00 0x17 表示“用 2 字节编码 23”，非最短形式。
        assert_eq!(
            decode(&[0x19, 0x00, 0x17]),
            Err(CborError::NonMinimalInteger)
        );
    }

    #[test]
    fn rejects_indefinite_length() {
        assert_eq!(decode(&[0x5f, 0xff]), Err(CborError::IndefiniteLength));
        assert_eq!(decode(&[0x9f, 0xff]), Err(CborError::IndefiniteLength));
    }

    #[test]
    fn rejects_floats_and_tags() {
        // major type 7 / info 26 是 float32。
        assert!(matches!(
            decode(&[0xfa, 0x00, 0x00, 0x00, 0x00]),
            Err(CborError::UnsupportedType { major: 7, .. })
        ));
        // major type 6 是 tag。
        assert!(matches!(
            decode(&[0xc0, 0x00]),
            Err(CborError::UnsupportedType { major: 6, .. })
        ));
    }

    #[test]
    fn rejects_unsorted_and_duplicate_map_keys() {
        // {"b": 1, "a": 1}：键顺序错误。
        let unsorted = vec![0xa2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x01];
        assert_eq!(decode(&unsorted), Err(CborError::UnsortedMapKeys));
        // {"a": 1, "a": 1}：键重复。
        let duplicate = vec![0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x01];
        assert_eq!(decode(&duplicate), Err(CborError::DuplicateMapKey));
    }

    #[test]
    fn rejects_trailing_bytes() {
        assert_eq!(decode(&[0x00, 0x00]), Err(CborError::TrailingBytes(1)));
    }

    #[test]
    fn map_from_sorts_by_encoded_key() {
        let value = Value::map_from([
            (Value::Text("zulu".into()), Value::Uint(1)),
            (Value::Text("a".into()), Value::Uint(2)),
            (Value::Uint(7), Value::Uint(3)),
        ])
        .expect("键互不相同");
        let Value::Map(items) = &value else {
            panic!("应为 map")
        };
        // canonical 顺序先比较编码字节：uint(7)=0x07 < text("a")=0x6161 < text("zulu")。
        assert_eq!(items[0].0, Value::Uint(7));
        assert_eq!(items[1].0, Value::Text("a".into()));
        assert_eq!(items[2].0, Value::Text("zulu".into()));
        // 编码后可以被严格解码器接受。
        assert_eq!(decode_canonical(&encode(&value)).unwrap(), value);
    }

    #[test]
    fn depth_limit_is_enforced() {
        // 构造 MAX_DEPTH + 2 层嵌套数组。
        let mut bytes = vec![0x81u8; MAX_DEPTH + 2];
        bytes.push(0x00);
        assert_eq!(decode(&bytes), Err(CborError::DepthLimitExceeded));
    }

    #[test]
    fn oversized_length_is_rejected_before_allocation() {
        // 声明 2^32-1 个数组元素，但输入只有几个字节。
        assert_eq!(
            decode(&[0x9a, 0xff, 0xff, 0xff, 0xff]),
            Err(CborError::LengthOutOfRange)
        );
    }

    #[test]
    fn round_trip_is_byte_identical() {
        let value = Value::Array(vec![
            Value::Uint(1),
            Value::Nint(0),
            Value::Bytes(vec![1, 2, 3]),
            Value::Text("中文".into()),
            Value::Bool(true),
            Value::Null,
            Value::map_from([(Value::Text("k".into()), Value::Uint(9))]).unwrap(),
        ]);
        let bytes = encode(&value);
        assert_eq!(decode_canonical(&bytes).unwrap(), value);
        assert_eq!(encode(&decode(&bytes).unwrap()), bytes);
    }

    #[test]
    fn signed_integers_round_trip() {
        for candidate in [i64::MIN, -1, 0, 1, i64::MAX] {
            let value = candidate.to_value();
            assert_eq!(i64::from_value(&value).unwrap(), candidate);
        }
    }
}
