//! TOML 语义三方合并（基于 `toml_edit`，**保留注释与格式**）。
//!
//! ## 合并规则
//!
//! - 表（`[table]`、内联表、dotted key）按 key 独立合并；**数组与 array-of-tables
//!   是原子值**。
//! - 结果文档以 **ours 的文档为骨架**克隆而来，因此 ours 未被改动的部分连注释、
//!   空行、引号风格都逐字保留；被 theirs 改动的 key 会连同 **theirs 的格式**一起
//!   写入。
//! - 一侧删除 key、另一侧修改同一 key → 冲突，诊断记录键路径。
//! - 重复 key 与无效 TOML 由 `toml_edit` 拒绝，映射为
//!   [`MergeError::DuplicateKey`] / [`MergeError::Parse`]，诊断只含**位置**。
//!
//! ## 已知限制
//!
//! - 从 theirs 新增的 key 会追加到对应表的末尾，可能与 ours 的原有排版顺序不同。
//! - ours 是内联表而 theirs 的对应子项是标准表时，写入会被转换成内联表形式；
//!   语义不变，排版可能变化。

use envsync_domain::StructuredFormat;
use toml_edit::{DocumentMut, Item, TableLike, Value};

use super::{
    child_pointer, classify, structured_conflict, Budget, ConflictShape, KeyConflict, MergeError,
    MergeInput, MergeProvenance, MergeResult, Plain, Presence,
};

const FORMAT: StructuredFormat = StructuredFormat::Toml;

/// TOML 三方合并入口。
pub fn merge_toml(input: &MergeInput<'_>) -> Result<MergeResult, MergeError> {
    let (base, ours, theirs) = match classify(input) {
        Presence::Decided(result) => return Ok(result),
        Presence::Both { base, ours, theirs } => (base, ours, theirs),
    };

    let base_doc = base.map(parse_strict).transpose()?;
    let ours_doc = parse_strict(ours)?;
    let theirs_doc = parse_strict(theirs)?;

    let mut conflicts = Vec::new();
    let mut provenance = MergeProvenance::default();

    let mut merged = ours_doc.clone();
    merge_table(
        base_doc
            .as_ref()
            .map(|doc| doc.as_table() as &dyn TableLike),
        ours_doc.as_table() as &dyn TableLike,
        theirs_doc.as_table() as &dyn TableLike,
        merged.as_table_mut() as &mut dyn TableLike,
        "",
        &mut conflicts,
        &mut provenance,
    );

    if !conflicts.is_empty() {
        return Ok(MergeResult::Conflict(structured_conflict(
            input, &conflicts,
        )));
    }

    let bytes = merged.to_string().into_bytes();
    let reparsed = parse_strict(&bytes)?;
    if table_plain(reparsed.as_table()) != table_plain(merged.as_table()) {
        return Err(MergeError::RenderVerificationFailed { format: FORMAT });
    }

    Ok(MergeResult::Clean {
        bytes,
        provenance: provenance.note("toml 按 key 合并并保留 ours 的注释与格式"),
    })
}

/// 解析并施加深度 / 节点上限。
pub(crate) fn parse_strict(bytes: &[u8]) -> Result<DocumentMut, MergeError> {
    let text = std::str::from_utf8(bytes).map_err(|err| MergeError::Parse {
        format: FORMAT,
        detail: format!("invalid utf-8 at byte {}", err.valid_up_to()),
    })?;
    let doc: DocumentMut = text.parse().map_err(|err| classify_error(text, &err))?;
    let mut budget = Budget::new();
    charge_table(doc.as_table(), 1, &mut budget)?;
    Ok(doc)
}

/// 把 `toml_edit` 的解析错误映射为结构化错误，只保留键名与位置。
fn classify_error(text: &str, err: &toml_edit::TomlError) -> MergeError {
    let message = err.message();
    let position = err
        .span()
        .map(|span| {
            let line = text[..span.start.min(text.len())].matches('\n').count() + 1;
            format!("line {line}")
        })
        .unwrap_or_else(|| "unknown position".to_owned());
    if message.contains("duplicate key") {
        // `toml_edit` 的消息里不带键名，但 span 精确指向重复的键，取该片段即可
        // 得到键名本身（键名属于允许出现在诊断里的结构信息）。
        let key = err
            .span()
            .and_then(|span| text.get(span))
            .map(str::to_owned)
            .unwrap_or_else(|| "<unknown>".to_owned());
        return MergeError::DuplicateKey {
            pointer: child_pointer("", &key),
        };
    }
    MergeError::Parse {
        format: FORMAT,
        detail: format!("invalid toml at {position}"),
    }
}

fn charge_table(
    table: &dyn TableLike,
    depth: usize,
    budget: &mut Budget,
) -> Result<(), MergeError> {
    budget.charge(depth)?;
    for (_, item) in table.iter() {
        charge_item(item, depth + 1, budget)?;
    }
    Ok(())
}

fn charge_item(item: &Item, depth: usize, budget: &mut Budget) -> Result<(), MergeError> {
    budget.charge(depth)?;
    match item {
        Item::None => Ok(()),
        Item::Value(value) => charge_value(value, depth + 1, budget),
        Item::Table(table) => charge_table(table, depth + 1, budget),
        Item::ArrayOfTables(array) => {
            for table in array.iter() {
                charge_table(table, depth + 1, budget)?;
            }
            Ok(())
        }
    }
}

fn charge_value(value: &Value, depth: usize, budget: &mut Budget) -> Result<(), MergeError> {
    budget.charge(depth)?;
    match value {
        Value::Array(array) => {
            for item in array.iter() {
                charge_value(item, depth + 1, budget)?;
            }
            Ok(())
        }
        Value::InlineTable(table) => {
            for (_, item) in table.iter() {
                charge_value(item, depth + 1, budget)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// 取出「真实存在」的子项：`Item::None` 视为不存在。
fn present<'a>(table: &'a dyn TableLike, key: &str) -> Option<&'a Item> {
    table.get(key).filter(|item| !item.is_none())
}

/// 按有序键并集逐键合并，把结果写进 `result`（`result` 初始为 ours 的克隆）。
#[allow(clippy::too_many_arguments)]
fn merge_table(
    base: Option<&dyn TableLike>,
    ours: &dyn TableLike,
    theirs: &dyn TableLike,
    result: &mut dyn TableLike,
    pointer: &str,
    conflicts: &mut Vec<KeyConflict>,
    provenance: &mut MergeProvenance,
) {
    let mut keys: Vec<String> = Vec::new();
    let base_keys = base.map(|t| t.iter().map(|(k, _)| k.to_owned()).collect::<Vec<_>>());
    for key in base_keys
        .iter()
        .flatten()
        .cloned()
        .chain(ours.iter().map(|(k, _)| k.to_owned()))
        .chain(theirs.iter().map(|(k, _)| k.to_owned()))
    {
        if !keys.contains(&key) {
            keys.push(key);
        }
    }

    for key in keys {
        let pointer = child_pointer(pointer, &key);
        let base_child = base.and_then(|t| present(t, &key));
        let ours_child = present(ours, &key);
        let theirs_child = present(theirs, &key);
        let merged = merge_item(
            base_child,
            ours_child,
            theirs_child,
            &pointer,
            conflicts,
            provenance,
        );
        match merged {
            None => {
                result.remove(&key);
            }
            Some(item) => {
                // 只在语义确实变化时写回，未变化的 key 保留 ours 的原始排版。
                // `TableLike::insert` 对内联表会自动把 `Item::Table` 折叠成内联表，
                // 因此这里无需区分父表类型。
                let unchanged = ours_child.map(item_plain) == Some(item_plain(&item));
                if !unchanged {
                    result.insert(&key, item);
                }
            }
        }
    }
}

/// 单个 `Item` 的三方合并。返回 `None` 表示该键在结果中不存在。
fn merge_item(
    base: Option<&Item>,
    ours: Option<&Item>,
    theirs: Option<&Item>,
    pointer: &str,
    conflicts: &mut Vec<KeyConflict>,
    provenance: &mut MergeProvenance,
) -> Option<Item> {
    let base_plain = base.map(item_plain);
    let ours_plain = ours.map(item_plain);
    let theirs_plain = theirs.map(item_plain);

    if ours_plain == theirs_plain {
        if base_plain == ours_plain {
            provenance.took_base += 1;
        } else {
            provenance.took_ours += 1;
            provenance.took_theirs += 1;
        }
        return ours.cloned();
    }
    if base_plain == ours_plain {
        provenance.took_theirs += 1;
        return theirs.cloned();
    }
    if base_plain == theirs_plain {
        provenance.took_ours += 1;
        return ours.cloned();
    }

    // 双方改动不同：只有两侧都是表时才继续下钻。
    if let (Some(ours_item), Some(theirs_item)) = (ours, theirs) {
        if let (Some(ours_table), Some(theirs_table)) =
            (ours_item.as_table_like(), theirs_item.as_table_like())
        {
            let mut merged = ours_item.clone();
            let result_table = merged
                .as_table_like_mut()
                .expect("clone of table-like is table-like");
            merge_table(
                base.and_then(Item::as_table_like),
                ours_table,
                theirs_table,
                result_table,
                pointer,
                conflicts,
                provenance,
            );
            return Some(merged);
        }
    }

    conflicts.push(KeyConflict {
        pointer: if pointer.is_empty() {
            "/".to_owned()
        } else {
            pointer.to_owned()
        },
        shape: if ours.is_none() || theirs.is_none() {
            ConflictShape::DeleteModify
        } else {
            ConflictShape::ModifyModify
        },
    });
    ours.or(theirs).cloned()
}

/// 与格式无关的语义视图，用于比较与渲染后校验（忽略注释、空白、引号风格）。
pub(crate) fn table_plain(table: &dyn TableLike) -> Plain {
    Plain::map(
        table
            .iter()
            .filter(|(_, item)| !item.is_none())
            .map(|(key, item)| (key.to_owned(), item_plain(item)))
            .collect(),
    )
}

fn item_plain(item: &Item) -> Plain {
    match item {
        Item::None => Plain::Null,
        Item::Value(value) => value_plain(value),
        Item::Table(table) => table_plain(table),
        Item::ArrayOfTables(array) => Plain::Seq(
            array
                .iter()
                .map(|t| table_plain(t as &dyn TableLike))
                .collect(),
        ),
    }
}

fn value_plain(value: &Value) -> Plain {
    match value {
        Value::String(v) => Plain::Str(v.value().clone()),
        Value::Integer(v) => Plain::Num(v.value().to_string()),
        Value::Float(v) => Plain::Num(format!("{:?}", v.value())),
        Value::Boolean(v) => Plain::Bool(*v.value()),
        Value::Datetime(v) => Plain::Str(v.value().to_string()),
        Value::Array(array) => Plain::Seq(array.iter().map(value_plain).collect()),
        Value::InlineTable(table) => Plain::map(
            table
                .iter()
                .map(|(key, value)| (key.to_owned(), value_plain(value)))
                .collect(),
        ),
    }
}
