//! 输出层：JSON 信封、人类可读渲染与统一脱敏器。
//!
//! 三条硬性约束：
//!
//! 1. **`--json` 时 stdout 只有一行 JSON。** 所有日志、进度、错误说明都写 stderr，
//!    否则调用方无法用 `envsync ... --json | jq` 这种最自然的方式消费输出。
//! 2. **JSON 是对外契约。** 信封字段固定为
//!    `{schema_version, command, status, data, diagnostics}`，`data` 由每个命令自己的
//!    具名结构体定义（见 [`crate::commands`]），因此字段增删会被 golden test 抓住。
//! 3. **所有输出都过一遍脱敏器。** 人类可读文本走 [`redact_text`]，JSON 走
//!    [`redact_json`]；秘密不应该因为“换了一条输出路径”而泄露。

use serde::Serialize;
use serde_json::Value;

/// JSON 契约的**当前** schema 版本，也是 `--schema-version` 的默认值。
///
/// M1 把它提升到 2：`status` 增加 `open_conflicts`、`plan` 增加 `device_view`，并新增
/// `fetch` / `merge` / `conflicts` / `profile` 四组命令。
pub const JSON_SCHEMA_VERSION: u32 = 2;

/// 仍然可以被请求的最低 schema 版本。
///
/// 老脚本可以显式要求 v1：输出会退回 v1 的字段集合（v2 新增字段被剔除）。范围之外
/// 的版本号一律报错——静默按某个版本输出会让调用方以为自己拿到了别的形状。
pub const MIN_JSON_SCHEMA_VERSION: u32 = 1;

/// 脱敏后的占位文本。
pub const REDACTED: &str = "<redacted>";

/// 命令执行状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// 命令成功。
    Ok,
    /// 命令失败；此时 `data` 为 `null`，`diagnostics` 至少有一条。
    Error,
}

/// JSON 契约里的一条诊断。
///
/// 字段与 [`envsync_domain::Diagnostic`] 一一对应，另外复用同一结构承载
/// [`envsync_core::CoreError`]：错误码就是 `code`，因此调用方只需要解析一种形状。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiagnosticOut {
    /// 严重级别：`blocking` / `warning` / `info`。
    pub severity: &'static str,
    /// 稳定的机器可读错误码。
    pub code: String,
    /// 关联资源；与具体资源无关时为 `null`。
    pub resource: Option<String>,
    /// 人类可读说明。
    pub message: String,
}

impl DiagnosticOut {
    /// 由核心层错误构造一条阻塞级诊断。
    pub fn from_error(error: &envsync_core::CoreError) -> Self {
        DiagnosticOut {
            severity: "blocking",
            code: error.code().to_owned(),
            resource: None,
            message: error.to_string(),
        }
    }

    /// 构造一条 `info` 级诊断（说明性信息，不代表任何问题）。
    pub fn info(code: &str, message: String) -> Self {
        DiagnosticOut {
            severity: "info",
            code: code.to_owned(),
            resource: None,
            message,
        }
    }

    /// 构造一条 `warning` 级诊断（值得注意，但不阻塞本次命令）。
    pub fn warning(code: &str, message: String) -> Self {
        DiagnosticOut {
            severity: "warning",
            code: code.to_owned(),
            resource: None,
            message,
        }
    }

    /// 单行人类可读表示。
    pub fn render(&self) -> String {
        match &self.resource {
            Some(resource) => format!(
                "  [{}] {}（{}）：{}",
                self.severity, self.code, resource, self.message
            ),
            None => format!("  [{}] {}：{}", self.severity, self.code, self.message),
        }
    }
}

impl From<&envsync_domain::Diagnostic> for DiagnosticOut {
    fn from(diagnostic: &envsync_domain::Diagnostic) -> Self {
        DiagnosticOut {
            severity: match diagnostic.severity {
                envsync_domain::Severity::Blocking => "blocking",
                envsync_domain::Severity::Warning => "warning",
                envsync_domain::Severity::Info => "info",
            },
            code: diagnostic.code.clone(),
            resource: diagnostic.resource.as_ref().map(|id| id.to_string()),
            message: diagnostic.message.clone(),
        }
    }
}

/// JSON 信封。
///
/// 用泛型持有 `data` 的引用而不是提前转成 [`Value`]，是为了让每个命令的数据结构
/// 保持强类型：字段名写错在编译期就会失败。
#[derive(Serialize)]
struct Envelope<'a, T: Serialize> {
    schema_version: u32,
    command: &'a str,
    status: Status,
    data: Option<&'a T>,
    diagnostics: &'a [DiagnosticOut],
}

/// 把结果渲染成**单行** JSON 并写 stdout。
///
/// `schema_version` 为 1 时输出会退回 v1 形状：`v2_only` 列出的字段从 `data` 中移除。
/// 这是**唯一**的降级手段——v1 与 v2 的差异只有「v2 多了哪些字段」，因此剔除即可，
/// 不需要为每个命令维护两份结构体。
///
/// 序列化失败时不 panic，而是退化成一条 `internal.serialize` 错误信封——CLI 的
/// 最后一步不应该因为格式化问题把整个进程炸掉。
pub fn print_json<T: Serialize>(
    command: &str,
    status: Status,
    schema_version: u32,
    data: Option<&T>,
    diagnostics: &[DiagnosticOut],
    v2_only: &[&str],
) {
    let envelope = Envelope {
        schema_version,
        command,
        status,
        data,
        diagnostics,
    };
    let mut value = match serde_json::to_value(&envelope) {
        Ok(value) => value,
        Err(error) => fallback_envelope(command, schema_version, &error.to_string()),
    };
    if schema_version < JSON_SCHEMA_VERSION {
        downgrade(&mut value, v2_only);
    }
    redact_json(&mut value);
    // `Value` 的 `Display` 是紧凑格式，天然保证「只有一行」。
    println!("{value}");
}

/// 把 `data` 降级到 v1 形状：移除 v2 才引入的字段。
fn downgrade(envelope: &mut Value, v2_only: &[&str]) {
    let Some(Value::Object(data)) = envelope.get_mut("data") else {
        return;
    };
    for field in v2_only {
        data.remove(*field);
    }
}

/// 序列化失败时的兜底信封。
fn fallback_envelope(command: &str, schema_version: u32, message: &str) -> Value {
    let diagnostic = DiagnosticOut {
        severity: "blocking",
        code: "internal.serialize".to_owned(),
        resource: None,
        message: message.to_owned(),
    };
    serde_json::json!({
        "schema_version": schema_version,
        "command": command,
        "status": "error",
        "data": Value::Null,
        "diagnostics": [{
            "severity": diagnostic.severity,
            "code": diagnostic.code,
            "resource": Value::Null,
            "message": diagnostic.message,
        }],
    })
}

/// 人类可读的成功输出：正文写 stdout，诊断写 stderr。
///
/// 诊断走 stderr 是为了让 `envsync plan > plan.txt` 这类用法只拿到正文。
pub fn print_human(body: &str, diagnostics: &[DiagnosticOut]) {
    let body = redact_text(body);
    if !body.is_empty() {
        println!("{body}");
    }
    print_human_diagnostics(diagnostics);
}

/// 人类可读的失败输出：全部写 stderr。
pub fn print_human_error(error: &envsync_core::CoreError, diagnostics: &[DiagnosticOut]) {
    eprintln!("错误：{}", redact_text(&error.to_string()));
    eprintln!("错误码：{}", error.code());
    print_human_diagnostics(diagnostics);
}

/// 把诊断逐条写 stderr。
fn print_human_diagnostics(diagnostics: &[DiagnosticOut]) {
    if diagnostics.is_empty() {
        return;
    }
    eprintln!("诊断（{} 条）：", diagnostics.len());
    for diagnostic in diagnostics {
        eprintln!("{}", redact_text(&diagnostic.render()));
    }
}

// ---------------------------------------------------------------------------
// 脱敏器
//
// 没有引入正则依赖：规则少而固定，手写扫描既可读又不会因为回溯而变慢，还避免了
// 「正则写错导致整段输出消失」这种更糟糕的失败模式。
// ---------------------------------------------------------------------------

/// 会触发脱敏的键名词根（已去掉 `-`/`_` 并转小写）。
///
/// 用「包含」而不是「相等」匹配，所以 `access_token`、`client-secret`、`X-Api-Key`
/// 这些常见变体都会命中。宁可多脱敏一个无害字段，也不能漏掉一个真正的秘密。
const SENSITIVE_WORDS: [&str; 6] = [
    "token",
    "secret",
    "password",
    "apikey",
    "authorization",
    "bearer",
];

/// `bearer <token>` 中令牌的最短长度；太短的词更可能是普通英文而不是令牌。
const MIN_BEARER_LEN: usize = 8;

/// 判断键名是否敏感。大小写不敏感，且忽略 `-`/`_` 分隔符。
pub fn is_sensitive_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|ch| *ch != '-' && *ch != '_')
        .flat_map(char::to_lowercase)
        .collect();
    SENSITIVE_WORDS.iter().any(|word| normalized.contains(word))
}

/// 就地脱敏一棵 JSON 树。
///
/// * 对象：键名敏感时**整个值**（哪怕是对象或数组）替换为 [`REDACTED`]；
/// * 数组：逐元素递归；
/// * 字符串：再跑一遍 [`redact_text`]，覆盖「值里藏着 `bearer xxx`」的情况。
pub fn redact_json(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if is_sensitive_key(key) {
                    *child = Value::String(REDACTED.to_owned());
                } else {
                    redact_json(child);
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                redact_json(item);
            }
        }
        Value::String(text) => {
            let redacted = redact_text(text);
            if &redacted != text {
                *text = redacted;
            }
        }
        _ => {}
    }
}

/// 脱敏一段纯文本。
///
/// 两条规则：
///
/// 1. `bearer <令牌>`（大小写不敏感，令牌至少 [`MIN_BEARER_LEN`] 个 `[A-Za-z0-9._-]`）；
/// 2. `<敏感键><=|:><值>`，值必须以 ASCII 字母或数字开头。
///
/// 第 2 条刻意要求值以 ASCII 开头：这样 `token: 已失效` 这类中文说明不会被误吃掉，
/// 而 `api_key=AKIA...` 一定会被拦下。
pub fn redact_text(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    // `copied` 之前的内容都已经写进 `out`；命中脱敏时才需要提前 flush。
    let mut copied = 0usize;
    let mut index = 0usize;

    while index < bytes.len() {
        if !is_ident_byte(bytes[index]) {
            // 非 ASCII 标识符字节：多字节 UTF-8 的任何一个字节都 >= 0x80，
            // 因此逐字节前进不会切开字符（切片只发生在 ASCII 边界上）。
            index += 1;
            continue;
        }
        let start = index;
        let end = ident_end(bytes, start);
        index = end;
        let word = &text[start..end];

        let hit = if word.eq_ignore_ascii_case("bearer") {
            bearer_value(bytes, end)
        } else {
            None
        }
        .or_else(|| {
            if is_sensitive_key(word) {
                keyed_value(bytes, end)
            } else {
                None
            }
        });

        if let Some((value_start, value_end)) = hit {
            out.push_str(&text[copied..value_start]);
            out.push_str(REDACTED);
            copied = value_end;
            index = value_end;
        }
    }
    out.push_str(&text[copied..]);
    out
}

/// 标识符字节：ASCII 字母数字加 `_`、`-`。
fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

/// 令牌字节：`[A-Za-z0-9._-]`。
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'_' || byte == b'-'
}

/// 从 `start` 起的标识符结束位置。
fn ident_end(bytes: &[u8], start: usize) -> usize {
    let mut index = start;
    while index < bytes.len() && is_ident_byte(bytes[index]) {
        index += 1;
    }
    index
}

/// 跳过空格与制表符。
fn skip_blank(bytes: &[u8], from: usize) -> usize {
    let mut index = from;
    while index < bytes.len() && (bytes[index] == b' ' || bytes[index] == b'\t') {
        index += 1;
    }
    index
}

/// `bearer` 之后的令牌区间。
fn bearer_value(bytes: &[u8], from: usize) -> Option<(usize, usize)> {
    let start = skip_blank(bytes, from);
    if start == from {
        // `bearer` 后必须紧跟空白，否则命中的只是 `bearerish` 这类普通单词。
        return None;
    }
    let mut end = start;
    while end < bytes.len() && is_token_byte(bytes[end]) {
        end += 1;
    }
    if end - start < MIN_BEARER_LEN {
        return None;
    }
    Some((start, end))
}

/// `key = value` / `key: value` 中值的区间。
fn keyed_value(bytes: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut index = from;
    // 键可能被引号包着：`"api_key": "..."`。
    if matches!(bytes.get(index), Some(b'"' | b'\'')) {
        index += 1;
    }
    index = skip_blank(bytes, index);
    if !matches!(bytes.get(index), Some(b'=' | b':')) {
        return None;
    }
    index = skip_blank(bytes, index + 1);
    if matches!(bytes.get(index), Some(b'"' | b'\'')) {
        index += 1;
    }

    let start = index;
    let mut end = value_end(bytes, start);
    if end == start || !bytes[start].is_ascii_alphanumeric() {
        return None;
    }

    // `Authorization: Bearer <令牌>`：值本身是 `bearer` 前缀时要连令牌一起吃掉，
    // 否则只会脱掉 “Bearer” 这个无害的词，真正的令牌反而留在输出里。
    if bytes[start..end].eq_ignore_ascii_case(b"bearer") {
        let token_start = skip_blank(bytes, end);
        let mut token_end = token_start;
        while token_end < bytes.len() && is_token_byte(bytes[token_end]) {
            token_end += 1;
        }
        if token_end > token_start {
            end = token_end;
        }
    }
    Some((start, end))
}

/// 值的结束位置：吃到空白、非 ASCII 或常见分隔符为止。
fn value_end(bytes: &[u8], from: usize) -> usize {
    let mut index = from;
    while index < bytes.len() {
        let byte = bytes[index];
        if !byte.is_ascii_graphic() {
            break;
        }
        if matches!(byte, b'"' | b'\'' | b',' | b';' | b')' | b']' | b'}' | b'>') {
            break;
        }
        index += 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sensitive_key_variants_are_detected() {
        for key in [
            "token",
            "TOKEN",
            "api_key",
            "API-KEY",
            "apiKey",
            "access_token",
            "client-secret",
            "Password",
            "Authorization",
            "bearer",
        ] {
            assert!(is_sensitive_key(key), "`{key}` 应当被判定为敏感键名");
        }
        for key in ["resource", "revision", "state", "operation", "code", "head"] {
            assert!(!is_sensitive_key(key), "`{key}` 不应当被判定为敏感键名");
        }
    }

    #[test]
    fn json_sensitive_key_variants_are_replaced() {
        let mut value = json!({
            "token": "abc",
            "API-KEY": "def",
            "access_token": "ghi",
            "PassWord": "jkl",
            "authorization": "mno",
            "revision": 7,
        });
        redact_json(&mut value);
        for key in [
            "token",
            "API-KEY",
            "access_token",
            "PassWord",
            "authorization",
        ] {
            assert_eq!(value[key], json!(REDACTED), "键 `{key}` 未被脱敏");
        }
        // 非敏感字段必须原样保留，否则输出就没法用了。
        assert_eq!(value["revision"], json!(7));
    }

    #[test]
    fn json_nested_objects_and_arrays_are_redacted() {
        let mut value = json!({
            "data": {
                "resources": [
                    { "resource": "shell/zsh/main", "secret": "s3cr3t" },
                    { "resource": "git/config", "nested": { "api_key": "AKIA0000" } },
                ],
            },
            "diagnostics": [
                { "code": "resource.unreadable", "message": "请求头 bearer abcdefgh12345678 被拒绝" },
            ],
        });
        redact_json(&mut value);

        assert_eq!(value["data"]["resources"][0]["secret"], json!(REDACTED));
        assert_eq!(
            value["data"]["resources"][0]["resource"],
            json!("shell/zsh/main")
        );
        assert_eq!(
            value["data"]["resources"][1]["nested"]["api_key"],
            json!(REDACTED)
        );
        assert_eq!(
            value["diagnostics"][0]["message"],
            json!("请求头 bearer <redacted> 被拒绝")
        );
        assert_eq!(
            value["diagnostics"][0]["code"],
            json!("resource.unreadable")
        );
    }

    #[test]
    fn sensitive_key_replaces_whole_subtree() {
        let mut value = json!({ "secrets": { "a": 1, "b": [1, 2, 3] } });
        redact_json(&mut value);
        assert_eq!(value["secrets"], json!(REDACTED));
    }

    #[test]
    fn plain_text_bearer_token_is_redacted() {
        assert_eq!(
            redact_text("请在请求头写 Bearer eyJhbGciOi.J9abcdef 才能访问"),
            "请在请求头写 Bearer <redacted> 才能访问"
        );
        assert_eq!(
            redact_text("Authorization: Bearer abcdefgh12345678"),
            "Authorization: <redacted>"
        );
        assert_eq!(
            redact_text("authorization=bearer abcdefgh12345678, next"),
            "authorization=<redacted>, next"
        );
    }

    #[test]
    fn plain_text_key_value_is_redacted() {
        assert_eq!(redact_text("api_key=AKIA0123456789"), "api_key=<redacted>");
        assert_eq!(
            redact_text("配置里写着 password: hunter2 请更换"),
            "配置里写着 password: <redacted> 请更换"
        );
        assert_eq!(
            redact_text("{\"secret\": \"s3cr3t\"}"),
            "{\"secret\": \"<redacted>\"}"
        );
    }

    #[test]
    fn ordinary_content_is_untouched() {
        // 资源 ID 里含 “token” 字样，但既不是键值对也不是 bearer 令牌。
        let text = "资源 shell/token/main 已同步，token 数量为 3";
        assert_eq!(redact_text(text), text);

        // 冒号后面是中文说明，不是秘密。
        let text = "计划失效：token 已过期，请重新 plan";
        assert_eq!(redact_text(text), text);

        // 非敏感键的键值对完全不受影响。
        let text = "revision=7 state=drifted resource=shell/zsh/main";
        assert_eq!(redact_text(text), text);

        // `bearer` 后面没有足够长的令牌时不动。
        let text = "bearer 短";
        assert_eq!(redact_text(text), text);

        // 空串与纯中文。
        assert_eq!(redact_text(""), "");
        assert_eq!(redact_text("工作区已收敛"), "工作区已收敛");
    }

    #[test]
    fn envelope_fields_are_stable() {
        #[derive(Serialize)]
        struct Data {
            value: u32,
        }
        let value = serde_json::to_value(Envelope {
            schema_version: JSON_SCHEMA_VERSION,
            command: "status",
            status: Status::Ok,
            data: Some(&Data { value: 1 }),
            diagnostics: &[],
        })
        .expect("信封必须可序列化");

        // `serde_json` 的对象是有序 map（按键名排序），因此这个集合是稳定可断言的。
        let keys: Vec<&str> = value
            .as_object()
            .expect("信封是对象")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            ["command", "data", "diagnostics", "schema_version", "status"]
        );
        assert_eq!(value["status"], json!("ok"));
    }

    #[test]
    fn error_envelope_has_null_data() {
        let value = serde_json::to_value(Envelope::<()> {
            schema_version: JSON_SCHEMA_VERSION,
            command: "sync",
            status: Status::Error,
            data: None,
            diagnostics: &[DiagnosticOut {
                severity: "blocking",
                code: "plan.stale".to_owned(),
                resource: None,
                message: "计划已失效".to_owned(),
            }],
        })
        .expect("信封必须可序列化");

        assert_eq!(value["data"], Value::Null);
        assert_eq!(value["status"], json!("error"));
        assert_eq!(value["diagnostics"][0]["code"], json!("plan.stale"));
        assert_eq!(value["diagnostics"][0]["resource"], Value::Null);
    }
}
