//! Git 后端的**认证配置与凭据隔离**。
//!
//! 本模块只做三件事：
//!
//! 1. 把允许的认证方式收敛成一个封闭枚举 [`GitAuth`]，其他配置形式（用户名 + 密码、
//!    URL 内嵌 token、明文文件……）在类型层面就无法表达；
//! 2. 在打开后端**之前**校验远端 URL（[`validate_remote_url`]），把凭据挡在配置边界外；
//! 3. 提供 [`redacted_remote`] 与 [`remote_host`]，保证日志、诊断和错误信息里永远只出现
//!    脱敏后的远端标识。
//!
//! ## 凭据永不进入进程状态
//!
//! EnvSync 自己**不解析、不保存、不传递**任何密钥或 token：
//!
//! * [`GitAuth::SshAgent`]：私钥留在 ssh-agent 里，本进程只拿到签名结果；
//! * [`GitAuth::CredentialHelper`]：凭据由 git 的 credential helper 现取现用；
//! * [`GitAuth::TokenSecretRef`]：只保存一个**引用**（secret 的 id），M2 的 Vault 落地
//!   之前不解析它，因此进程内不存在可被 dump 的 token。
//!
//! ## 错误信息为什么只用静态字符串
//!
//! 所有拒绝路径都返回 [`BackendError::Unsupported`]，其载荷是 `&'static str`。这不是偷懒：
//! 静态字符串在类型层面就不可能插值进用户提供的 URL，于是「错误信息泄漏凭据」这条风险
//! 被编译器消除，而不是靠代码评审保证。

use crate::BackendError;

/// 远端 URL 的长度上限；超过一律拒绝，避免把超长输入塞进日志。
const MAX_URL_LEN: usize = 2048;

/// secret 引用标识的长度上限。
const MAX_SECRET_ID_LEN: usize = 128;

/// 脱敏后用于替换 userinfo 的占位符。
const USERINFO_MASK: &str = "***";

/// 脱敏后用于替换查询串的占位符。
const QUERY_MASK: &str = "<redacted>";

/// 本地文件系统远端在日志中的占位符。
///
/// 本地路径既可能暴露用户名（`/home/<user>/…`）又属于本机信息，因此一律不进日志。
const LOCAL_PLACEHOLDER: &str = "<local>";

/// Git 后端允许的认证方式。
///
/// 这是一个**封闭**枚举：EnvSync 只接受这三种方式，任何「把密码/token 直接写进配置」的
/// 形式都无法构造。从字符串配置构造请使用 [`GitAuth::parse`]，它会拒绝未知种类。
#[derive(Clone, PartialEq, Eq)]
pub enum GitAuth {
    /// 使用 ssh-agent 持有的私钥；本进程只发起签名请求，永远拿不到私钥本身。
    SshAgent,
    /// 使用 git 的 credential helper（`git credential fill`）现取现用。
    CredentialHelper,
    /// 只保存一个 secret 引用；M2 的 Vault 落地前**不解析**，因此现在无法用于实际连接。
    TokenSecretRef {
        /// secret 的标识符。它是**引用**，不是 token 本身；即便如此也不会被日志或
        /// `Debug` 输出（见本类型的 `Debug` 实现）。
        secret_id: String,
    },
}

impl GitAuth {
    /// 配置中允许出现的认证方式名称，顺序稳定，可直接用于 CLI 帮助与错误提示。
    pub const KINDS: [&'static str; 3] = ["ssh-agent", "credential-helper", "token-secret-ref"];

    /// 本认证方式的稳定短名称，与 [`GitAuth::KINDS`] 一致。
    pub fn kind(&self) -> &'static str {
        match self {
            GitAuth::SshAgent => "ssh-agent",
            GitAuth::CredentialHelper => "credential-helper",
            GitAuth::TokenSecretRef { .. } => "token-secret-ref",
        }
    }

    /// 从配置文件里的字符串构造认证方式。
    ///
    /// `secret_id` 只对 `token-secret-ref` 有意义；给其他种类传入 `Some(..)` 会被拒绝，
    /// 以免用户误以为「顺手写个密码就能用」。
    ///
    /// # 错误
    ///
    /// 种类不在 [`GitAuth::KINDS`] 内、缺少或多余 `secret_id` 时返回
    /// [`BackendError::Unsupported`]。
    pub fn parse(kind: &str, secret_id: Option<&str>) -> Result<Self, BackendError> {
        let auth =
            match kind {
                "ssh-agent" => {
                    reject_secret_id(secret_id)?;
                    GitAuth::SshAgent
                }
                "credential-helper" => {
                    reject_secret_id(secret_id)?;
                    GitAuth::CredentialHelper
                }
                "token-secret-ref" => {
                    let secret_id = secret_id.ok_or(BackendError::Unsupported(
                        "token-secret-ref 认证必须提供 secret 引用标识",
                    ))?;
                    GitAuth::TokenSecretRef {
                        secret_id: secret_id.to_owned(),
                    }
                }
                _ => return Err(BackendError::Unsupported(
                    "Git 远端只支持 ssh-agent、credential-helper、token-secret-ref 三种认证方式",
                )),
            };
        auth.validate()?;
        Ok(auth)
    }

    /// 校验配置自身是否合法。
    ///
    /// [`GitAuth::SshAgent`] 与 [`GitAuth::CredentialHelper`] 没有参数，恒合法。
    /// [`GitAuth::TokenSecretRef`] 的 `secret_id` 必须是**引用形态**：非空、不超过 128
    /// 字节、只含 `A-Za-z0-9._:-`。这条字符集限制同时挡下了最常见的误用——把 token 原文
    /// （通常含 `/`、`+`、`=` 或空白）粘进 `secret_id`。
    ///
    /// # 错误
    ///
    /// 不满足上述约束时返回 [`BackendError::Unsupported`]。
    pub fn validate(&self) -> Result<(), BackendError> {
        match self {
            GitAuth::SshAgent | GitAuth::CredentialHelper => Ok(()),
            GitAuth::TokenSecretRef { secret_id } => {
                if secret_id.is_empty() {
                    return Err(BackendError::Unsupported("secret 引用标识不能为空"));
                }
                if secret_id.len() > MAX_SECRET_ID_LEN {
                    return Err(BackendError::Unsupported(
                        "secret 引用标识过长（上限 128 字节）",
                    ));
                }
                if !secret_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
                {
                    return Err(BackendError::Unsupported(
                        "secret 引用标识只能包含字母、数字与 `.`、`_`、`:`、`-`：这里要填引用，不是 token 原文",
                    ));
                }
                Ok(())
            }
        }
    }
}

/// 手写 `Debug`：**绝不**输出 `secret_id`。
///
/// 派生实现会把 `secret_id` 原样打印，一旦用户误把 token 填进去，任何一次
/// `tracing::debug!(?config)` 都会把它写进日志。这里统一替换成掩码。
impl std::fmt::Debug for GitAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitAuth::SshAgent => f.write_str("SshAgent"),
            GitAuth::CredentialHelper => f.write_str("CredentialHelper"),
            GitAuth::TokenSecretRef { .. } => f
                .debug_struct("TokenSecretRef")
                .field("secret_id", &USERINFO_MASK)
                .finish(),
        }
    }
}

/// 给非 `token-secret-ref` 的认证方式传了 `secret_id` 时拒绝。
fn reject_secret_id(secret_id: Option<&str>) -> Result<(), BackendError> {
    if secret_id.is_some() {
        return Err(BackendError::Unsupported(
            "只有 token-secret-ref 认证接受 secret 引用标识",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 远端 URL
// ---------------------------------------------------------------------------

/// 远端 URL 的结构分解结果。
///
/// 只做 EnvSync 需要的最小切分，不追求完整的 RFC 3986 解析：判定「有没有凭据」只需要
/// authority 和 query 两段。
enum Shape<'a> {
    /// 带 scheme 的 URL：`scheme://[userinfo@]host[/path][?query]`。
    Url {
        /// 小写化后的 scheme。
        scheme: String,
        /// `@` 之前的 userinfo（若有）。
        userinfo: Option<&'a str>,
        /// 主机（可能带端口）。
        host: &'a str,
        /// 以 `/` 开头的路径，可能为空。
        path: &'a str,
        /// `?` 之后的查询串（若有）。
        query: Option<&'a str>,
    },
    /// scp 风格的 ssh 远端：`[user@]host:path`。
    Scp {
        /// `@` 之前的 userinfo（若有）。
        userinfo: Option<&'a str>,
        /// 主机。
        host: &'a str,
        /// 冒号之后的仓库路径。
        path: &'a str,
    },
    /// 本地文件系统路径。
    Local,
}

/// 切分远端 URL。
fn shape(url: &str) -> Shape<'_> {
    if let Some((scheme, rest)) = url.split_once("://") {
        let (before_query, query) = match rest.split_once('?') {
            Some((before, query)) => (before, Some(query)),
            None => (rest, None),
        };
        let (authority, path) = match before_query.find('/') {
            Some(index) => (&before_query[..index], &before_query[index..]),
            None => (before_query, ""),
        };
        let (userinfo, host) = split_userinfo(authority);
        return Shape::Url {
            scheme: scheme.to_ascii_lowercase(),
            userinfo,
            host,
            path,
            query,
        };
    }

    // 没有 scheme：可能是 scp 风格（`git@host:org/repo.git`）或本地路径。
    // 先切 userinfo，再找主机与路径之间的冒号——否则 `user:pass@host:path` 里的第一个
    // 冒号会被误当成分隔符，密码段就溜过去了。
    let (userinfo, rest) = match url.split_once('@') {
        Some((userinfo, rest)) if !userinfo.contains('/') && !userinfo.contains('\\') => {
            (Some(userinfo), rest)
        }
        _ => (None, url),
    };
    if let Some((host, path)) = rest.split_once(':') {
        // `host` 含 `/` 说明冒号出现在路径中间，那是本地路径；单字母 host 是 Windows
        // 盘符（`C:\repo`），git 自身也用同样的规则消歧。
        let is_drive_letter = host.len() == 1 && host.as_bytes()[0].is_ascii_alphabetic();
        if !host.is_empty() && !host.contains('/') && !host.contains('\\') && !is_drive_letter {
            return Shape::Scp {
                userinfo,
                host,
                path,
            };
        }
    }
    Shape::Local
}

/// 从 authority 中切出 userinfo；用 `rsplit_once` 以便 `a@b@host` 也被完整识别。
fn split_userinfo(authority: &str) -> (Option<&str>, &str) {
    match authority.rsplit_once('@') {
        Some((userinfo, host)) => (Some(userinfo), host),
        None => (None, authority),
    }
}

/// 校验远端 URL 是否可以安全地交给 Git 后端。
///
/// 规则（任何一条不满足都返回 [`BackendError::Unsupported`]）：
///
/// * 非空、不超过 2048 字节、不含控制字符或空白（防止 CRLF 注入进日志）；
/// * scheme 只允许 `https`、`ssh`、`file`，或者没有 scheme 的本地路径 / scp 风格 ssh。
///   `http` 与 `git` 协议不加密，凭据和内容都会明文过网，直接拒绝；
/// * **不得包含 userinfo**：`https://user:pass@host/…` 和 `https://user@host/…` 都拒绝。
///   例外是 ssh：`git@host:org/repo.git` 里的 `git` 是 ssh 登录名而不是凭据，因此允许
///   纯用户名，但只要 userinfo 里出现 `:`（即带密码段）立刻拒绝；
/// * **不得携带查询串或片段**：`?access_token=…` 是 token 泄漏的经典载体，而 git 远端从
///   不需要查询参数，整段禁掉最简单也最安全。
///
/// # 错误
///
/// 违反上述任一规则时返回 [`BackendError::Unsupported`]，其文本是静态字符串，
/// **不会**回显被拒绝的 URL。
pub fn validate_remote_url(url: &str) -> Result<(), BackendError> {
    if url.is_empty() {
        return Err(BackendError::Unsupported("远端 URL 不能为空"));
    }
    if url.len() > MAX_URL_LEN {
        return Err(BackendError::Unsupported("远端 URL 过长（上限 2048 字节）"));
    }
    if url.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
        return Err(BackendError::Unsupported("远端 URL 不能包含控制字符或空白"));
    }
    if url.contains('#') {
        return Err(BackendError::Unsupported("远端 URL 不能包含片段（`#`）"));
    }

    let no_credentials = BackendError::Unsupported(
        "远端 URL 不能包含 userinfo：凭据只能来自 ssh-agent、credential helper 或 secret 引用",
    );
    let no_query = BackendError::Unsupported(
        "远端 URL 不能携带查询串：token 只能通过 secret 引用配置，不能写进 URL",
    );

    match shape(url) {
        Shape::Url {
            scheme,
            userinfo,
            host,
            query,
            ..
        } => {
            match scheme.as_str() {
                "https" | "ssh" | "file" => {}
                _ => {
                    return Err(BackendError::Unsupported(
                        "远端 URL 只支持 https、ssh、file 或本地路径（http 与 git 协议不加密）",
                    ))
                }
            }
            if query.is_some() {
                return Err(no_query);
            }
            match (scheme.as_str(), userinfo) {
                // ssh 的登录名不是凭据，但带密码段的一律拒绝。
                ("ssh", Some(userinfo)) if !userinfo.contains(':') => {}
                (_, Some(_)) => return Err(no_credentials),
                (_, None) => {}
            }
            // `file://` 的 host 允许为空（`file:///tmp/x`），其余必须有主机名。
            if host.is_empty() && scheme != "file" {
                return Err(BackendError::Unsupported("远端 URL 缺少主机名"));
            }
            Ok(())
        }
        Shape::Scp { userinfo, host, .. } => {
            if url.contains('?') {
                return Err(no_query);
            }
            if host.is_empty() {
                return Err(BackendError::Unsupported("远端 URL 缺少主机名"));
            }
            match userinfo {
                Some(userinfo) if userinfo.contains(':') => Err(no_credentials),
                _ => Ok(()),
            }
        }
        Shape::Local => {
            if url.contains('?') {
                return Err(no_query);
            }
            Ok(())
        }
    }
}

/// 返回远端 URL 的**脱敏**形式，供日志、诊断和错误信息使用。
///
/// 脱敏规则：
///
/// * userinfo 整段替换为 `***`（即便只是用户名也照样掩码，避免「这个用户名是不是密码」
///   的判断出现在调用点）；
/// * 查询串整段替换为 `<redacted>`；
/// * 本地文件系统路径（含 `file://`）替换为 `<local>`：本机绝对路径既是主机信息也常含
///   用户名，不应进入日志。
///
/// 该函数对**任意**输入都成立，包括没通过 [`validate_remote_url`] 的字符串——它同时被用
/// 来清洗底层 git 错误文本，所以不能假设输入是合法 URL。
pub fn redacted_remote(url: &str) -> String {
    match shape(url) {
        Shape::Url {
            scheme,
            userinfo,
            host,
            path,
            query,
        } => {
            if scheme == "file" {
                return format!("file://{LOCAL_PLACEHOLDER}");
            }
            let mut out = String::with_capacity(url.len());
            out.push_str(&scheme);
            out.push_str("://");
            if userinfo.is_some() {
                out.push_str(USERINFO_MASK);
                out.push('@');
            }
            out.push_str(host);
            out.push_str(path);
            if query.is_some() {
                out.push('?');
                out.push_str(QUERY_MASK);
            }
            out
        }
        Shape::Scp {
            userinfo,
            host,
            path,
        } => {
            let mut out = String::with_capacity(url.len());
            if userinfo.is_some() {
                out.push_str(USERINFO_MASK);
                out.push('@');
            }
            out.push_str(host);
            out.push(':');
            out.push_str(path);
            out
        }
        Shape::Local => LOCAL_PLACEHOLDER.to_owned(),
    }
}

/// 返回远端的主机部分（可能带端口），本地远端返回 `<local>`。
///
/// 这是 `tracing` 里唯一允许出现的远端标识：主机名足以定位「同步到哪儿去了」，又不含
/// userinfo、路径和查询串。
pub fn remote_host(url: &str) -> String {
    match shape(url) {
        Shape::Url { scheme, host, .. } if scheme != "file" => host.to_owned(),
        Shape::Scp { host, .. } => host.to_owned(),
        _ => LOCAL_PLACEHOLDER.to_owned(),
    }
}

/// 清洗底层 git 错误文本中的疑似远端 URL，纵深防御用。
///
/// libgit2 的错误信息经常把整个 remote URL 拼进去。EnvSync 在配置边界就拒绝了带凭据的
/// URL，正常路径上不会有东西可泄漏；但错误文本来自第三方库，不能假设它的构造方式，因此
/// 在写入 [`BackendError`] 之前再过一遍：凡是含 `://` 或 `@` 的词都替换成
/// [`redacted_remote`] 的输出。
///
/// 代价是原始信息里的空白被归一化成单个空格，对错误展示无影响。
pub(crate) fn scrub(text: &str) -> String {
    text.split_whitespace()
        .map(|word| {
            if word.contains("://") || word.contains('@') {
                // 去掉包裹的引号和尾随标点，避免它们把 URL 切分逻辑带偏。
                let trimmed = word.trim_matches(['\'', '"', '(', ')']);
                let tail = trimmed.trim_end_matches(['.', ',', ';', ':']);
                redacted_remote(tail)
            } else {
                word.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_three_supported_kinds() {
        assert_eq!(
            GitAuth::parse("ssh-agent", None).unwrap(),
            GitAuth::SshAgent
        );
        assert_eq!(
            GitAuth::parse("credential-helper", None).unwrap(),
            GitAuth::CredentialHelper
        );
        assert_eq!(
            GitAuth::parse("token-secret-ref", Some("envsync:git")).unwrap(),
            GitAuth::TokenSecretRef {
                secret_id: "envsync:git".to_owned()
            }
        );
    }

    #[test]
    fn rejects_other_auth_forms() {
        for kind in ["password", "basic", "netrc", "plaintext", ""] {
            let err = GitAuth::parse(kind, Some("hunter2")).unwrap_err();
            assert_eq!(err.code(), "unsupported");
        }
    }

    #[test]
    fn debug_never_prints_secret_id() {
        let auth = GitAuth::TokenSecretRef {
            secret_id: "canary-secret-id".to_owned(),
        };
        assert!(!format!("{auth:?}").contains("canary-secret-id"));
    }

    #[test]
    fn scp_style_ssh_remotes_are_accepted() {
        validate_remote_url("git@github.com:envsync/dotfiles.git").unwrap();
        assert_eq!(
            remote_host("git@github.com:envsync/dotfiles.git"),
            "github.com"
        );
    }

    #[test]
    fn local_paths_never_leak_into_logs() {
        validate_remote_url("/home/alice/envsync-remote.git").unwrap();
        assert_eq!(redacted_remote("/home/alice/envsync-remote.git"), "<local>");
        assert_eq!(remote_host("/home/alice/envsync-remote.git"), "<local>");
    }
}
