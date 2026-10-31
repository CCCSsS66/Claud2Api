pub use crate::browser::BrowserProfile;
use crate::error::{Fault, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    env,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct TlsFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowCidr {
    addr: IpAddr,
    prefix: u8,
}
impl AllowCidr {
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.is_empty() {
            return None;
        }
        let (addr, prefix) = match value.split_once('/') {
            Some((addr, prefix)) => (
                addr.parse::<IpAddr>().ok()?,
                Some(prefix.parse::<u8>().ok()?),
            ),
            None => (value.parse::<IpAddr>().ok()?, None),
        };
        let limit = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(limit);
        (prefix <= limit).then_some(Self { addr, prefix })
    }
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                u32::from(network) & mask == u32::from(candidate) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                u128::from(network) & mask == u128::from(candidate) & mask
            }
            _ => false,
        }
    }
}

const fn enabled_by_default() -> bool {
    true
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub session_ttl_seconds: u64,
    pub request_timeout_seconds: u64,
    pub max_request_bytes: usize,
    pub simulated_cache: bool,
    pub compaction_enabled: bool,
    pub context_budget: usize,
    pub compaction_trigger_percent: usize,
    pub keep_recent_rounds: usize,
    pub account_min_interval_seconds: u64,
    pub account_requests_per_minute: usize,
    pub rate_limit_min_seconds: u64,
    pub rate_limit_fallback_seconds: u64,
    pub overload_seconds: u64,
    #[serde(default = "enabled_by_default")]
    pub native_web_search: bool,
    #[serde(default = "enabled_by_default")]
    pub native_artifacts: bool,
    #[serde(default = "enabled_by_default")]
    pub native_repl: bool,
    #[serde(default = "enabled_by_default")]
    pub native_widgets: bool,
    #[serde(default = "enabled_by_default")]
    pub native_project_knowledge: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            session_ttl_seconds: 3600,
            request_timeout_seconds: 300,
            max_request_bytes: 4 << 20,
            simulated_cache: true,
            compaction_enabled: true,
            context_budget: 128000,
            compaction_trigger_percent: 75,
            keep_recent_rounds: 6,
            account_min_interval_seconds: 5,
            account_requests_per_minute: 6,
            rate_limit_min_seconds: 60,
            rate_limit_fallback_seconds: 18000,
            overload_seconds: 15,
            native_web_search: true,
            native_artifacts: true,
            native_repl: true,
            native_widgets: true,
            native_project_knowledge: true,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        let checks = [
            (self.session_ttl_seconds, 60, 604800),
            (self.request_timeout_seconds, 1, 900),
            (self.max_request_bytes as u64, 1024, 32 << 20),
            (self.context_budget as u64, 4096, 1_000_000),
            (self.compaction_trigger_percent as u64, 10, 90),
            (self.keep_recent_rounds as u64, 1, 32),
            (self.account_min_interval_seconds, 1, 300),
            (self.account_requests_per_minute as u64, 1, 60),
            (self.rate_limit_min_seconds, 60, 86400),
            (self.rate_limit_fallback_seconds, 60, 604800),
            (self.overload_seconds, 1, 900),
        ];
        if checks.iter().any(|(v, min, max)| v < min || v > max) {
            return Err(Fault::invalid(
                "configuration contains an out-of-range value",
            ));
        }
        Ok(())
    }
    fn environment() -> Result<Self> {
        let mut s = Self::default();
        macro_rules! number {
            ($field:ident, $name:literal) => {
                if let Ok(v) = env::var($name) {
                    s.$field = v
                        .parse()
                        .map_err(|_| Fault::invalid(concat!("invalid ", $name)))?;
                }
            };
        }
        number!(session_ttl_seconds, "STICKY_SESSION_TTL_SECONDS");
        number!(request_timeout_seconds, "REQUEST_TIMEOUT_SECONDS");
        number!(max_request_bytes, "MAX_REQUEST_BYTES");
        number!(context_budget, "CONTEXT_BUDGET_TOKENS");
        number!(
            compaction_trigger_percent,
            "CONTEXT_COMPACTION_TRIGGER_PERCENT"
        );
        number!(keep_recent_rounds, "CONTEXT_KEEP_RECENT_ROUNDS");
        number!(account_min_interval_seconds, "ACCOUNT_MIN_INTERVAL_SECONDS");
        number!(account_requests_per_minute, "ACCOUNT_REQUESTS_PER_MINUTE");
        number!(
            rate_limit_min_seconds,
            "ACCOUNT_RATE_LIMIT_COOLDOWN_SECONDS"
        );
        number!(
            rate_limit_fallback_seconds,
            "ACCOUNT_RATE_LIMIT_FALLBACK_SECONDS"
        );
        number!(overload_seconds, "ACCOUNT_OVERLOAD_COOLDOWN_SECONDS");
        number!(simulated_cache, "SIMULATED_CACHE_ENABLED");
        number!(compaction_enabled, "CONTEXT_COMPACTION_ENABLED");
        number!(native_web_search, "NATIVE_WEB_SEARCH_ENABLED");
        number!(native_artifacts, "NATIVE_ARTIFACTS_ENABLED");
        number!(native_repl, "NATIVE_REPL_ENABLED");
        number!(native_widgets, "NATIVE_WIDGETS_ENABLED");
        number!(native_project_knowledge, "NATIVE_PROJECT_KNOWLEDGE_ENABLED");
        s.validate()?;
        Ok(s)
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Credential {
    pub session_key: String,
    pub cookie: String,
}
impl Credential {
    pub fn parse(line: &str) -> Result<Self> {
        let line = line.trim();
        if line.is_empty() || line.len() > 65536 || line.contains(['\r', '\n']) {
            return Err(Fault::invalid("credential must be a nonempty single line"));
        }
        let cookie = if line.contains("sessionKey=") {
            line.to_owned()
        } else {
            String::new()
        };
        let session_key = if cookie.is_empty() {
            line.to_owned()
        } else {
            cookie_value(&cookie, "sessionKey").unwrap_or_default()
        };
        if session_key.is_empty() || !line.bytes().all(|b| (32..127).contains(&b)) {
            return Err(Fault::invalid("invalid account credential"));
        }
        Ok(Self {
            session_key,
            cookie,
        })
    }
    pub fn id(&self) -> String {
        hex::encode(Sha256::digest(self.session_key.trim().as_bytes()))
    }
}
pub fn cookie_value(cookie: &str, key: &str) -> Option<String> {
    cookie.split(';').find_map(|v| {
        v.trim()
            .split_once('=')
            .filter(|(k, _)| *k == key)
            .map(|(_, v)| v.to_owned())
    })
}
#[derive(Clone)]
pub struct Config {
    pub browser_profile: BrowserProfile,
    pub public_bind: SocketAddr,
    pub control_bind: SocketAddr,
    pub gateway_key: String,
    pub admin_key: String,
    pub bot_key: String,
    pub data_dir: PathBuf,
    pub import_state: Option<PathBuf>,
    pub base_url: String,
    pub locale: String,
    pub timezone: String,
    pub default_model: String,
    pub effort: String,
    pub legacy_thinking: String,
    pub accounts: Vec<Credential>,
    pub settings: Settings,
    pub tls: Option<TlsFiles>,
    pub public_tls: Option<TlsFiles>,
    pub control_tls: Option<TlsFiles>,
    pub trust_proxy: bool,
    pub admin_session_ttl: u64,
    pub admin_max_failures: u32,
    pub admin_lockout_seconds: u64,
    pub admin_allow: Vec<AllowCidr>,
}
impl Config {
    pub fn secure_transport(&self) -> bool {
        self.control_tls.is_some() || self.trust_proxy
    }
    pub fn client_allowed(&self, ip: IpAddr) -> bool {
        self.admin_allow.is_empty() || self.admin_allow.iter().any(|rule| rule.contains(ip))
    }
}
fn var(name: &str, fallback: &str) -> String {
    env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| fallback.to_owned())
}
fn flag(name: &str) -> Result<bool> {
    match env::var(name) {
        Err(_) => Ok(false),
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "" | "0" | "false" | "no" | "off" => Ok(false),
            "1" | "true" | "yes" | "on" => Ok(true),
            _ => Err(Fault::invalid(format!("invalid {name}"))),
        },
    }
}
fn env_number(name: &str, fallback: u64) -> Result<u64> {
    match env::var(name) {
        Err(_) => Ok(fallback),
        Ok(value) => value
            .trim()
            .parse::<u64>()
            .map_err(|_| Fault::invalid(format!("invalid {name}"))),
    }
}
fn tls_pair(cert_name: &str, key_name: &str) -> Result<Option<TlsFiles>> {
    match (var(cert_name, ""), var(key_name, "")) {
        (cert, key) if cert.is_empty() && key.is_empty() => Ok(None),
        (cert, key) if !cert.is_empty() && !key.is_empty() => {
            for path in [cert.as_str(), key.as_str()] {
                let meta = std::fs::metadata(path).map_err(|_| {
                    Fault::invalid(format!("cannot read {cert_name} or {key_name}"))
                })?;
                if !meta.is_file() || meta.len() > 1 << 20 {
                    return Err(Fault::invalid(format!(
                        "{cert_name} or {key_name} is invalid"
                    )));
                }
            }
            Ok(Some(TlsFiles {
                cert: PathBuf::from(cert),
                key: PathBuf::from(key),
            }))
        }
        _ => Err(Fault::invalid(format!(
            "set both {cert_name} and {key_name}, or neither"
        ))),
    }
}
fn file_text(path: &Path, max: u64) -> Result<String> {
    let meta =
        std::fs::metadata(path).map_err(|_| Fault::invalid("cannot read configured file"))?;
    if !meta.is_file() || meta.len() > max {
        return Err(Fault::invalid("configured file is invalid or too large"));
    }
    std::fs::read_to_string(path).map_err(|_| Fault::invalid("configured file is not UTF-8"))
}
fn secret(name: &str) -> Result<String> {
    let value = match env::var(format!("{name}_FILE")) {
        Ok(path) => file_text(Path::new(&path), 1 << 20)?,
        Err(_) => var(name, ""),
    };
    let v = value.trim_start_matches('\u{feff}').trim().to_owned();
    if v.contains(['\r', '\n']) {
        return Err(Fault::invalid("key must be a single line"));
    }
    Ok(v)
}
impl Config {
    pub fn load() -> Result<Self> {
        let gateway_key = secret("GATEWAY_API_KEY")?;
        let admin_key = secret("ADMIN_API_KEY")?;
        let bot_key = secret("BOT_READ_KEY")?;
        if gateway_key.len() < 32
            || admin_key.len() < 32
            || gateway_key == admin_key
            || (!bot_key.is_empty()
                && (bot_key.len() < 32 || bot_key == gateway_key || bot_key == admin_key))
        {
            return Err(Fault::invalid(
                "configure distinct gateway and admin keys (and optional bot key), each at least 32 bytes",
            ));
        }
        let public_bind = SocketAddr::new(
            var("BIND_HOST", "127.0.0.1")
                .parse::<IpAddr>()
                .map_err(|_| Fault::invalid("BIND_HOST must be an IP address"))?,
            var("PORT", "8080")
                .parse()
                .map_err(|_| Fault::invalid("invalid PORT"))?,
        );
        let control_bind = var("CONTROL_BIND", "127.0.0.1:18082")
            .parse::<SocketAddr>()
            .map_err(|_| Fault::invalid("invalid CONTROL_BIND"))?;
        if !crate::updates::managed() && (public_bind.port() == 0 || control_bind.port() == 0) {
            return Err(Fault::invalid("listeners require a nonzero port"));
        }
        let tls = tls_pair("TLS_CERT_FILE", "TLS_KEY_FILE")?;
        let public_tls =
            tls_pair("PUBLIC_TLS_CERT_FILE", "PUBLIC_TLS_KEY_FILE")?.or_else(|| tls.clone());
        let control_tls =
            tls_pair("CONTROL_TLS_CERT_FILE", "CONTROL_TLS_KEY_FILE")?.or_else(|| tls.clone());
        let trust_proxy = flag("TRUST_PROXY")?;
        if !control_bind.ip().is_loopback() {
            if !flag("ALLOW_REMOTE_CONTROL")? {
                return Err(Fault::invalid(
                    "CONTROL_BIND is not loopback; set ALLOW_REMOTE_CONTROL=true to expose the console",
                ));
            }
            if control_tls.is_none() && !trust_proxy && !flag("ALLOW_INSECURE_CONTROL")? {
                return Err(Fault::invalid(
                    "refusing plaintext remote control: configure TLS_CERT_FILE/TLS_KEY_FILE (or CONTROL_TLS_*), set TRUST_PROXY=true for an HTTPS proxy, or explicitly set ALLOW_INSECURE_CONTROL=true",
                ));
            }
        }
        let admin_session_ttl = env_number("ADMIN_SESSION_TTL_SECONDS", 28800)?;
        let admin_max_failures = env_number("ADMIN_MAX_FAILED_ATTEMPTS", 10)?;
        let admin_lockout_seconds = env_number("ADMIN_LOCKOUT_SECONDS", 900)?;
        if !(300..=604800).contains(&admin_session_ttl)
            || !(3..=100).contains(&admin_max_failures)
            || !(60..=86400).contains(&admin_lockout_seconds)
        {
            return Err(Fault::invalid(
                "admin session or lockout configuration is out of range",
            ));
        }
        let mut admin_allow = Vec::new();
        for item in var("ADMIN_ALLOW_CIDRS", "").split(',') {
            if item.trim().is_empty() {
                continue;
            }
            admin_allow.push(
                AllowCidr::parse(item)
                    .ok_or_else(|| Fault::invalid("invalid ADMIN_ALLOW_CIDRS entry"))?,
            );
        }
        if admin_allow.len() > 64 {
            return Err(Fault::invalid(
                "ADMIN_ALLOW_CIDRS accepts at most 64 entries",
            ));
        }
        let parsed = url::Url::parse(&var("CLAUDE_BASE_URL", "https://claude.ai"))
            .map_err(|_| Fault::invalid("invalid upstream URL"))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(Fault::invalid("invalid upstream URL"));
        }
        let mut accounts = Vec::new();
        if let Ok(path) = env::var("CLAUDE_SESSION_FILE") {
            accounts.push(Credential::parse(
                file_text(Path::new(&path), 1 << 20)?
                    .trim_start_matches('\u{feff}')
                    .trim(),
            )?);
        } else {
            let path = var("CLAUDE_ACCOUNTS_FILE", "accounts.txt");
            if env::var("CLAUDE_ACCOUNTS_FILE").is_ok() && !Path::new(&path).is_file() {
                return Err(Fault::invalid("cannot read configured accounts file"));
            }
            if Path::new(&path).exists() {
                for line in file_text(Path::new(&path), 1 << 20)?.lines() {
                    let l = line.trim_start_matches('\u{feff}').trim();
                    if !l.is_empty() && !l.starts_with('#') {
                        accounts.push(Credential::parse(l)?);
                    }
                }
            }
            let cookie = var("CLAUDE_COOKIE", "");
            let session = var("CLAUDE_SESSION_KEY", "");
            let c = if cookie.is_empty() {
                session
            } else if cookie.contains("sessionKey=") {
                cookie
            } else if !session.is_empty() {
                format!("sessionKey={session}; {cookie}")
            } else {
                return Err(Fault::invalid(
                    "CLAUDE_COOKIE requires a sessionKey or CLAUDE_SESSION_KEY",
                ));
            };
            if !c.is_empty() {
                accounts.push(Credential::parse(&c)?);
            }
        }
        let mut ids = std::collections::HashSet::new();
        accounts.retain(|a| ids.insert(a.id()));
        if accounts.len() > 512
            || accounts.iter().any(|a| {
                [&gateway_key, &admin_key, &bot_key]
                    .iter()
                    .any(|k| !k.is_empty() && (**k == a.session_key || **k == a.cookie))
            })
        {
            return Err(Fault::invalid("invalid account pool or key separation"));
        }
        let data_dir = PathBuf::from(var("CLAUD2API_DATA_DIR", "/var/lib/claud2api"));
        if !data_dir.is_absolute() {
            return Err(Fault::invalid("CLAUD2API_DATA_DIR must be absolute"));
        }
        let locale = var("CLAUDE_LOCALE", "zh-CN");
        if locale.is_empty()
            || locale.len() > 64
            || !locale
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(Fault::invalid("invalid CLAUDE_LOCALE"));
        }
        let import_state = env::var("STICKY_SESSION_STATE_FILE")
            .ok()
            .map(PathBuf::from);
        if import_state
            .as_ref()
            .is_some_and(|p| !p.is_absolute() || !p.is_file())
        {
            return Err(Fault::invalid(
                "Go state import requires an existing absolute file path",
            ));
        }
        let timezone = var("CLAUDE_TIMEZONE", "Asia/Singapore");
        if timezone.parse::<chrono_tz::Tz>().is_err() {
            return Err(Fault::invalid("invalid CLAUDE_TIMEZONE"));
        }
        Ok(Self {
            browser_profile: BrowserProfile::parse(&var("BROWSER_PROFILE", "chrome_146_windows"))?,
            public_bind,
            control_bind,
            gateway_key,
            admin_key,
            bot_key,
            data_dir,
            import_state,
            base_url: parsed.to_string().trim_end_matches('/').to_owned(),
            locale,
            timezone,
            default_model: var("DEFAULT_MODEL", "claude-sonnet-5"),
            legacy_thinking: if matches!(var("CLAUDE_THINKING", "").as_str(), "none" | "disabled")
                || serde_json::from_str::<serde_json::Value>(&var("CLAUDE_THINKING", ""))
                    .ok()
                    .is_some_and(|v| v["type"] == "disabled")
            {
                "off".to_owned()
            } else {
                "auto".to_owned()
            },
            effort: {
                let value = var("CLAUDE_EFFORT", &var("CLAUDE_CODE_EFFORT_LEVEL", "medium"))
                    .trim()
                    .to_lowercase();
                if matches!(value.as_str(), "low" | "medium" | "high" | "xhigh" | "max") {
                    value
                } else {
                    "medium".to_owned()
                }
            },
            accounts,
            settings: Settings::environment()?,
            tls,
            public_tls,
            control_tls,
            trust_proxy,
            admin_session_ttl,
            admin_max_failures: admin_max_failures as u32,
            admin_lockout_seconds,
            admin_allow,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::AllowCidr;
    use std::net::IpAddr;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }
    #[test]
    fn allow_cidrs_are_family_aware_and_bounded() {
        let v4 = AllowCidr::parse("10.0.0.0/8").unwrap();
        assert!(v4.contains(ip("10.1.2.3")));
        assert!(!v4.contains(ip("11.1.2.3")));
        assert!(!v4.contains(ip("::ffff:10.1.2.3")));
        let single = AllowCidr::parse("192.0.2.7").unwrap();
        assert!(single.contains(ip("192.0.2.7")));
        assert!(!single.contains(ip("192.0.2.8")));
        let all = AllowCidr::parse("0.0.0.0/0").unwrap();
        assert!(all.contains(ip("203.0.113.9")));
        let v6 = AllowCidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains(ip("2001:db8::1")));
        assert!(!v6.contains(ip("2001:db9::1")));
        assert!(AllowCidr::parse("10.0.0.0/33").is_none());
        assert!(AllowCidr::parse("not-an-address").is_none());
        assert!(AllowCidr::parse("").is_none());
    }
}
