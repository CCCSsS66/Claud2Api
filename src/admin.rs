//! Short-lived console sessions and failed-login throttling.
use crate::{
    error::{Fault, Result},
    store::now,
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Admin,
    Bot,
}
impl Scope {
    pub fn label(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Bot => "bot",
        }
    }
}

struct Session {
    scope: Scope,
    expires_at: i64,
}

#[derive(Default)]
struct Attempt {
    failures: u32,
    window_start: i64,
    blocked_until: i64,
}

pub struct AdminGuard {
    sessions: Mutex<HashMap<String, Session>>,
    attempts: Mutex<HashMap<IpAddr, Attempt>>,
    ttl: i64,
    max_failures: u32,
    window: i64,
    lockout: i64,
    issued: AtomicU64,
}

impl AdminGuard {
    pub fn new(ttl: u64, max_failures: u32, lockout: u64) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            attempts: Mutex::new(HashMap::new()),
            ttl: ttl as i64,
            max_failures,
            window: 900,
            lockout: lockout as i64,
            issued: AtomicU64::new(0),
        }
    }
    fn digest(token: &str) -> String {
        hex::encode(Sha256::digest(token.as_bytes()))
    }
    pub fn issued(&self) -> u64 {
        self.issued.load(Ordering::Relaxed)
    }
    pub async fn active(&self) -> usize {
        let now = now();
        self.sessions
            .lock()
            .await
            .values()
            .filter(|session| session.expires_at > now)
            .count()
    }
    pub async fn issue(&self, scope: Scope) -> (String, i64) {
        let token = format!(
            "c2a_adm_{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let expires_at = now() + self.ttl;
        let mut sessions = self.sessions.lock().await;
        let now = now();
        sessions.retain(|_, session| session.expires_at > now);
        if sessions.len() >= 64
            && let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, session)| session.expires_at)
                .map(|(key, _)| key.clone())
        {
            sessions.remove(&oldest);
        }
        sessions.insert(Self::digest(&token), Session { scope, expires_at });
        self.issued.fetch_add(1, Ordering::Relaxed);
        (token, expires_at)
    }
    pub async fn scope(&self, token: &str) -> Option<Scope> {
        if token.is_empty() {
            return None;
        }
        let key = Self::digest(token);
        let mut sessions = self.sessions.lock().await;
        let now = now();
        if sessions
            .get(&key)
            .is_some_and(|session| session.expires_at <= now)
        {
            sessions.remove(&key);
            return None;
        }
        sessions.get(&key).map(|session| session.scope)
    }
    pub async fn revoke(&self, token: &str) -> bool {
        if token.is_empty() {
            return false;
        }
        self.sessions
            .lock()
            .await
            .remove(&Self::digest(token))
            .is_some()
    }
    pub async fn admit(&self, ip: IpAddr) -> Result<()> {
        let now = now();
        let mut attempts = self.attempts.lock().await;
        if attempts.len() > 4096 {
            attempts.retain(|_, entry| {
                entry.blocked_until > now || now - entry.window_start < self.window
            });
        }
        match attempts.get(&ip) {
            Some(entry) if entry.blocked_until > now => Err(Fault::busy(
                "too many failed control logins; retry later",
                (entry.blocked_until - now) as u64,
            )),
            _ => Ok(()),
        }
    }
    pub async fn fail(&self, ip: IpAddr) {
        let now = now();
        let mut attempts = self.attempts.lock().await;
        let entry = attempts.entry(ip).or_default();
        if entry.window_start == 0 || now - entry.window_start > self.window {
            entry.failures = 0;
            entry.window_start = now;
        }
        entry.failures += 1;
        if entry.failures >= self.max_failures {
            entry.failures = 0;
            entry.window_start = now;
            entry.blocked_until = now + self.lockout;
        }
    }
    pub async fn success(&self, ip: IpAddr) {
        self.attempts.lock().await.remove(&ip);
    }
    pub async fn sweep(&self) {
        let now = now();
        self.sessions
            .lock()
            .await
            .retain(|_, session| session.expires_at > now);
        self.attempts
            .lock()
            .await
            .retain(|_, entry| entry.blocked_until > now || now - entry.window_start < self.window);
    }
}
