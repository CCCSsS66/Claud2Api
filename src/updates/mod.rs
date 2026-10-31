mod disk;
pub mod github;
mod policy;
mod supervisor;
pub mod version;

use crate::error::{Fault, Result};
use serde_json::{Value, json};
use std::{net::SocketAddr, path::Path};
pub use supervisor::run;

pub const PROTOCOL: u32 = 1;
pub const DATA_FORMAT: &str = "sqlite-v1/Claud2Api-vault-v1";
pub const RUNTIME_ABI: &str = "linux-amd64-glibc-2.36";
pub fn describe() -> Value {
    json!({"protocol":PROTOCOL,"version":crate::VERSION,"runtime_abi":RUNTIME_ABI,"data_format":DATA_FORMAT})
}
pub fn managed() -> bool {
    std::env::args().any(|v| v == "--worker")
        && std::env::var("CLAUD2API_WORKER_TOKEN")
            .is_ok_and(|v| v.len() == 64 && v.bytes().all(|c| c.is_ascii_hexdigit()))
}
pub fn ready(public: SocketAddr, control: SocketAddr) -> Result<()> {
    if !managed() {
        return Ok(());
    }
    let path = std::env::var("CLAUD2API_WORKER_READY").map_err(|_| Fault::internal())?;
    let token = std::env::var("CLAUD2API_WORKER_TOKEN").map_err(|_| Fault::internal())?;
    disk::atomic_json(
        Path::new(&path),
        &json!({"public":public,"control":control,"token":token,"build":describe()}),
    )
}
pub fn bounded_server(
    listener: tokio::net::TcpListener,
) -> Result<axum_server::Server<SocketAddr>> {
    let failed = |_| Fault::new(503, "api_error", "listener initialization failed");
    let mut server = axum_server::from_tcp(listener.into_std().map_err(failed)?).map_err(failed)?;
    tune(&mut server);
    Ok(server)
}
fn tls_server(
    listener: tokio::net::TcpListener,
    config: axum_server::tls_rustls::RustlsConfig,
) -> Result<axum_server::Server<SocketAddr, axum_server::tls_rustls::RustlsAcceptor>> {
    let failed = |_| Fault::new(503, "api_error", "listener initialization failed");
    let mut server = axum_server::from_tcp_rustls(listener.into_std().map_err(failed)?, config)
        .map_err(failed)?;
    tune(&mut server);
    Ok(server)
}
fn tune<A: axum_server::Address, Acc>(server: &mut axum_server::Server<A, Acc>) {
    let builder = server.http_builder();
    *builder = builder.clone().http1_only();
    server
        .http_builder()
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(std::time::Duration::from_secs(10));
}
pub async fn tls_config(
    files: Option<&crate::config::TlsFiles>,
) -> Result<Option<axum_server::tls_rustls::RustlsConfig>> {
    let Some(files) = files else {
        return Ok(None);
    };
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&files.cert, &files.key)
        .await
        .map_err(|_| Fault::invalid("cannot load TLS certificate or key"))?;
    Ok(Some(tls))
}
/// Serve a router with optional direct TLS while preserving peer addresses for
/// `ConnectInfo<SocketAddr>` (used by client allowlists and login throttling).
pub fn spawn_server(
    listener: tokio::net::TcpListener,
    tls: Option<axum_server::tls_rustls::RustlsConfig>,
    router: axum::Router,
    handle: axum_server::Handle<SocketAddr>,
) -> Result<tokio::task::JoinHandle<std::io::Result<()>>> {
    let service = router.into_make_service_with_connect_info::<SocketAddr>();
    if let Some(tls) = tls {
        let server = tls_server(listener, tls)?.handle(handle);
        Ok(tokio::spawn(async move { server.serve(service).await }))
    } else {
        let server = bounded_server(listener)?.handle(handle);
        Ok(tokio::spawn(async move { server.serve(service).await }))
    }
}
