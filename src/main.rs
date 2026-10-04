//! An axum HTTP server with SQLite-backed sessions and Argon2id password login.

mod api;
mod auth;
mod db;
mod routes;
#[cfg(test)]
mod testutil;

use std::{
    env,
    future::Future,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use rusqlite::Connection;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::auth::{AuthConfig, LoginThrottle};

/// Bounds every handler, so a slow client cannot hold a request open forever.
/// Exceeding it produces a 408 from `TimeoutLayer`.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Upper bound on draining in-flight requests after SIGTERM, so `docker stop`
/// cannot hang until the daemon kills the container.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct AppState {
    /// One connection behind a mutex. SQLite serialises writers anyway, so a
    /// pool would buy little; WAL still lets readers run during a write.
    db: Arc<Mutex<Connection>>,
    auth: AuthConfig,
    throttle: Arc<LoginThrottle>,
}

impl AppState {
    pub fn new(conn: Connection, auth: AuthConfig) -> Self {
        Self {
            db: Arc::new(Mutex::new(conn)),
            auth,
            throttle: Arc::new(LoginThrottle::default()),
        }
    }

    /// Runs `f` against the connection on the blocking pool.
    ///
    /// rusqlite is synchronous and Argon2 is deliberately slow, so neither may
    /// run on a reactor thread — one login must not stall every other
    /// connection. The closure holds the lock, so it must not await.
    pub async fn db<F, T>(&self, f: F) -> Result<T, api::ApiError>
    where
        F: FnOnce(&mut Connection) -> Result<T, api::ApiError> + Send + 'static,
        T: Send + 'static,
    {
        let conn = Arc::clone(&self.db);
        match tokio::task::spawn_blocking(move || {
            // A panicking request poisons the lock. SQLite has already rolled
            // the statement back, so the data is consistent; recovering beats
            // refusing every later request.
            let mut guard = conn.lock().unwrap_or_else(PoisonError::into_inner);
            f(&mut guard)
        })
        .await
        {
            Ok(result) => result,
            Err(err) => {
                tracing::error!(%err, "database task panicked");
                Err(api::ApiError::Internal("服务器内部错误".into()))
            }
        }
    }
}

struct Config {
    host: String,
    port: u16,
    database: PathBuf,
    auth: AuthConfig,
}

impl Config {
    fn from_env() -> Self {
        Self {
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(3000),
            database: env::var("DATABASE_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("data/app.db")),
            auth: AuthConfig {
                cookie_secure: env_flag("COOKIE_SECURE", false),
                ttl: Duration::from_secs(
                    env::var("SESSION_TTL_SECS")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(24 * 60 * 60),
                ),
            },
        }
    }

    fn socket_addr(&self) -> SocketAddr {
        // A malformed HOST would panic here; fall back instead so a typo cannot crash the boot.
        format!("{}:{}", self.host, self.port)
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], self.port)))
    }
}

fn env_flag(key: &str, default: bool) -> bool {
    parse_flag(env::var(key).ok().as_deref(), default)
}

/// Split out from `env_flag` so the parsing is testable without mutating the
/// process environment, which is shared by every test running in parallel.
fn parse_flag(value: Option<&str>, default: bool) -> bool {
    match value {
        Some(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        None => default,
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,tower_http=info".into()))
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();

    if let Err(err) = run().await {
        tracing::error!(%err, "http-server exited with an error");
        // Exit non-zero so `restart: on-failure` and orchestrators notice.
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env();
    let addr = config.socket_addr();

    let conn = db::open(&config.database)?;
    db::migrate(&conn)?;
    let expired = db::delete_expired_sessions(&conn, db::now())?;
    tracing::info!(
        database = %config.database.display(),
        expired_sessions_pruned = expired,
        session_ttl_secs = config.auth.ttl.as_secs(),
        cookie_secure = config.auth.cookie_secure,
        "database ready"
    );

    let app = routes::build_router(REQUEST_TIMEOUT).with_state(AppState::new(conn, config.auth));

    let listener = tokio::net::TcpListener::bind(addr).await?;

    tracing::info!(
        addr = %addr,
        version = env!("CARGO_PKG_VERSION"),
        "http-server listening"
    );

    // `docker stop` sends SIGTERM: finish in-flight requests, then drain keep-alive
    // connections, so a rolling restart never truncates a response.
    match serve(listener, app, SHUTDOWN_GRACE, shutdown_signal()).await? {
        Shutdown::Drained => tracing::info!("shutdown complete"),
        Shutdown::TimedOut => {
            tracing::warn!("in-flight requests exceeded {SHUTDOWN_GRACE:?}; exiting anyway")
        }
    }
    Ok(())
}

#[derive(Debug, PartialEq)]
enum Shutdown {
    /// Every connection finished before the grace period elapsed.
    Drained,
    /// The grace period elapsed with requests still in flight.
    TimedOut,
}

/// Serves until `shutdown` resolves, then stops accepting and lets in-flight
/// requests finish within `grace`.
///
/// The drain deadline is armed by the shutdown signal, never by start-up:
/// bounding the whole `serve` future in a timeout would stop the server `grace`
/// after boot, no matter how healthy it was.
async fn serve(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    grace: Duration,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<Shutdown> {
    // One signal, fanned out to the server and the watchdog.
    let (signalled, mut watchdog_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown.await;
        let _ = signalled.send(true);
    });
    let mut server_rx = watchdog_rx.clone();

    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        server_rx.wait_for(|v| *v).await.ok();
    });

    let watchdog = async move {
        watchdog_rx.wait_for(|v| *v).await.ok();
        tokio::time::sleep(grace).await;
    };

    tokio::select! {
        served = server => {
            served?;
            Ok(Shutdown::Drained)
        }
        _ = watchdog => Ok(Shutdown::TimedOut),
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            tracing::error!("failed to install Ctrl+C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(err) => tracing::error!(%err, "failed to install SIGTERM handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received SIGINT"),
        _ = terminate => tracing::info!("received SIGTERM"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::app;

    #[test]
    fn malformed_host_falls_back_to_all_interfaces() {
        let config = Config {
            host: "not-an-ip".into(),
            port: 3000,
            database: PathBuf::from("data/app.db"),
            auth: AuthConfig {
                cookie_secure: false,
                ttl: Duration::from_secs(60),
            },
        };
        assert_eq!(config.socket_addr(), SocketAddr::from(([0, 0, 0, 0], 3000)));
    }

    #[test]
    fn boolean_flags_accept_the_usual_spellings() {
        for value in ["1", "true", "TRUE", " yes ", "on"] {
            assert!(parse_flag(Some(value), false), "{value} should be true");
        }
        for value in ["0", "false", "no", "off", "", "maybe"] {
            assert!(!parse_flag(Some(value), true), "{value} should be false");
        }
        // Unset keeps the default the caller chose.
        assert!(parse_flag(None, true));
        assert!(!parse_flag(None, false));
    }

    /// Minimal raw HTTP/1.1 client: enough to prove the real socket path works
    /// without pulling in a full client dependency.
    async fn raw_get(addr: SocketAddr, path: &str) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .await
            .expect("read response");
        response
    }

    /// Spawns `serve` on an ephemeral port. Returns the address, a sender that
    /// triggers shutdown, and a receiver carrying the `Shutdown` outcome.
    fn spawn_server(
        grace: Duration,
    ) -> (
        SocketAddr,
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<Shutdown>,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let outcome = serve(listener, app(), grace, async move {
                let _ = stop_rx.await;
            })
            .await;
            let _ = done_tx.send(
                outcome
                    .map_err(|_| "io error")
                    .unwrap_or(Shutdown::TimedOut),
            );
        });

        (addr, stop_tx, done_rx)
    }

    /// Regression test: the drain deadline must be armed by the shutdown signal,
    /// not by start-up. When it was wired to the whole `serve` future, the server
    /// died `grace` after boot and the container sat in a restart loop.
    #[tokio::test]
    async fn server_keeps_serving_past_the_grace_period() {
        let grace = Duration::from_millis(100);
        let (addr, _stop, _done) = spawn_server(grace);

        // Well past `grace`, with no shutdown signal sent: still serving.
        tokio::time::sleep(grace * 6).await;
        let response = raw_get(addr, "/health").await;

        assert!(response.starts_with("HTTP/1.1 200"), "got: {response}");
        assert!(response.contains(r#""status":"ok""#), "got: {response}");
    }

    #[tokio::test]
    async fn shutdown_signal_lets_in_flight_requests_finish() {
        let grace = Duration::from_secs(5);
        let (addr, stop, done) = spawn_server(grace);

        let client = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            raw_get(addr, "/api/slow?ms=1000").await
        });

        // Signal while the 1s request is still in flight.
        tokio::time::sleep(Duration::from_millis(400)).await;
        stop.send(()).unwrap();

        let response = client.await.unwrap();
        // The in-flight request must finish with its real body, not a truncated one.
        assert!(response.starts_with("HTTP/1.1 200"), "got: {response}");
        assert!(response.contains(r#""slept_ms":1000"#), "got: {response}");
        assert_eq!(done.await.unwrap(), Shutdown::Drained);
    }

    #[tokio::test]
    async fn shutdown_reports_timeout_when_a_request_outlasts_grace() {
        let grace = Duration::from_millis(150);
        let (addr, stop, done) = spawn_server(grace);

        let client = tokio::spawn(async move {
            // Connect immediately so the 3s request is genuinely in flight.
            raw_get(addr, "/api/slow?ms=3000").await
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        stop.send(()).unwrap();

        // The 3s request outlives the 150ms drain window, so `serve` gives up early.
        assert_eq!(done.await.unwrap(), Shutdown::TimedOut);
        client.abort();
    }
}
