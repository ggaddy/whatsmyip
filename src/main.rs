use std::net::SocketAddr;

use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    init_tracing();

    let bind_addr = match resolve_bind_addr() {
        Ok(addr) => addr,
        Err(err) => {
            eprintln!("invalid bind address: {err}");
            std::process::exit(2);
        }
    };

    let config = match whatsmyip::AppConfig::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("configuration error: {err}");
            std::process::exit(2);
        }
    };

    let app = whatsmyip::build_app(config);

    let listener = match TcpListener::bind(bind_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("failed to bind {bind_addr}: {err}");
            std::process::exit(1);
        }
    };

    tracing::info!(%bind_addr, "listening");

    if let Err(err) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    {
        eprintln!("server error: {err}");
        std::process::exit(1);
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info,whatsmyip=info,axum::rejection=trace")
    });

    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn resolve_bind_addr() -> Result<SocketAddr, String> {
    if let Ok(bind_addr) = std::env::var("BIND_ADDR") {
        return bind_addr
            .parse::<SocketAddr>()
            .map_err(|err| format!("BIND_ADDR '{bind_addr}' is invalid: {err}"));
    }

    if let Ok(port) = std::env::var("PORT") {
        let port: u16 = port
            .parse()
            .map_err(|err| format!("PORT '{port}' is invalid: {err}"))?;
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], port));
        return Ok(bind_addr);
    }

    "0.0.0.0:8080"
        .parse::<SocketAddr>()
        .map_err(|err| format!("default bind address invalid: {err}"))
}

async fn shutdown_signal() {
    if tokio::signal::ctrl_c().await.is_ok() {
        tracing::info!("shutdown signal received");
    }
}
