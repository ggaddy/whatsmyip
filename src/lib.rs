use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
    routing::get,
    Router,
};
use ipnet::IpNet;
use std::{net::{IpAddr, SocketAddr}, sync::Arc};

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub trusted_proxies: Vec<IpNet>,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, String> {
        let trusted_proxies = match std::env::var("TRUSTED_PROXIES") {
            Ok(value) => parse_trusted_proxies(&value)?,
            Err(std::env::VarError::NotPresent) => Vec::new(),
            Err(err) => {
                return Err(format!(
                    "failed to read TRUSTED_PROXIES: {err}"
                ))
            }
        };

        Ok(Self { trusted_proxies })
    }
}

#[derive(Clone, Debug)]
struct AppState {
    trusted_proxies: Vec<IpNet>,
}

pub fn build_app(config: AppConfig) -> Router {
    let state = Arc::new(AppState {
        trusted_proxies: config.trusted_proxies,
    });

    Router::new()
        .route("/", get(ip_handler))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(state)
}

async fn ip_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let client_ip = resolve_client_ip(peer.ip(), &headers, &state.trusted_proxies);
    text_response(StatusCode::OK, format!("{}\n", client_ip))
}

async fn healthz() -> Response {
    text_response(StatusCode::OK, "ok\n".to_string())
}

async fn readyz() -> Response {
    text_response(StatusCode::OK, "ready\n".to_string())
}

pub fn resolve_client_ip(
    peer_ip: IpAddr,
    headers: &HeaderMap,
    trusted_proxies: &[IpNet],
) -> IpAddr {
    if trusted_proxies.is_empty() || !is_trusted(peer_ip, trusted_proxies) {
        return peer_ip;
    }

    if let Some(ip) = header_ip(headers, "cf-connecting-ip") {
        return ip;
    }

    if let Some(ip) = x_forwarded_for(headers, trusted_proxies) {
        return ip;
    }

    if let Some(ip) = header_ip(headers, "x-real-ip") {
        return ip;
    }

    peer_ip
}

fn x_forwarded_for(headers: &HeaderMap, trusted_proxies: &[IpNet]) -> Option<IpAddr> {
    let ips = parse_x_forwarded_for(headers);
    if ips.is_empty() {
        return None;
    }

    for ip in ips.iter().rev() {
        if !is_trusted(*ip, trusted_proxies) {
            return Some(*ip);
        }
    }

    Some(ips[0])
}

fn parse_x_forwarded_for(headers: &HeaderMap) -> Vec<IpAddr> {
    let value = match headers.get("x-forwarded-for") {
        Some(value) => value,
        None => return Vec::new(),
    };

    let value = match value.to_str() {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };

    value
        .split(',')
        .filter_map(|part| part.trim().parse::<IpAddr>().ok())
        .collect()
}

fn header_ip(headers: &HeaderMap, name: &str) -> Option<IpAddr> {
    let value = headers.get(name)?;
    parse_header_ip(value)
}

fn parse_header_ip(value: &HeaderValue) -> Option<IpAddr> {
    let value = value.to_str().ok()?;
    value.trim().parse().ok()
}

fn is_trusted(ip: IpAddr, trusted_proxies: &[IpNet]) -> bool {
    trusted_proxies.iter().any(|net| net.contains(&ip))
}

pub fn parse_trusted_proxies(value: &str) -> Result<Vec<IpNet>, String> {
    let mut proxies = Vec::new();

    for part in value.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }

        let net = if trimmed.contains('/') {
            trimmed
                .parse::<IpNet>()
                .map_err(|err| format!("invalid CIDR '{trimmed}': {err}"))?
        } else {
            let ip = trimmed
                .parse::<IpAddr>()
                .map_err(|err| format!("invalid IP '{trimmed}': {err}"))?;
            let prefix = if ip.is_ipv4() { 32 } else { 128 };
            IpNet::new(ip, prefix).map_err(|err| {
                format!("invalid trusted proxy '{trimmed}': {err}")
            })?
        };

        proxies.push(net);
    }

    Ok(proxies)
}

fn text_response(status: StatusCode, body: String) -> Response {
    let mut response = Response::new(body.into());
    *response.status_mut() = status;
    let headers = response.headers_mut();

    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    );

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use axum::Router;
    use http_body_util::BodyExt;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tower::ServiceExt;

    #[test]
    fn parse_trusted_proxies_accepts_single_ip() {
        let proxies = parse_trusted_proxies("10.0.0.1").expect("valid ip");
        assert_eq!(proxies.len(), 1);
        assert!(proxies[0].contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn parse_trusted_proxies_accepts_cidr() {
        let proxies = parse_trusted_proxies("10.0.0.0/24").expect("valid cidr");
        assert_eq!(proxies.len(), 1);
        assert!(proxies[0].contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42))));
    }

    #[test]
    fn resolve_client_ip_ignores_headers_when_untrusted() {
        let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.10"),
        );
        let ip = resolve_client_ip(peer_ip, &headers, &[]);
        assert_eq!(ip, peer_ip);
    }

    #[test]
    fn resolve_client_ip_prefers_cf_connecting_ip() {
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let trusted = parse_trusted_proxies("10.0.0.0/24").expect("trusted");
        let mut headers = HeaderMap::new();
        headers.insert(
            "cf-connecting-ip",
            HeaderValue::from_static("198.51.100.10"),
        );
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.10"),
        );

        let ip = resolve_client_ip(peer_ip, &headers, &trusted);
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)));
    }

    #[test]
    fn resolve_client_ip_uses_x_forwarded_for_chain() {
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let trusted = parse_trusted_proxies("10.0.0.0/24, 192.0.2.0/24").expect("trusted");
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.5, 192.0.2.10"),
        );

        let ip = resolve_client_ip(peer_ip, &headers, &trusted);
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
    }

    #[tokio::test]
    async fn handler_returns_peer_ip_when_untrusted() {
        let app = build_app(AppConfig {
            trusted_proxies: Vec::new(),
        });

        let peer = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 4242));
        let mut request = Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .expect("request");

        request.extensions_mut().insert(ConnectInfo(peer));

        let response = app.oneshot(request).await.expect("response");
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let body = std::str::from_utf8(&body).expect("utf8");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "127.0.0.1\n");
    }

    #[tokio::test]
    async fn handler_honors_trusted_proxy_header() {
        let trusted_proxies = parse_trusted_proxies("127.0.0.1").expect("trusted");
        let app = build_app(AppConfig { trusted_proxies });

        let peer = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 4242));
        let mut request = Request::builder()
            .uri("/")
            .header("cf-connecting-ip", "203.0.113.55")
            .body(axum::body::Body::empty())
            .expect("request");

        request.extensions_mut().insert(ConnectInfo(peer));

        let response = app.oneshot(request).await.expect("response");
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let body = std::str::from_utf8(&body).expect("utf8");

        assert_eq!(body, "203.0.113.55\n");
    }

    #[tokio::test]
    async fn healthz_is_ok() {
        let app = build_app(AppConfig {
            trusted_proxies: Vec::new(),
        });

        let mut request = Request::builder()
            .uri("/healthz")
            .body(axum::body::Body::empty())
            .expect("request");
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((
                Ipv4Addr::new(127, 0, 0, 1),
                4242,
            ))));

        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    fn build_app(config: AppConfig) -> Router {
        super::build_app(config)
    }
}
