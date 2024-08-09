use axum::Router;
use if_addrs::get_if_addrs;
use std::net::{IpAddr, SocketAddr};
use tokio::net::{TcpListener, ToSocketAddrs};

pub async fn serve<S: ToSocketAddrs>(addr: S, router: Router) -> std::io::Result<()> {
    let tcp_listener = TcpListener::bind(addr).await?;
    print_listener_urls(&tcp_listener);

    axum::serve(tcp_listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
}

fn print_listener_urls(listener: &TcpListener) {
    if let Ok(addr) = listener.local_addr() {
        let port = addr.port();
        log::info!("Listening on port {}", port);
        match addr {
            SocketAddr::V4(addr4) if addr4.ip().is_unspecified() => {
                for ip in get_interface_ips(false) {
                    print_addr(ip, port)
                }
            }
            SocketAddr::V6(addr6) if addr6.ip().is_unspecified() => {
                for ip in get_interface_ips(true) {
                    print_addr(ip, port)
                }
            }
            _ => print_addr(addr.ip(), port),
        }
    } else {
        eprintln!("Could not determine the address the server is listening on.");
    }
}

fn get_interface_ips(ipv6: bool) -> Vec<IpAddr> {
    get_if_addrs()
        .into_iter()
        .flatten()
        .map(|i| i.ip())
        .filter(|ip| (ipv6 && ip.is_ipv6()) || (!ipv6 && ip.is_ipv4()))
        .collect()
}

fn print_addr(addr: IpAddr, port: u16) {
    match addr {
        _ if addr.is_loopback() => log::info!("➜  Local:   http://localhost:{}", port),
        IpAddr::V4(_) => log::info!("➜  Network: http://{}:{}", addr, port),
        // Enclose IPv6 addresses in square brackets
        IpAddr::V6(_) => log::info!("➜  Network: http://[{}]:{}", addr, port),
    }
}

pub async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
