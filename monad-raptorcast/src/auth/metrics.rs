pub const GAUGE_RAPTORCAST_AUTH_AUTHENTICATED_UDP_BYTES_WRITTEN: &str =
    "monad.raptorcast.auth.authenticated_udp_bytes_written";
pub const GAUGE_RAPTORCAST_AUTH_NON_AUTHENTICATED_UDP_BYTES_WRITTEN: &str =
    "monad.raptorcast.auth.non_authenticated_udp_bytes_written";
pub const GAUGE_RAPTORCAST_AUTH_AUTHENTICATED_UDP_BYTES_READ: &str =
    "monad.raptorcast.auth.authenticated_udp_bytes_read";
pub const GAUGE_RAPTORCAST_AUTH_NON_AUTHENTICATED_UDP_BYTES_READ: &str =
    "monad.raptorcast.auth.non_authenticated_udp_bytes_read";

pub const GAUGE_RAPTORCAST_AUTH_SIGNATURE_TCP_BYTES_WRITTEN: &str =
    "monad.raptorcast.auth.signature_tcp_bytes_written";
pub const GAUGE_RAPTORCAST_AUTH_WIREAUTH_TCP_BYTES_WRITTEN: &str =
    "monad.raptorcast.auth.wireauth_tcp_bytes_written";
pub const GAUGE_RAPTORCAST_AUTH_SIGNATURE_TCP_BYTES_READ: &str =
    "monad.raptorcast.auth.signature_tcp_bytes_read";
pub const GAUGE_RAPTORCAST_AUTH_WIREAUTH_TCP_BYTES_READ: &str =
    "monad.raptorcast.auth.wireauth_tcp_bytes_read";

pub struct UdpMetrics;

monad_wireauth::impl_metric_names!(UdpMetrics, "udp");

pub struct TcpMetrics;

monad_wireauth::impl_metric_names!(TcpMetrics, "tcp");
