pub mod protocol;
pub mod socket;

pub use protocol::{AuthenticationProtocol, NoopAuthProtocol, NoopHeader, WireAuthProtocol};
pub use socket::{AuthenticatedSocketHandle, DualSocketHandle};
