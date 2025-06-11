use core::fmt;
use std::io;
use redis::RedisError;
use hickory_proto::error::ProtoError;
use hickory_resolver::error::ResolveError;

pub type DnsBlrsResult<T> = std::result::Result<T, DnsBlrsError>;

/// Custom error type
pub enum DnsBlrsError {
    InvalidOpCode(u8),
    MessageTypeNotQuery,
    SocketBinding,
    NoQueryInRequest,

    Redis(RedisError),
    IO(io::Error),
    Resolver(ResolveError),
    // SystemTime(SystemTimeError),
    Proto(ProtoError)
}

impl fmt::Display for DnsBlrsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DnsBlrsError::InvalidOpCode(code) => write!(f, "Opcode received '{code}' was not query (0)"),
            DnsBlrsError::MessageTypeNotQuery => write!(f, "Message type received was not query"),
            DnsBlrsError::SocketBinding => write!(f, "Failed to bind any socket"),
            DnsBlrsError::NoQueryInRequest => write!(f, "No query found in request"),
            DnsBlrsError::Redis(e) => write!(f, "A Redis error occured: {e}"),
            DnsBlrsError::IO(e) => write!(f, "An IO error occured: {e}"),
            DnsBlrsError::Resolver(e) => write!(f, "A Resolver error occured: {e}"),
            DnsBlrsError::Proto(e) => write!(f, "A Proto error occured: {e}")
        }
    }
}

impl From<RedisError> for DnsBlrsError {
    fn from(e: RedisError) -> Self {
        DnsBlrsError::Redis(e)
    }
}
impl From<ResolveError> for DnsBlrsError {
    fn from(e: ResolveError) -> Self {
        DnsBlrsError::Resolver(e)
    }
}
impl From<ProtoError> for DnsBlrsError {
    fn from(e: ProtoError) -> Self {
        DnsBlrsError::Proto(e)
    }
}
impl From<io::Error> for DnsBlrsError {
    fn from(e: io::Error) -> Self {
        DnsBlrsError::IO(e)
    }
}
