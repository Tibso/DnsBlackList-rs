use std::{io, net::{Ipv4Addr, Ipv6Addr}, time::SystemTimeError};
use redis::RedisError;
use hickory_proto::error::ProtoError;
use hickory_resolver::error::ResolveError;
use serde::Deserialize;

pub type DnsBlrsResult<T> = std::result::Result<T, DnsBlrsError>;

#[derive(Deserialize, Debug, Clone)]
/// The configuration file structure
pub struct Confile {
    pub daemon_id: String,
    pub redis_address: String
}

#[derive(Deserialize, Debug, Clone)]
/// The configuration structure
pub struct Config {
    pub is_filtering: bool,
    pub filters: Vec<String>,
    pub blackholes: (Ipv4Addr, Ipv6Addr)
}
impl Default for Config {
    /// Initializes the configuration structure with its default values
    fn default() -> Self {
        Self {
            is_filtering: false,
            filters: Vec::new(),
            blackholes: (Ipv4Addr::LOCALHOST, Ipv6Addr::LOCALHOST)
        }
    }
}

#[derive(Debug)]
/// The custom error structure
pub struct DnsBlrsError {
    kind: DnsBlrsErrorKind
}
impl DnsBlrsError {
    /// Links the error types to the error structure
    pub fn kind(self) -> DnsBlrsErrorKind {
        self.kind
    }
}
impl From<DnsBlrsErrorKind> for DnsBlrsError {
    /// Implements the From trait to construct the error structure with the error types
    fn from(kind: DnsBlrsErrorKind) -> Self {
        Self {kind}
    }
}

impl From<RedisError> for DnsBlrsError {
    fn from(err: RedisError) -> Self {
        Self {kind: DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::Redis(err))}
    }
}
impl From<SystemTimeError> for DnsBlrsError {
    fn from(err: SystemTimeError) -> Self {
        Self {kind: DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::SystemTime(err))}
    }
}
impl From<ResolveError> for DnsBlrsError {
    fn from(err: ResolveError) -> Self {
        Self {kind: DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::Resolver(err))}
    }
}
impl From<ProtoError> for DnsBlrsError {
    fn from(err: ProtoError) -> Self {
        Self {kind: DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::Proto(err))}
    }
}
impl From<io::Error> for DnsBlrsError {
    fn from(err: io::Error) -> Self {
        Self {kind: DnsBlrsErrorKind::ExternCrateError(ExternCrateErrorKind::IO(err))}
    }
}

#[derive(Debug)]
/// Custom error type
pub enum DnsBlrsErrorKind {
    InvalidOpCode,
    InvalidMessageType,
    InvalidRule,
    NotImpl,
    SetupBinding,
    BuildConfig,
    RequestRefused,
    LogicError,
    // This custom error type wraps the external crates errors
    // to enable proper error propagation
    ExternCrateError(ExternCrateErrorKind),
}

#[derive(Debug)]
/// The errors from external crates
pub enum ExternCrateErrorKind {
    Redis(RedisError),
    IO(io::Error),
    Resolver(ResolveError),
    SystemTime(SystemTimeError),
    Proto(ProtoError)
}
