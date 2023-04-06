use std::{
    net::{SocketAddr, Ipv6Addr, Ipv4Addr},
    io,
    time::SystemTimeError
};
use serde::{Serialize, Deserialize};

use redis::RedisError;

use trust_dns_resolver::error::ResolveError;

pub type DnsLrResult<T> = std::result::Result<T, DnsLrError>;

#[derive(Serialize, Deserialize, Debug, Clone)]
/// The configuration file structure
pub struct Confile {
    pub daemon_id: String,
    pub redis_address: String
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// The configuration structure
pub struct Config { 
    pub forwarders: Vec<SocketAddr>,
    pub binds: Vec<String>,
    pub is_filtering: bool,
    pub matchclasses: Option<Vec<String>>,
    pub blackhole_ips: Option<(Ipv4Addr, Ipv6Addr)>
}
// Implementation of the Default trait
impl Default for Config {
    /// Initializes the configuration structure with its default values
    fn default() -> Self {
        Config {
            forwarders: vec![],
            binds : vec![],
            is_filtering: false,
            matchclasses: None,
            blackhole_ips: None
        }
    }
}

#[derive(Debug)]
/// The custom error structure
pub struct DnsLrError {
    kind: DnsLrErrorKind
}
impl DnsLrError {
    // Links the error types to the error structure
    pub fn kind(&self) -> &DnsLrErrorKind {
        &self.kind
    }
}
impl From<DnsLrErrorKind> for DnsLrError {
    /// Implements the From trait to construct the error structure with the error types
    fn from(kind: DnsLrErrorKind) -> Self {
        Self {kind}
    }
}

#[derive(Debug)]
/// The custom error types
pub enum DnsLrErrorKind {
    InvalidOpCode,
    InvalidMessageType,
    InvalidArpaAddress,
    InvalidRule,
    SetupBindingError,
    SetupForwardersError,
    RequestRefused,
    // The custom error type wraps around the external crates errors
    // to enable error propagation
    ExternCrateError(ExternCrateErrorKind),
}

#[derive(Debug)]
/// The errors from external crates
pub enum ExternCrateErrorKind {
    RedisError(RedisError),
    IOError(io::Error),
    ResolverError(ResolveError),
    SystemTimeError(SystemTimeError)
}