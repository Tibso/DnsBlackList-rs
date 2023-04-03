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
pub struct Confile {
    pub daemon_id: String,
    pub redis_address: String
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config { 
    pub forwarders: Vec<SocketAddr>,
    pub binds: Vec<String>,
    pub is_filtering: bool,
    pub matchclasses: Option<Vec<String>>,
    pub blackhole_ips: Option<(Ipv4Addr, Ipv6Addr)>
}
impl Default for Config {
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
pub struct DnsLrError {
    kind: DnsLrErrorKind
}
impl DnsLrError {
    pub fn kind(&self) -> &DnsLrErrorKind {
        &self.kind
    }
}
impl From<DnsLrErrorKind> for DnsLrError {
    fn from(kind: DnsLrErrorKind) -> Self {
        Self {kind}
    }
}

#[derive(Debug)]
pub enum DnsLrErrorKind {
    InvalidOpCode,
    InvalidMessageType,
    InvalidArpaAddress,
    InvalidRule,
    SetupBindingError,
    SetupForwardersError,
    RequestRefused,
    ExternCrateError(ExternCrateErrorKind),
}

#[derive(Debug)]
pub enum ExternCrateErrorKind {
    RedisError(RedisError),
    IOError(io::Error),
    ResolverError(ResolveError),
    SystemTimeError(SystemTimeError)
}
