use std::{
    net::{SocketAddr, Ipv6Addr, Ipv4Addr},
    io
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
    SetupBindingError,
    SetupForwardersError,
    RequestRefused,
    ExternCrateError(ExternCrateErrorKind),
}

#[derive(Debug)]
pub enum ExternCrateErrorKind {
    RedisError(RedisError),
    IOError(io::Error),
    ResolverError(ResolveError)
}
/*
impl From<RedisError> for ExternCrateErrorKind {
    fn from(error: RedisError) -> ExternCrateErrorKind {
        ExternCrateErrorKind::RedisError(error)
    }
}
impl From<io::Error> for ExternCrateErrorKind {
    fn from(error: io::Error) -> ExternCrateErrorKind {
        ExternCrateErrorKind::IOError(error)
    }
}
impl From<ResolveError> for ExternCrateErrorKind {
    fn from(error: ResolveError) -> ExternCrateErrorKind {
        ExternCrateErrorKind::ResolverError(error)
    }
}
impl From<ProtoError> for ExternCrateErrorKind {
    fn from(error: ProtoError) -> ExternCrateErrorKind {
        ExternCrateErrorKind::ProtoError(error)
    }
}
impl From<JoinError> for ExternCrateErrorKind {
    fn from(error: JoinError) -> ExternCrateErrorKind {
        ExternCrateErrorKind::JoinError(error)
    }
}
*/