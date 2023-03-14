use core::fmt;
use std::{
    fmt::{Display, Formatter},
    net::{SocketAddr, Ipv6Addr, Ipv4Addr},
    io
};
use serde::{Serialize, Deserialize};

use tokio::task::JoinError;
use trust_dns_resolver::error::ResolveError;
use trust_dns_proto::error::ProtoError;
use redis::RedisError;

pub type DnsLrResult<T> = std::result::Result<T, WrappedErrors>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Confile {
    pub daemon_id: String,
    pub redis_address: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config { 
    pub daemon_id: String,
    pub forwarders: Vec<SocketAddr>,
    pub binds: Vec<String>,
    pub is_filtering: bool,
    pub matchclasses: Option<Vec<String>>,
    pub blackhole_ips: Option<(Ipv4Addr, Ipv6Addr)>
}

#[derive(Debug)]
pub enum WrappedErrors {
    DNSlrError(ErrorKind),
    RedisError(RedisError),
    IOError(io::Error),
    ResolverError(ResolveError),
    ProtoError(ProtoError),
    JoinError(JoinError)
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ErrorKind {
    InvalidOpCode,
    InvalidMessageType,
    InvalidArpaAddress,
    SetupBindingError,
    SetupForwardersError,
    RequestRefused
}

impl Display for WrappedErrors {
    fn fmt (&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            WrappedErrors::DNSlrError(ref error) => write!(f, "A DNSlr error occurred {:?}", error),
            WrappedErrors::IOError(ref error) => error.fmt(f),
            WrappedErrors::RedisError(ref error) => error.fmt(f),
            WrappedErrors::ResolverError(ref error) => error.fmt(f),
            WrappedErrors::ProtoError(ref error) => error.fmt(f),
            WrappedErrors::JoinError(ref error) => error.fmt(f)
        }
    }
}
impl From<RedisError> for WrappedErrors {
    fn from (error: RedisError) -> WrappedErrors {
        WrappedErrors::RedisError(error)
    }
}
impl From<io::Error> for WrappedErrors {
    fn from (error: io::Error) -> WrappedErrors {
        WrappedErrors::IOError(error)
    }
}
impl From<ResolveError> for WrappedErrors {
    fn from (error: ResolveError) -> WrappedErrors {
        WrappedErrors::ResolverError(error)
    }
}
impl From<ProtoError> for WrappedErrors {
    fn from (error: ProtoError) -> WrappedErrors {
        WrappedErrors::ProtoError(error)
    }
}
impl From<JoinError> for WrappedErrors {
    fn from (error: JoinError) -> WrappedErrors {
        WrappedErrors::JoinError(error)
    }
}
