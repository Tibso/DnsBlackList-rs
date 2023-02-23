use std::str::FromStr;

use crate::handler_mod::CustomError;

use trust_dns_client::{
    op::LowerQuery,
    rr::{RecordType, RData}
};
use trust_dns_proto::rr::Record;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    Name,
    TokioAsyncResolver
};

pub async fn get_answers (
    request: &LowerQuery
) -> Result<Vec<Record>, CustomError> {
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::google(),
        ResolverOpts::default()
    ).unwrap();

    let mut answers: Vec<Record> =  Vec::new();
    let name_binding = request.name().to_string();
    let name = name_binding.as_str();
    match request.query_type() {
        RecordType::A => {
            let response = match resolver.ipv4_lookup(name).await {
                Ok(ok) => ok,
                Err(error) => return Err(CustomError::ResolverError(error))
            };

            for rdata in response {
                answers.push(Record::from_rdata(Name::from_str(name).unwrap(), 60, RData::A(rdata)));
            } 
        },
        RecordType::AAAA => {
            let response = match resolver.ipv6_lookup(name).await {
                Ok(ok) => ok,
                Err(error) => return Err(CustomError::ResolverError(error))
            };

            for rdata in response {
                answers.push(Record::from_rdata(Name::from_str(name).unwrap(), 60, RData::AAAA(rdata)));
            } 
        },
        RecordType::TXT => {
            let response = match resolver.txt_lookup(name).await {
                Ok(ok) => ok,
                Err(error) => return Err(CustomError::ResolverError(error))
            };

            for rdata in response {
                answers.push(Record::from_rdata(Name::from_str(name).unwrap(), 60, RData::TXT(rdata)));
            } 
        },
        _ => todo!()
    }

    return Ok(answers)
}