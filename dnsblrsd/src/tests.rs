#[cfg(test)]
mod tests {
    use crate::resolver::{self, Records};

    use std::{str::FromStr, net::Ipv4Addr};

    use hickory_proto::{
        rr::{dnssec::{rdata::RRSIG, Algorithm}, rdata, Record, RecordData, RecordType},
        op::Query
    };
    use hickory_resolver::{lookup::Lookup, Name};

    #[test]
    fn a_lookup() {
        let query_name = Name::from_str("test.example.com").unwrap();
        let query_type = RecordType::A;
        let lookup = Lookup::from_rdata(
            Query::query(query_name.clone(), query_type),
            RecordData::into_rdata(rdata::A(Ipv4Addr::from_str("127.0.0.1").unwrap()))
        );

        let mut sorted_records = Records::new();
        resolver::sort_records(lookup.records(), &query_name, query_type, &mut sorted_records);

        assert_eq!(sorted_records.answer.len(), 1);
        assert_eq!(sorted_records.name_servers.len(), 0);
        assert_eq!(sorted_records.soas.len(), 0);
        assert_eq!(sorted_records.additional.len(), 0);
    }

    #[test]
    fn a_lookup_dnssec() {
        let query_name = Name::from_str("test.example.com").unwrap();
        let query_type = RecordType::A;
        let mut lookup = Lookup::from_rdata(
            Query::query(query_name.clone(), query_type),
            RecordData::into_rdata(rdata::A(Ipv4Addr::from_str("127.0.0.1").unwrap()))
        );
        lookup.extend_records(vec![Record::from_rdata(
            query_name.clone(),
            86400,
            RecordData::into_rdata(RRSIG::new(
                RecordType::A,
                Algorithm::RSASHA256,
                1, 86400, 1, 1, 1,
                Name::new(),
                Vec::new()
            )))]);

        let mut sorted_records = SortedRecords::new();
        resolver::sort_records(lookup.records(), &query_name, query_type, &mut sorted_records);

        assert_eq!(sorted_records.answer.len(), 2);
        assert_eq!(sorted_records.name_servers.len(), 0);
        assert_eq!(sorted_records.soas.len(), 0);
        assert_eq!(sorted_records.additional.len(), 0);
    }

    #[test]
    fn cname_lookup() {
        let query_name = Name::from_str("test.example.net").unwrap();
        let query_type = RecordType::A;
        let mut lookup = Lookup::from_rdata(
            Query::query(query_name.clone(), query_type),
            RecordData::into_rdata(rdata::CNAME(Name::from_str("test.example.com").unwrap()))
        );
        lookup.extend_records(vec![Record::from_rdata(
            Name::from_str("test.example.com").unwrap(),
            86400,
            RecordData::into_rdata(rdata::A(Ipv4Addr::from_str("127.0.0.1").unwrap())))]);

        let mut sorted_records = SortedRecords::new();
        resolver::sort_records(lookup.records(), &query_name, query_type, &mut sorted_records);

        assert_eq!(sorted_records.answer.len(), 2);
        assert_eq!(sorted_records.name_servers.len(), 0);
        assert_eq!(sorted_records.soas.len(), 0);
        assert_eq!(sorted_records.additional.len(), 0);
    }
}
