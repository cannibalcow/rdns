use super::types::QClass;
use super::{error::DnsError, types::QueryType};
pub struct DNSQuestion {
    pub qname: QName,
    pub qtype: QueryType,
    pub qclass: QClass,
}

#[derive(PartialEq, Debug, Clone)]
pub struct QName {
    pub parts: Vec<String>,
    pub raw: Vec<u8>,
    pub last_read: usize,
}

impl DNSQuestion {
    pub fn decode(dns_request: &[u8]) -> Result<DNSQuestion, DnsError> {
        let qname = DNSQuestion::parse_qname(dns_request).unwrap();
        return Ok(DNSQuestion {
            qname: qname.clone(),
            qtype: DNSQuestion::parse_qtype(dns_request, &qname.last_read).unwrap(),
            qclass: DNSQuestion::parse_qclass(dns_request, &qname.last_read).unwrap(),
        });
    }

    pub fn parse_qtype(dns_request: &[u8], read_from: &usize) -> Result<QueryType, ()> {
        let value = dns_request[read_from + 1];
        return Ok(QueryType::from_u8(value));
    }

    pub fn parse_qclass(dns_request: &[u8], read_from: &usize) -> Result<QClass, ()> {
        let value = dns_request[read_from + 3];
        return Ok(QClass::from_u8(value));
    }

    pub fn print(&self) {
        println!("DNS QUESTION");
        println!("QNAME: {:?}", self.qname);
        println!("QType: {:?}", self.qtype);
        println!("QClass: {:?}", self.qclass);
    }

    pub fn parse_qname(dns_request: &[u8]) -> Result<QName, DnsError> {
        let result = DNSQuestion::parse_qname_parts(12, dns_request, &mut vec![]);
        let last_read = result.1;
        let qname = QName {
            parts: result.0,
            raw: (&dns_request[12..last_read]).to_vec(),
            last_read: last_read,
        };

        return Ok(qname);
    }

    pub fn parse_qname_parts(
        pos: usize,
        dns_request: &[u8],
        parts: &mut Vec<String>,
    ) -> (Vec<String>, usize) {
        let read_forward: usize = dns_request[pos] as usize;

        if read_forward == 0 {
            return (parts.to_vec(), pos + read_forward + 1);
        }

        let part = &dns_request[pos + 1..=pos + read_forward];
        parts.push(String::from_utf8(part.to_vec()).unwrap());

        let next_pos = pos + read_forward + 1;

        return DNSQuestion::parse_qname_parts(next_pos, dns_request, parts);
    }
}
