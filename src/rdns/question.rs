use super::error::DnsError;
pub struct DNSQuestion {
    qname: Vec<String>,
    qtype: QueryType,
}

impl DNSQuestion {
    pub fn decode(dns_request: &[u8]) -> Result<DNSQuestion, DnsError> {
        let host_parts = DNSQuestion::parse_qname(dns_request);

        // fix
        let parts = host_parts.unwrap();

        return Ok(DNSQuestion {
            qname: parts.0,
            qtype: DNSQuestion::parse_qtype(dns_request, &parts.1).unwrap(),
        });
    }

    pub fn parse_qtype(dns_request: &[u8], read_from: &usize) -> Result<QueryType, ()> {
        let value = dns_request[read_from + 1];
        return Ok(QueryType::from(value));
    }

    pub fn print(&self) {
        println!("DNS QUESTION");
        println!("QNAME: {:?}", self.qname);
        println!("QType: {:?}", self.qtype);
    }

    pub fn parse_qname(dns_request: &[u8]) -> Result<(Vec<String>, usize), DnsError> {
        let result = DNSQuestion::parse_qname_parts(12, dns_request, &mut vec![]);
        return Ok(result);
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

#[allow(dead_code)]
#[derive(Debug, PartialEq)]
pub enum QueryType {
    A = 1,      // IP address
    NS = 2,     // name server
    CNAME = 5,  // canonical name
    PTR = 12,   // pointer record
    HINFO = 13, // host info
    MX = 15,    // mx
    AXFR = 252, // request for zone transfer
    ANY = 255,  // request for all records
}

impl QueryType {
    fn from(val: u8) -> QueryType {
        println!("Query value: {}", val);
        match val {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            12 => QueryType::PTR,
            13 => QueryType::HINFO,
            15 => QueryType::MX,
            252 => QueryType::AXFR,
            255 => QueryType::ANY,
            _ => panic!("Unknown query type"),
        }
    }
}
