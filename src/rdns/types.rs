#[derive(PartialEq, Debug, Clone)]
pub enum QClass {
    IN = 1,    // Internet address
    CS = 2,    // CSNET (obsolete)
    CH = 3,    // CHAOS Class
    HS = 4,    // Hesioid [Dyer 87]
    ANY = 255, // ANY
}

impl QClass {
    pub fn from_u8(value: u8) -> QClass {
        match value {
            1 => QClass::IN,
            2 => QClass::CS,
            3 => QClass::CH,
            4 => QClass::HS,
            255 => QClass::ANY,
            _ => panic!("Invalid qclass value: {:?}", value),
        }
    }
}

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
    pub fn from_u8(val: u8) -> QueryType {
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
