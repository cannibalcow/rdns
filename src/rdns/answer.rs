use super::types::QClass;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum AnswerType {
    A = 1,      //a host address
    NS = 2,     // an authoritative name server
    MD = 3,     // a mail destination (Obsolete - use MX)
    MF = 4,     // a mail forwarder (Obsolete - use MX)
    CNAME = 5,  // the canonical name for an alias
    SOA = 6,    // marks the start of a zone of authority
    MB = 7,     //a mailbox domain name (EXPERIMENTAL)
    MG = 8,     //a mail group member (EXPERIMENTAL)
    MR = 9,     //a mail rename domain name (EXPERIMENTAL)
    NULL = 10,  //a null RR (EXPERIMENTAL)
    WKS = 11,   //a well known service description
    PTR = 12,   // a domain name pointer
    HINFO = 13, // host information
    MINFO = 14, // mailbox or mail list information
    MX = 15,    // mail exchange
    TXT = 16,   // text strings
}
#[derive(Debug)]
#[allow(dead_code)]
pub struct Answer {
    name: Vec<u8>,
    answertype: AnswerType,
    class: QClass,
    ttl: u8,
    rdlength: u8,
    rddata: Vec<u8>,
}

impl Answer {
    pub fn new(
        name: Vec<u8>,
        answertype: AnswerType,
        class: QClass,
        ttl: u8,
        rddata: Vec<u8>,
    ) -> Self {
        return Answer {
            name: name,
            answertype: answertype,
            class: class,
            ttl: ttl,
            rdlength: rddata.len() as u8,
            rddata: rddata,
        };
    }

    pub fn to_udp_package(&self) -> Vec<u8> {
        let s = self.clone();
        let mut packet: Vec<u8> = vec![];
        let mut name = s.name.clone();
        let typ = (s.answertype.clone()) as u8;
        let class = (s.class.clone()) as u8;
        let ttl = s.ttl.clone();
        let mut rddata = s.rddata.clone();

        packet.append(&mut name);
        packet.append(&mut vec![typ]);
        packet.append(&mut vec![class]);
        packet.append(&mut vec![ttl]);
        packet.append(&mut vec![self.rdlength]);
        packet.append(&mut rddata);

        return packet.clone();
    }
}
