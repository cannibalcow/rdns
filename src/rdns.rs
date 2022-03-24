// https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
#[derive(PartialEq, Debug)]
enum QR {
    QUERY,
    RESPONSE,
}

#[derive(PartialEq, Debug)]
enum OPCode {
    QUERY = 0,
    IQUERY = 1,
    STATUS = 2,
    NOTIFY = 4,
    UPDATE = 5,
}

impl OPCode {
    fn from_u32(value: u32) -> OPCode {
        match value {
            0 => OPCode::QUERY,
            1 => OPCode::IQUERY,
            2 => OPCode::STATUS,
            4 => OPCode::NOTIFY,
            5 => OPCode::UPDATE,
            _ => panic!("Ivalid opcode value"),
        }
    }
}

#[derive(Debug)]
enum ReturnCode {
    NoError = 0,
    FormatError = 1,
    ServFail = 2,
    NameError = 3,
    Refused = 5,
    YXDomain = 6,
    YXRRSet = 7,
    NXRRSet = 8,
    NotAuth = 9,
    NotZone = 10,
}

impl ReturnCode {
    fn from_u8(value: u8) -> ReturnCode {
        match value {
            0 => ReturnCode::NoError,
            1 => ReturnCode::FormatError,
            2 => ReturnCode::ServFail,
            3 => ReturnCode::NameError,
            5 => ReturnCode::Refused,
            6 => ReturnCode::YXDomain,
            7 => ReturnCode::YXRRSet,
            8 => ReturnCode::NXRRSet,
            9 => ReturnCode::NotAuth,
            10 => ReturnCode::NotZone,
            _ => panic!("Inalid opcode: {:?}", value),
        }
    }
}

pub struct DNSHeader {
    id: u16,
    qr: QR,
    opcode: OPCode,
    aa: bool,
    truncated: bool,
    recursion_desired: bool,
    recursion_available: bool,
    return_code: ReturnCode,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl DNSHeader {
    pub fn decode(dns_request: &[u8]) -> Result<DNSHeader, ()> {
        return Ok(DNSHeader {
            id: DNSHeader::parse_header_id(dns_request),
            qr: DNSHeader::parse_header_qr(dns_request)?,
            opcode: DNSHeader::parse_header_opcode(dns_request)?,
            aa: DNSHeader::parse_header_aa(dns_request)?,
            truncated: DNSHeader::parse_header_tc(dns_request)?,
            recursion_desired: DNSHeader::parse_header_rd(dns_request)?,
            recursion_available: DNSHeader::parse_header_ra(dns_request)?,
            return_code: DNSHeader::parse_header_rc(dns_request)?,
            qdcount: DNSHeader::parse_header_qdcount(dns_request),
            ancount: DNSHeader::parse_header_ancount(dns_request),
            nscount: DNSHeader::parse_header_nscount(dns_request),
            arcount: DNSHeader::parse_header_arcount(dns_request),
        });
    }

    fn parse_header_arcount(dns_request: &[u8]) -> u16 {
        let count: u16 = ((dns_request[10] as u16) << 8) | dns_request[11] as u16;
        return count;
    }

    fn parse_header_nscount(dns_request: &[u8]) -> u16 {
        let count = ((dns_request[8] as u16) << 8) | dns_request[9] as u16;
        return count;
    }

    fn parse_header_ancount(dns_request: &[u8]) -> u16 {
        let count = ((dns_request[6] as u16) << 8) | dns_request[7] as u16;
        return count;
    }

    fn parse_header_qdcount(dns_request: &[u8]) -> u16 {
        let qdcount = ((dns_request[4] as u16) << 8) | dns_request[5] as u16;
        return qdcount;
    }

    fn parse_header_id(dns_request: &[u8]) -> u16 {
        let id = ((dns_request[0] as u16) << 8) | dns_request[1] as u16;
        return id;
    }

    fn parse_header_qr(dns_request: &[u8]) -> Result<QR, ()> {
        let bit = DNSHeader::get_bit_at(dns_request[3], 0);
        if bit.is_err() {
            return Err(());
        }

        if bit.unwrap() == true {
            return Ok(QR::RESPONSE);
        } else {
            return Ok(QR::QUERY);
        }
    }

    fn parse_header_opcode(dns_request: &[u8]) -> Result<OPCode, ()> {
        let mask = 0b0111_1000;
        let result = mask & dns_request[2];
        let opcode_value = result >> 4;
        let opcode: OPCode = OPCode::from_u32(opcode_value as u32);
        return Ok(opcode);
    }

    fn parse_header_aa(dns_request: &[u8]) -> Result<bool, ()> {
        let aa = DNSHeader::get_bit_at(dns_request[3], 5);
        return aa;
    }

    fn parse_header_tc(dns_request: &[u8]) -> Result<bool, ()> {
        let tc = DNSHeader::get_bit_at(dns_request[3], 6);
        return tc;
    }

    fn parse_header_rd(dns_request: &[u8]) -> Result<bool, ()> {
        let rd = DNSHeader::get_bit_at(dns_request[3], 7);
        return rd;
    }

    fn parse_header_ra(dns_request: &[u8]) -> Result<bool, ()> {
        let ra = DNSHeader::get_bit_at(dns_request[3], 0);
        return ra;
    }

    fn parse_header_rc(dns_request: &[u8]) -> Result<ReturnCode, ()> {
        let rc = dns_request[3] & 0x0F;

        return Ok(ReturnCode::from_u8(rc));
    }

    fn get_bit_at(input: u8, n: u8) -> Result<bool, ()> {
        if n < 8 {
            Ok(input & (1 << n) != 0)
        } else {
            Err(())
        }
    }

    pub(crate) fn print(&self) {
        println!("========================");
        println!("Id: {:?}", self.id);
        println!("Query type: {:?}", self.qr);
        println!("Opcode: {:?}", self.opcode);
        println!("Authoritve answer: {:?}", self.aa);
        println!("Truncated: {:?}", self.truncated);
        println!("Recursion Desired: {:?}", self.recursion_desired);
        println!("Recursion Available: {:?}", self.recursion_available);
        println!("Response code: {:?}", self.return_code);
        println!("qd count: {:?}", self.qdcount);
        println!("an count: {:?}", self.ancount);
        println!("ns count: {:?}", self.nscount);
        println!("ar count: {:?}", self.arcount);
        println!("");
    }
}

#[allow(dead_code)]
pub struct DNSQuestion {
    qname: Vec<String>,
}

impl DNSQuestion {
    pub fn decode(dns_request: &[u8]) -> Result<DNSQuestion, ()> {
        return Ok(DNSQuestion {
            qname: DNSQuestion::parse_qname(dns_request).unwrap(),
        });
    }

    pub fn print(&self) {
        println!("DNS QUESTION");
        println!("QNAME: {:?}", self.qname)
    }

    fn parse_qname(dns_request: &[u8]) -> Result<Vec<String>, ()> {
        let result = DNSQuestion::parse_qname_parts(12, dns_request, &mut vec![]);
        return Ok(result);
    }

    fn parse_qname_parts(pos: usize, dns_request: &[u8], parts: &mut Vec<String>) -> Vec<String> {
        let read_forward: usize = dns_request[pos] as usize;

        if read_forward == 0 {
            return parts.to_vec();
        }

        let part = &dns_request[pos + 1..=pos + read_forward];
        // println!("Part: {:?}", result_spart.unwrap());
        parts.push(String::from_utf8(part.to_vec()).unwrap());

        let next_pos = pos + read_forward + 1;

        return DNSQuestion::parse_qname_parts(next_pos, dns_request, parts);
    }
}

#[allow(dead_code)]
fn print_packet(dns_request: &[u8]) {
    for (i, v) in dns_request.iter().enumerate() {
        if i % 2 == 1 {
            println!("|{:08b}|", i);
        } else {
            print!("{:2?} |{:08b}", i, v);
        }
    }
    println!("\nDNS length: {:?}", dns_request.len());
}

#[cfg(test)]
mod tests {
    use crate::rdns::{DNSHeader, DNSQuestion, OPCode, QR};

    use super::print_packet;

    // www.test.com
    const DNS_REQUEST: [u8; 53] = [
        137, 40, 1, 32, 0, 1, 0, 0, 0, 0, 0, 1, 3, 119, 119, 119, 4, 116, 101, 115, 116, 3, 99,
        111, 109, 0, 0, 1, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 12, 0, 10, 0, 8, 163, 23, 29, 76,
        18, 6, 57, 90,
    ];

    #[test]
    fn parse_part_test() {
        let result = DNSQuestion::parse_qname_parts(12, &DNS_REQUEST, &mut vec![]);

        println!("Parts: {:?}", result);
        assert_eq!("www".to_string(), result[0]);
        assert_eq!("test".to_string(), result[1]);
        assert_eq!("com".to_string(), result[2]);
    }

    #[test]
    fn print_packet_test() {
        print_packet(&DNS_REQUEST);
    }

    #[test]
    fn parse_id() {
        let id = DNSHeader::parse_header_id(&DNS_REQUEST);
        assert_eq!(id, 35112);
    }

    #[test]
    fn parse_qr() {
        let qr = DNSHeader::parse_header_qr(&DNS_REQUEST);

        assert_eq!(qr.unwrap(), QR::QUERY);
    }

    #[test]
    fn parse_opcode() {
        let opcode = DNSHeader::parse_header_opcode(&DNS_REQUEST);

        assert_eq!(opcode.unwrap(), OPCode::QUERY);
    }

    #[test]
    fn pase_aa() {
        let aa = DNSHeader::parse_header_aa(&DNS_REQUEST);

        assert_eq!(aa.unwrap(), true);
    }

    #[test]
    fn parse_tc() {
        let tc = DNSHeader::parse_header_tc(&DNS_REQUEST);
        assert_eq!(tc.unwrap(), false);
    }

    #[test]
    fn parse_rd() {
        let rd = DNSHeader::parse_header_rd(&DNS_REQUEST);
        assert_eq!(rd.unwrap(), false);
    }

    #[test]
    fn parse_ra() {
        let ra = DNSHeader::parse_header_ra(&DNS_REQUEST);
        assert_eq!(ra.unwrap(), false);
    }

    #[test]
    fn tst() {
        // let v: i8 = 122;
        // let x = (v & (0b1111 << 4) >> 4) as u8;

        // #let value = 0b00001010 as u8;
        // let value = 0b00001010 as u8;
        // let value = 0b00001010 as u8;
        let value = 0b00000001 as u8;
        let mask = 0b01111000 as u8;
        let target = value & mask;
        // let a = (v & 0b1111 << 4) as u8;
        println!("V: {:08b}", value);
        println!("M: {:08b}", mask);
        println!("T: {:08b}", target);

        let x = target >> 3;

        println!("X: {:08b} = {:?}", x, x);
    }
}
