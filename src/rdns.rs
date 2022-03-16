use std::io::{Error, ErrorKind};

// https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
#[derive(PartialEq, Debug)]
enum QR {
    QUERY,
    RESPONSE,
}

#[derive(PartialEq, Debug)]
enum OPCode {
    QUERY,
    IQUERY,
    STATUS,
    NOTIFY,
    UPDATE,
    DSO,
}

#[derive(Debug)]
enum ReturnCode {
    NoError,
    FormatError,
    ServFail,
    NxDomain,
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
            id: parse_header_id(dns_request),
            qr: parse_header_qr(dns_request).unwrap(),
            opcode: parse_header_opcode(dns_request).unwrap(),
            aa: parse_header_aa(dns_request).unwrap(),
            truncated: parse_header_tc(dns_request).unwrap(),
            recursion_desired: parse_header_rd(dns_request).unwrap(),
            recursion_available: parse_header_ra(dns_request).unwrap(),
            return_code: parse_header_rc(dns_request).unwrap(),
            qdcount: parse_header_qdcount(dns_request),
            ancount: parse_header_ancount(dns_request),
            nscount: parse_header_nscount(dns_request),
            arcount: parse_header_arcount(dns_request),
        });
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

struct DNSQuestion {
    name: String,
}

fn parse_header_arcount(dns_request: &[u8]) -> u16 {
    let count = ((dns_request[10] as u16) << 8) | dns_request[11] as u16;
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
    println!("Paseid: {:?}", id);
    return id;
}

fn parse_header_qr(dns_request: &[u8]) -> Result<QR, ()> {
    let bit = get_bit_at(dns_request[3], 0);
    println!("Binary haed: {:b}", &dns_request[3]);
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
    // Wtf
    let opcode = (dns_request[3] & (0b1111 << 4) >> 4) as u8;
    match opcode {
        0 => Ok(OPCode::QUERY),
        1 => Ok(OPCode::IQUERY),
        2 => Ok(OPCode::STATUS),
        4 => Ok(OPCode::NOTIFY),
        5 => Ok(OPCode::UPDATE),
        6 => Ok(OPCode::DSO),
        x => Err(()),
    }
}

fn parse_header_aa(dns_request: &[u8]) -> Result<bool, ()> {
    let aa = get_bit_at(dns_request[3], 5);
    return aa;
}

fn parse_header_tc(dns_request: &[u8]) -> Result<bool, ()> {
    let tc = get_bit_at(dns_request[3], 6);
    return tc;
}

fn parse_header_rd(dns_request: &[u8]) -> Result<bool, ()> {
    let rd = get_bit_at(dns_request[3], 7);
    return rd;
}

fn parse_header_ra(dns_request: &[u8]) -> Result<bool, ()> {
    let ra = get_bit_at(dns_request[3], 0);
    return ra;
}

fn parse_header_rc(dns_request: &[u8]) -> Result<ReturnCode, ()> {
    let rc = dns_request[3] & 0x0F;
    match rc {
        0 => Ok(ReturnCode::NoError),
        1 => Ok(ReturnCode::FormatError),
        2 => Ok(ReturnCode::ServFail),
        3 => Ok(ReturnCode::NxDomain),
        x => Err(()),
    }
}

fn get_bit_at(input: u8, n: u8) -> Result<bool, ()> {
    if n < 8 {
        Ok(input & (1 << n) != 0)
    } else {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use crate::rdns::{
        parse_header_opcode, parse_header_qr, parse_header_ra, parse_header_rd, parse_header_tc,
        OPCode, QR,
    };

    use super::{parse_header_aa, parse_header_id};
    // www.test.com
    const DNS_REQUEST: [u8; 53] = [
        137, 40, 1, 32, 0, 1, 0, 0, 0, 0, 0, 1, 3, 119, 119, 119, 4, 116, 101, 115, 116, 3, 99,
        111, 109, 0, 0, 1, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 12, 0, 10, 0, 8, 163, 23, 29, 76,
        18, 6, 57, 90,
    ];

    #[test]
    fn parse_id() {
        let id = parse_header_id(&DNS_REQUEST);
        assert_eq!(id, 35112);
    }

    #[test]
    fn parse_qr() {
        let qr = parse_header_qr(&DNS_REQUEST);

        assert_eq!(qr.unwrap(), QR::QUERY);
    }

    #[test]
    fn parse_opcode() {
        let opcode = parse_header_opcode(&DNS_REQUEST);

        assert_eq!(opcode.unwrap(), OPCode::QUERY);
    }

    #[test]
    fn pase_aa() {
        let aa = parse_header_aa(&DNS_REQUEST);

        assert_eq!(aa.unwrap(), true);
    }

    #[test]
    fn parse_tc() {
        let tc = parse_header_tc(&DNS_REQUEST);
        assert_eq!(tc.unwrap(), false);
    }

    #[test]
    fn parse_rd() {
        let rd = parse_header_rd(&DNS_REQUEST);
        assert_eq!(rd.unwrap(), false);
    }

    #[test]
    fn parse_ra() {
        let ra = parse_header_ra(&DNS_REQUEST);
        assert_eq!(ra.unwrap(), false);
    }

    #[test]
    fn tst() {
        let v: i8 = 122;
        // let x = (v & (0b1111 << 4) >> 4) as u8;
        let x = v >> 4;
        let y = v & 0x0F;
        println!("kuk {:08b}", v);
        println!("kuk2 {:08b} {:?}", x, x);
        println!("kuk3 {:08b} {:?}", y, y);
    }
}
