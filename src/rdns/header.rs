#[derive(PartialEq, Debug)]
pub enum QR {
    QUERY,
    RESPONSE,
}

#[derive(PartialEq, Debug)]
pub enum OPCode {
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
pub enum ReturnCode {
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

    pub fn parse_header_arcount(dns_request: &[u8]) -> u16 {
        let count: u16 = ((dns_request[10] as u16) << 8) | dns_request[11] as u16;
        return count;
    }

    pub fn parse_header_nscount(dns_request: &[u8]) -> u16 {
        let count = ((dns_request[8] as u16) << 8) | dns_request[9] as u16;
        return count;
    }

    pub fn parse_header_ancount(dns_request: &[u8]) -> u16 {
        let count = ((dns_request[6] as u16) << 8) | dns_request[7] as u16;
        return count;
    }

    pub fn parse_header_qdcount(dns_request: &[u8]) -> u16 {
        let qdcount = ((dns_request[4] as u16) << 8) | dns_request[5] as u16;
        return qdcount;
    }

    pub fn parse_header_id(dns_request: &[u8]) -> u16 {
        let id = ((dns_request[0] as u16) << 8) | dns_request[1] as u16;
        return id;
    }

    pub fn parse_header_qr(dns_request: &[u8]) -> Result<QR, ()> {
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

    pub fn parse_header_opcode(dns_request: &[u8]) -> Result<OPCode, ()> {
        let mask = 0b0111_1000;
        let result = mask & dns_request[2];
        let opcode_value = result >> 4;
        let opcode: OPCode = OPCode::from_u32(opcode_value as u32);
        return Ok(opcode);
    }

    pub fn parse_header_aa(dns_request: &[u8]) -> Result<bool, ()> {
        return DNSHeader::get_bit_at(dns_request[3], 5);
    }

    pub fn parse_header_tc(dns_request: &[u8]) -> Result<bool, ()> {
        let tc = DNSHeader::get_bit_at(dns_request[3], 6);
        return tc;
    }

    pub fn parse_header_rd(dns_request: &[u8]) -> Result<bool, ()> {
        let rd = DNSHeader::get_bit_at(dns_request[3], 7);
        return rd;
    }

    pub fn parse_header_ra(dns_request: &[u8]) -> Result<bool, ()> {
        let ra = DNSHeader::get_bit_at(dns_request[3], 0);
        return ra;
    }

    pub fn parse_header_rc(dns_request: &[u8]) -> Result<ReturnCode, ()> {
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

    pub fn print(&self) {
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

    #[allow(dead_code)]
    pub fn print_packet(dns_request: &[u8]) {
        for (i, v) in dns_request.iter().enumerate() {
            if i % 2 == 1 {
                println!("|{:08b}|", i);
            } else {
                print!("{:2?} [{:3?}] |{:08b} ", i, v, v);
            }
        }
        println!("\nDNS length: {:?}", dns_request.len());
    }
}
