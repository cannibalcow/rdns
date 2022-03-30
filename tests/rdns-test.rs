#[cfg(test)]
mod tests {
    use rdns::rdns::{
        answer::{Answer, AnswerType},
        header::{DNSHeader, OPCode, QR},
        question::DNSQuestion,
        types::{QClass, QueryType},
    };

    // www.test.com
    const DNS_REQUEST: [u8; 53] = [
        137, 40, 1, 32, 0, 1, 0, 0, 0, 0, 0, 1, 3, 119, 119, 119, 4, 116, 101, 115, 116, 3, 99,
        111, 109, 0, 0, 1, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 12, 0, 10, 0, 8, 163, 23, 29, 76,
        18, 6, 57, 90,
    ];

    const QTYPE_POS: usize = 26;

    #[test]
    fn parse_part_test() {
        let result = DNSQuestion::parse_qname_parts(12, &DNS_REQUEST, &mut vec![]);

        let parts = result.0;
        let pos = result.1;
        assert_eq!("www".to_string(), parts[0]);
        assert_eq!("test".to_string(), parts[1]);
        assert_eq!("com".to_string(), parts[2]);
        assert_eq!(QTYPE_POS, pos);
    }

    #[test]
    fn parse_qclass() {
        let class = DNSQuestion::parse_qclass(&DNS_REQUEST, &QTYPE_POS);
        assert_eq!(class.unwrap(), QClass::IN)
    }

    #[test]
    fn parse_qtype_test() {
        let qtype = DNSQuestion::parse_qtype(&DNS_REQUEST, &QTYPE_POS);
        assert_eq!(qtype.unwrap(), QueryType::A);
    }

    #[allow(dead_code)]
    fn print_packet_test() {
        DNSHeader::print_packet(&DNS_REQUEST);
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
    fn answer_test() {
        let qname = DNSQuestion::parse_qname(&DNS_REQUEST).unwrap();
        let rdata: Vec<u8> = vec![127, 0, 0, 1];
        let anwser = Answer::new(qname.raw, AnswerType::A, QClass::IN, 5, rdata);
        println!("answer: {:?}", anwser);
        let package = anwser.to_udp_package();

        println!("packet: {:?}", package);
    }
}
