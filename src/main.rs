use pretty_hex::*;
use rdns::{
    self,
    rdns::{
        answer::{self, Answer, AnswerType},
        header::DNSHeader,
        question::DNSQuestion,
        types::QClass,
    },
};
use std::net::UdpSocket;

// https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf
// https://www.rfc-editor.org/rfc/rfc6895.html

fn main() -> std::io::Result<()> {
    {
        let socket = UdpSocket::bind("127.0.0.1:5353")?;

        let running = true;

        let cfg = HexConfig {
            title: false,
            width: 8,
            group: 0,
            ..HexConfig::default()
        };

        while running {
            let mut buf: [u8; 512] = [0; 512];

            let (amt, src) = socket.recv_from(&mut buf)?;

            let resp = &mut buf[..amt];

            println!("{:?}", resp.hex_conf(cfg));
            DNSHeader::print_packet(resp);
            let header_result = DNSHeader::decode(resp);
            let question_result = DNSQuestion::decode(resp);

            if header_result.is_err() {
                println!("Error parsing header :(");
                continue;
            }

            if question_result.is_err() {
                println!("Error parsing message :(");
                continue;
            }

            let header = header_result.unwrap();
            let question = question_result.unwrap();

            header.print();
            question.print();
            let rdata: Vec<u8> = vec![127, 0, 0, 1];
            let answer = Answer::new(question.qname.raw, AnswerType::A, QClass::IN, 60, rdata);
            let packet = answer.to_udp_package();

            // TODO:Fixa header i answer
            socket.send_to(&packet, &src).expect("Could not send");
        }
        // println!("Str: {:?}", String::from_utf8_lossy(resp))
        // buf.reverse();
        // socket.send_to(buf, &src)?;
        Ok(())
    }
}
