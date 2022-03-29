use pretty_hex::*;
use rdns::{
    self,
    rdns::{header::DNSHeader, question::DNSQuestion},
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

            let (amt, _) = socket.recv_from(&mut buf)?;

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
        }
        // println!("Str: {:?}", String::from_utf8_lossy(resp))
        // buf.reverse();
        // socket.send_to(buf, &src)?;
        Ok(())
    }
}
