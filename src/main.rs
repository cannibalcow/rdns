use std::net::UdpSocket;

use rdns::DNSHeader;
mod rdns;

// https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf

fn main() -> std::io::Result<()> {
    {
        let socket = UdpSocket::bind("127.0.0.1:5555")?;

        loop {
            let mut buf: [u8; 512] = [0; 512];

            let (amt, _) = socket.recv_from(&mut buf)?;

            let resp = &mut buf[..amt];


            let headerResult = DNSHeader::decode(resp);

            if headerResult.is_err() {
                println!("Error parsing :(");
                continue;
            }

            let header = headerResult.unwrap();

            header.print()

        }
        // println!("Str: {:?}", String::from_utf8_lossy(resp))
        // buf.reverse();
        // socket.send_to(buf, &src)?;
    }

    Ok(())
}

fn get_bit_at(input: u8, n: u8) -> Result<bool, ()> {
    if n < 8 {
        Ok(input & (1 << n) != 0)
    } else {
        Err(())
    }
}
