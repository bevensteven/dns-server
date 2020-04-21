use std::net::UdpSocket;

use crate::dns::query_type::QueryType;
use crate::dns::dns_packet::DnsPacket;
use crate::dns::dns_question::DnsQuestion;
use crate::dns::byte_packet_buffer::BytePacketBuffer;
use crate::dns::result_code::ResultCode;

fn lookup(qname: &str, qtype: QueryType, server: (&str, u16)) -> Result<DnsPacket> {
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut packet = DnsPacket::new();

    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet.questions.push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer).unwrap();
    socket.send_to(req_buffer.buf[0..req_buffer.pos], server)?;

    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf).unwrap();

    DnsPacket::from_buffer(&mut res_buffer)
}

fn main() {
    // Forward queries to Google's public DNS
    let server = ("8.8.8.8", 53);

    // Bind a UDP socket on port 2053
    let socket = UdpSocket::bind(("0.0.0.0", 2053)).unwrap();

    // Queries are handled sequentially.
    loop {

        // With a socket ready we can read a packet. This will block until
        // one is received.
        let mut req_buffer = BytePacketBuffer::new();
        let (_, src) = match socket.recv_from(req_buffer.buf) {
            Ok(x) => x,
            Err(e) => {
                println!("Failed to read from UDP socket: {:#?}", e); continue; }
        };

        // Use match to safely unwrap the Result. If everything is as expected, the
        // raw bytes are returned, and if not it'll abort by restarting the loop
        // and waiting for the next request.

        // Next parse the raw bytes into a DnsPacket.
        let request = match DnsPacket::from_buffer(&mut req_buffer) {
            Ok(x) => x,
            Err(e) => {
                println!("Failed to parse UDP query packet: {:#?}", e);
                continue;
            }
        }

        // Create and init the response packet
        let mut packet = DnsPacket::new();
        packet.header.id = request.header.id;
        packet.header.recursion_desired = true;
        packet.header.recursion_available = true;
        packet.header.response = true;

        // Make sure a question is actually present.
        // If not, we return `FORMERR` to indicate that the sender made something wrong.
        if request.questions.is_empty() {
            packet.header.rescode = ResultCode::FORMERR;
        } else {
            let question = &request.questions[0];
            println!("Received query: {:#?}", question);

            // Query can be forwarded to the target server.
            // It's possible that the query will fail, in which case we can use the
            // SERVFAIL response code.
            if let Ok(result) = lookup(&question.name, question.qtype, server) {
                packet.questions.push(question.clone());
                packet.header.rescode = result.header.rescode;

                for rec in result.answers {
                    println!("Answer: {:#?}", rec);
                    packet.answers.push(rec);
                }
                for rec in result.authorities {
                    println!("Authority: {:#?}", rec);
                    packet.authorities.push(rec);
                }
                for rec in result.resources {
                    println!("Resource: {:#?}", rec);
                    packet.resources.push(rec);
                }
            } else {
                packet.header.rescode = ResultCode::SERVFAIL;
            }

            // Encode response and send it.
            let mut res_buffer = BytePacketBuffer::new();
            match packet.write(&mut res_buffer) {
                Ok(_) => {},
                Err(e) => {
                    println!("Failed to encode UDP response packet: {:#?}", e);
                }
            }

            let len = res_buffer.pos();
            let data = match res_buffer.get_range(0, len) {
                Ok(_) => {},
                Err(e) => {
                    println!("Failed to retrieve repsonse buffer: {:#?}", e);
                }
            }

            match socket.send_to(data, src) {
                Ok(_) => {},
                Err(e) => {
                    println!("Failed to send response buffer: {:#?}", e);
                }
            }
        }
    }
}