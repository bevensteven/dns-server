use std::net::UdpSocket;
use std::io::Result;

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
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf).unwrap();

    DnsPacket::from_buffer(&mut res_buffer)
}

fn recursive_lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket> {
    // assume we always start with *a.root-servers.net*
    let mut ns = "198.41.0.4".to_string();

    loop {
        println!("Attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

        // send query to active server
        let ns_copy = ns.clone();

        let server = (ns_copy.as_str(), 53);
        let response = lookup(qname, qtype.clone(), server)?;

        // if there are entries in the answer section, and no errors, we're done!
        if !response.answers.is_empty() && 
            response.header.rescode == ResultCode::NOERROR {

            return Ok(response.clone());
        }

        if response.header.rescode == ResultCode::NXDOMAIN {
            return Ok(response.clone());
        }

        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns.clone();
            continue;
        }

        let new_ns_name = match response.get_unresolved_ns(qname) {
            Some(x) => x,
            None => return Ok(response.clone())
        };

        let recursive_response = recursive_lookup(&new_ns_name, QueryType::A)?;
        
        // pick a random IP from the result, and restart the loop
        // if no such record is available, we return the last result we got
        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns.clone();
        } else {
            return Ok(response.clone())
        }
    }
}

pub fn main() {
    // Forward queries to Google's public DNS
    let server = ("8.8.8.8", 53);

    // Bind a UDP socket on port 2053
    let socket = UdpSocket::bind(("0.0.0.0", 2053)).unwrap();

    // Queries are handled sequentially.
    loop {

        // With a socket ready we can read a packet. This will block until
        // one is received.
        let mut req_buffer = BytePacketBuffer::new();
        let (_, src) = match socket.recv_from(&mut req_buffer.buf) {
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
        };

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
            if let Ok(result) = recursive_lookup(&question.name, question.qtype) {
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
                Ok(x) => x,
                Err(e) => {
                    println!("Failed to retrieve repsonse buffer: {:#?}", e);
                    continue;
                }
            };

            match socket.send_to(&data, src) {
                Ok(_) => {},
                Err(e) => {
                    println!("Failed to send response buffer: {:#?}", e);
                }
            }
        }
    }
}