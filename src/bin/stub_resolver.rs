use std::net::UdpSocket;

/// Since this is an another binary, it is not part of the dns-server's crate
/// module structure. Given this, we need to declare that we are using dns-server
/// as a crate so that we can depend on the crate's code.
extern crate dns_server;
use dns_server::dns::byte_packet_buffer::BytePacketBuffer;
use dns_server::dns::dns_packet::DnsPacket;
use dns_server::dns::dns_question::DnsQuestion;
use dns_server::dns::query_type::QueryType;

fn main() {
    // Perform an A query for google.com
    let qname = "yahoo.com";
    let qtype = QueryType::MX;

    // Use google's public DNS server
    let server = ("8.8.8.8", 53);

    // open a socket to communicate with the DNS server
    let socket = UdpSocket::bind(("0.0.0.0", 43210)).unwrap();

    // Build query packet.
    let mut packet = DnsPacket::new();
    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    // write packet to a buffer
    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer).unwrap();

    // send it via our socket
    socket
        .send_to(&req_buffer.buf[0..req_buffer.pos], server)
        .unwrap();

    // Create a packet to receive the response
    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf).unwrap();

    let res_packet = DnsPacket::from_buffer(&mut res_buffer).unwrap();

    println!("{:#?}", res_packet.header);
    for q in res_packet.questions {
        println!("{:#?}", q);
    }
    for rec in res_packet.answers {
        println!("{:#?}", rec);
    }
    for rec in res_packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in res_packet.resources {
        println!("{:#?}", rec);
    }
}
