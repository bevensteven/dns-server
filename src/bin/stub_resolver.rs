use std::net::UdpSocket;

// TODO: figure out import problem
use dns::dns_packet::DnsPacket;
use dns::dns_question::DnsQuestion;
use dns::query_type::QueryType;

fn main() {
    // Perform an A query for google.com
    let qname = "google.com";
    let qtype = QueryType::A;

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

    let res_packet = DnsPacket::from_buffer(res_buffer).unwrap();

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
