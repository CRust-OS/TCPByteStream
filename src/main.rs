extern crate tcp_byte_stream;
extern crate pcap;
use std::env;

use tcp_byte_stream::TcpSegment; 

fn main() {
    const IPV4_START : u8 = 0x0E;
    const IPV4_PACKET_TYPE : usize = 0x17;
    const TCP_PACKET : u8 = 6;

    let file = env::args().nth(1).unwrap_or("tests/100_packets.pcap".to_string());

    let mut cap = pcap::Capture::from_file(file).unwrap();
    let mut data = Vec::new();
    while let Ok(packet) = cap.next() {
        if packet[IPV4_PACKET_TYPE] as u8 == TCP_PACKET {
            let tcp_len = 4 * (packet[0x0E] & 0x0F);
            let start = IPV4_START + tcp_len; 
            data.push(packet[start as usize ..].into_iter().cloned().collect::<Vec<u8>>());
        }
    }

    for _ in 0..1000 {
        for tcp in data.iter() {
            TcpSegment::parse(&tcp);
        }
    }
}

