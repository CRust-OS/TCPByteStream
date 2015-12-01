#![feature(test)]
extern crate test;
extern crate tcp_byte_stream;
extern crate pcap;

use tcp_byte_stream::TcpSegment; 
use test::Bencher;

#[bench]
fn bench_pcap(b: &mut Bencher) {
    const IPV4_START : u8 = 0x0E;
    const IPV4_PACKET_TYPE : usize = 0x17;
    const TCP_PACKET : u8 = 6;
    
        
    b.iter(|| {
       	let mut cap = pcap::Capture::from_file("tests/100_packets.pcap").unwrap();
        while let Ok(packet) = cap.next() {
            // skip any non-tcp packets
            if packet[IPV4_PACKET_TYPE] as u8 != TCP_PACKET {
                continue;
            }
            // get start of TCP header
            let tcp_len = 4 * (packet[0x0E] & 0x0F);
            let start = IPV4_START + tcp_len; 
            TcpSegment::parse(&packet[start as usize ..]);
        }
   }); 
}

