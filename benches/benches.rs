#![feature(test)]
extern crate test;
extern crate tcp_byte_stream;
extern crate pcap;

use tcp_byte_stream::{TcpSegment,IPv4PseudoHeader,TcpCTRL, TcpOpts, SYN, ACK, FIN, RST}; 
use tcp_byte_stream::util::{U8ToU16, U8ToU32, U32ToU8, U16ToU8, U32ToU16};
use test::Bencher;

#[bench]
fn bench_pcap(b: &mut Bencher) {
    let mut cap = pcap::Capture::from_file("tests/100_packets.pcap").unwrap();
    b.iter(|| {}); // TODO
}
