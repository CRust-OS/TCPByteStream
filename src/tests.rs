use super::{TcpSegment,IPv4PseudoHeader,TcpCTRL, TcpOpts, SYN, ACK, FIN, RST}; 
use util::{U8ToU16, U8ToU32, U32ToU8, U16ToU8, U32ToU16};

extern crate pcap;
extern crate test;

#[test]
fn test_syn(){
    let tcp_data : Vec<u8> = vec![151, 116, 0, 80, 4, 12, 185, 160, 0, 0, 0, 0, 160, 2, 96, 224, 81, 40, 0, 0, 2, 4, 4, 216, 4, 2, 8, 10, 1, 49, 10, 120, 0, 0, 0, 0, 1, 3, 3, 7];

    let header = IPv4PseudoHeader {
        source_addr : [192, 168, 2, 29].iter().to_u32().unwrap(),
        dest_addr   : [184, 150, 186, 93].iter().to_u32().unwrap(),
        protocol     : 6,
        tcp_len     : tcp_data.len() as u16
    };

    let parse_res =  TcpSegment::parse(&tcp_data);
    //assert!(parse_res.is_ok());
    //let segment = parse_res.unwrap();
    let segment = parse_res;
    assert_eq!(segment.src_port, 38772);
    assert_eq!(segment.dest_port, 80);
    assert_eq!(segment.window, 24800);
    assert_eq!(TcpCTRL::from_bits(segment.ctrl_flags).unwrap(), SYN);
    assert_eq!(segment.checksum, 0x5128);
    assert_eq!(segment.seq_num, 0x040cb9a0);
    assert_eq!(segment.ack_num, 0x00000000);
    assert_eq!(segment.data_off, 10);
    assert_eq!(segment.urg_ptr, 0);

    let opts_expected = vec![
        TcpOpts::MSS(1240),
        TcpOpts::SAckPermitted,
        TcpOpts::TimeStamp { 
            time: 19991160,
            echo: 0
        },
        TcpOpts::NOP,
        TcpOpts::WindowScale(7)
    ];

    assert_eq!(segment.options.len(), opts_expected.len());

    for (ref a, ref b) in segment.options.iter().zip(opts_expected.iter()) {
        assert_eq!(a, b);
    }

    assert_eq!(segment.calculate_checksum(header), segment.checksum);
    assert_eq!(segment.as_bytestream(), tcp_data);
}

#[test]
fn test_sync_ack(){
    let tcp_data : Vec<u8> = vec![0x00, 0x50, 0x96, 0xb6, 0xa5, 0xca, 
        0x60, 0x22, 0xf2, 0xf4, 0x03, 0x1d, 0xa0, 0x12,
        0x71, 0x20, 0xe9, 0x7a, 0x00, 0x00, 0x02, 0x04,
        0x05, 0x6a, 0x04, 0x02, 0x08, 0x0a, 0x82, 0xbc,
        0x3d, 0xec, 0x01, 0x3d, 0x3d, 0xe9, 0x01, 0x03,
        0x03, 0x07];

    let header = IPv4PseudoHeader {
        source_addr:    [206, 167, 212, 90].iter().to_u32().unwrap(),
        dest_addr:      [142,157,41,43].iter().to_u32().unwrap(),
        protocol:       6,
        tcp_len:        tcp_data.len() as u16
    };

    let segment = TcpSegment::parse(&tcp_data);
    assert_eq!(segment.src_port, 80);
    assert_eq!(segment.dest_port, 38582);
    assert_eq!(segment.window, 28960);
    assert_eq!(TcpCTRL::from_bits(segment.ctrl_flags).unwrap(), SYN | ACK);
    assert_eq!(segment.checksum, 0xe97a);
    assert_eq!(segment.seq_num, 0xa5ca6022);
    assert_eq!(segment.ack_num, 0xf2f4031d);
    assert_eq!(segment.data_off, 10);       // 40 byes -> 10 words
    assert_eq!(segment.urg_ptr, 0);

    let opts_expected = vec![
        TcpOpts::MSS(1386),
        TcpOpts::SAckPermitted,
        TcpOpts::TimeStamp{ time: 2193374700, echo: 20790761},
        TcpOpts::NOP,
        TcpOpts::WindowScale(7)
    ];

    assert_eq!(segment.options.len(), opts_expected.len());
    for (ref a, ref b) in segment.options.iter().zip(opts_expected.iter()) {
        assert_eq!(a, b);
    }

    assert_eq!(segment.calculate_checksum(header), segment.checksum);
    assert_eq!(segment.as_bytestream(), tcp_data);
}

#[test]
fn test_fin_ack(){
    let tcp_data: Vec<u8> =vec![0xa2, 0x30, 0x00, 0x50, 0x30, 0xf2,
                                0xad, 0x35, 0xce, 0x1b, 0x58, 0x05, 0x80, 0x11,
                                0x01, 0xff, 0x8b, 0xbc, 0x00, 0x00, 0x01, 0x01,
                                0x08, 0x0a, 0x01, 0x3d, 0x39, 0x49, 0x82, 0xe8,
                                0x29, 0xdf];

    let header = IPv4PseudoHeader {
        source_addr: [142, 157, 41, 43].iter().to_u32().unwrap(),
        dest_addr: [206, 167, 212, 121].iter().to_u32().unwrap(),
        protocol: 6,
        tcp_len: tcp_data.len() as u16
    };

    let segment = TcpSegment::parse(&tcp_data);
    assert_eq!(segment.src_port, 41520);
    assert_eq!(segment.dest_port, 80);
    assert_eq!(segment.window, 511);
    assert_eq!(TcpCTRL::from_bits(segment.ctrl_flags).unwrap(), ACK | FIN);
    assert_eq!(segment.checksum, 0x8bbc);
    assert_eq!(segment.seq_num, 0x30_F2_AD_35);
    assert_eq!(segment.ack_num, 0xCE_1B_58_05);
    assert_eq!(segment.data_off, 8);
    assert_eq!(segment.urg_ptr, 0);

    let opts_expected = vec![
        TcpOpts::NOP,
        TcpOpts::NOP,
        TcpOpts::TimeStamp{time: 20789577, echo: 2196253151}
    ];

    assert_eq!(segment.options.len(), opts_expected.len());
    for (ref a, ref b) in opts_expected.iter().zip(segment.options.iter()) {
        assert_eq!(a, b);
    }

    assert_eq!(segment.calculate_checksum(header), segment.checksum);
    assert_eq!(segment.as_bytestream(), tcp_data);
}

#[test]
fn test_ack_rst(){
    let tcp_data : Vec<u8> = vec![0x97, 0x00, 0x01, 0xbb, 0xcc, 0x0f,
                                  0x70, 0xdb, 0x73, 0xa3, 0x00, 0xe0, 0x80, 0x14,
                                  0x01, 0x29, 0xb1, 0x6c, 0x00, 0x00, 0x01, 0x01,
                                  0x08, 0x0a, 0x01, 0xb5, 0xf3, 0x30, 0xb1, 0xd7,
                                  0xa2, 0xdc];

    let header = IPv4PseudoHeader {
        source_addr:    [192, 168, 0, 109].iter().to_u32().unwrap(),
        dest_addr:      [96, 22, 15, 52].iter().to_u32().unwrap(),
        protocol:       6,
        tcp_len:        tcp_data.len() as u16
    };

    let segment = TcpSegment::parse(&tcp_data);
    assert_eq!(segment.src_port, 38656);
    assert_eq!(segment.dest_port, 443);
    assert_eq!(segment.window, 297);
    assert_eq!(TcpCTRL::from_bits(segment.ctrl_flags).unwrap(), RST | ACK);
    assert_eq!(segment.checksum, 0xb16c);
    assert_eq!(segment.seq_num, 0xCC_0F_70_DB);
    assert_eq!(segment.ack_num, 0x73_A3_00_E0);
    assert_eq!(segment.data_off, 8);
    assert_eq!(segment.urg_ptr, 0);

    let opts_expected = vec![
        TcpOpts::NOP,
        TcpOpts::NOP,
        TcpOpts::TimeStamp{time: 28701488, echo: 2983699164}
    ];

    assert_eq!(segment.options.len(), opts_expected.len());
    for (ref a, ref b) in opts_expected.iter().zip(segment.options.iter()) {
        assert_eq!(a, b);
    }

    assert_eq!(segment.calculate_checksum(header), segment.checksum);
    assert_eq!(segment.as_bytestream(), tcp_data);
}

#[bench]
fn bench_pcap(b: &mut Bencher) {
    let mut cap = pcap::Capture::from_file("100_packets.pcap").unwrap();
    b.iter(|| TODO);
}
