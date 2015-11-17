use super::{TcpSegment,IPv4PseudoHeader,TcpCTRL, TcpOpts, SYN, ACK}; 
use util::{U8ToU16, U8ToU32, U32ToU8, U16ToU8, U32ToU16};

#[test]
fn test_syn(){
    let tcp_data : Vec<u8> = vec![151, 116, 0, 80, 4, 12, 185, 160, 0, 0, 0, 0, 160, 2, 96, 224, 81, 40, 0, 0, 2, 4, 4, 216, 4, 2, 8, 10, 1, 49, 10, 120, 0, 0, 0, 0, 1, 3, 3, 7];

    let header = IPv4PseudoHeader {
        source_addr : [192, 168, 2, 29].iter().to_u32().unwrap(),
        dest_addr   : [184, 150, 186, 93].iter().to_u32().unwrap(),
        protocol     : 6,
        tcp_len     : tcp_data.len() as u16
    };

    let parse_res =  TcpSegment::parse(tcp_data);
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
}

#[test]
fn test_syncack(){
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

    let segment = TcpSegment::parse(tcp_data);
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
}
