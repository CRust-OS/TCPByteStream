extern crate tcp_byte_stream;

mod test_u8_to_u32 {
    use tcp_byte_stream::util::U8ToU32;

    #[test]
    fn test_invalid_length_short(){
        let x : [u8; 3] = [1,2,3];
        assert_eq!(x.iter().to_u32(), None);
    }

    #[test]
    fn test_invalid_length_long(){
        let x : [u8; 5] = [1,2,3,4,5];
        assert_eq!(x.iter().to_u32(), None);
    }

    #[test]
    fn test_works() {
        let x : [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
        assert_eq!(x.iter().to_u32(), Some(0xdeadbeef));
    }
}

mod test_u8_to_u16 {
    use tcp_byte_stream::util::U8ToU16;

    #[test]
    fn test_invalid_length_short() {
        let x : [u8; 1] = [1];
        assert_eq!(x.iter().to_u16(), None);
    }

    #[test]
    fn test_invalid_length_long() {
        let x : [u8; 3] = [1,2,3];
        assert_eq!(x.iter().to_u16(), None);
    }

    #[test]
    fn test_works() {
        let x : [u8; 2] = [0xB0, 0x0b];
        assert_eq!(x.iter().to_u16(), Some(0xB00B));
    }
}

mod test_u16_to_u8 {
    use tcp_byte_stream::util::U16ToU8;

    #[test]
    fn test_it_works(){
        let x : u16 = 0xB00B;
        assert_eq!(x.to_u8(), [0xB0, 0x0B]);
    }
} 

mod test_u32_to_u8 {
    use tcp_byte_stream::util::U32ToU8;

    #[test]
    fn test_it_works(){
        let x : u32 = 0xDEADBEEF;
        assert_eq!(x.to_u8(), [0xDE, 0xAD, 0xBE, 0xEF]);
    }
}

mod test_pcap_parse {
    use tcp_byte_stream::util::parse_pcap;

    #[test]
    fn test_parse_packet_1() {
        let data = [0x00, 0x0a, 0xbc, 0x03, 0x6d, 0x80, 0x00, 0x50, 0xa2,
                    0xdf, 0xe8, 0x1c, 0x08, 0x00, 0x45, 0x00, 0x03, 0x29, 
                    0x42, 0x7d, 0x40, 0x00, 0x6d, 0x06, 0x00, 0x00, 0x33,
                    0x78, 0x15, 0x2a, 0x61, 0x59, 0x52, 0x56, 0x06, 0xe0, 
                    0x00, 0x19, 0x79, 0x43, 0xd3, 0xbb, 0x88, 0xa4, 0x36, 
                    0xd2, 0x50, 0x18, 0xfe, 0x0a, 0xc3, 0xfc, 0x00, 0x00];
        
        let segment = parse_pcap(&data);
        
        assert_eq!(segment.src_port, 1760);
        assert_eq!(segment.dest_port, 25);
        assert_eq!(segment.seq_num, 2034488251);
        assert_eq!(segment.ack_num, 2292463314);
        assert_eq!(segment.data_off, 5); 
        // TODO: Ctrl flags
        assert_eq!(segment.window, 65034);
        assert_eq!(segment.checksum, 0xc3fc);
        assert_eq!(segment.urg_ptr, 0);
        // TODO: options
    }
}

