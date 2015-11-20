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
