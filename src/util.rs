use super::{TcpSegment, TcpOpts};

pub trait U8ToU32 {
    fn to_u32(&mut self) -> Option<u32>;
}

impl<'a, T> U8ToU32 for T where T : Iterator<Item=&'a u8>{
    fn to_u32(&mut self) -> Option<u32> {
        let (count, _) = self.size_hint();
        if count != 4 {
            None
        } else {
            let a = self.next();
            let b = self.next();
            let c = self.next();
            let d = self.next();
            match (a, b, c, d) {
                (Some(&w), Some(&x), Some(&y), Some(&z)) => {
                    Some(
                        ((w as u32) << 24) |
                        ((x as u32) << 16) |
                        ((y as u32) << 8)  |
                        ((z as u32))
                        )
                },
                _ => None
            }
        }
    }
}

pub trait U8ToU16 {
    fn to_u16(&mut self) -> Option<u16>;
}

impl<'a, T> U8ToU16 for T where T : Iterator<Item=&'a u8> {
    fn to_u16(&mut self) -> Option<u16> {
        let (count, _) = self.size_hint();
        if count != 2 {
            None
        } else {
            let a = self.next();
            let b = self.next();
            match (a, b) {
                (Some(&x), Some(&y)) => {
                    Some(((x as u16) << 8) | (y as u16))
                },
                _ => None
            }
        }
    }
}

pub trait U16ToU8 {
    fn to_u8(&self) -> [u8; 2];
}

impl U16ToU8 for u16 {
    fn to_u8(&self) -> [u8; 2] {
        [
            ((self & 0xFF00) >> 8) as u8,
            ((self & 0x00FF))      as u8
        ]
    }
}

pub trait U32ToU8 {
    fn to_u8(&self) -> [u8; 4];
}

impl U32ToU8 for u32 {
    fn to_u8(&self) -> [u8; 4]{
        [
            ((self & 0xFF000000) >> 24) as u8,
            ((self & 0x00FF0000) >> 16) as u8,
            ((self & 0x0000FF00) >> 8)  as u8,
            ((self & 0x000000FF))       as u8
        ]
    }
}

pub trait U32ToU16{
    fn to_u16(&self) -> (u16, u16);
}

impl U32ToU16 for u32 {
    fn to_u16(&self) -> (u16, u16){
        let a = ((self & 0xFFFF0000) >> 16) as u16;
        let b = (self & 0x0000FFFF) as u16;
        (a, b)
    }
}

pub fn parse_pcap(data : &[u8]) -> TcpSegment {
    TcpSegment {
        src_port        : [data[0x22], data[0x23]].iter().to_u16().unwrap(),
        dest_port       : [data[0x24], data[0x25]].iter().to_u16().unwrap(),
        seq_num         : [data[0x26],data[0x27],data[0x28],data[0x29]].iter()
                          .to_u32().unwrap(),
        ack_num         : [data[0x2A],data[0x2B],data[0x2C],data[0x2D]].iter()
                          .to_u32().unwrap(),
        data_off        : ((data[0x2E] & 0xF0)  >> 4) as u8,
        ctrl_flags      : [(data[0x2E] & 0x0F), data[0x2F]].iter().to_u16().unwrap(),
        window          : [data[0x30], data[0x31]].iter().to_u16().unwrap(),
        checksum        : [data[0x32], data[0x33]].iter().to_u16().unwrap(),
        urg_ptr         : [data[0x34], data[0x35]].iter().to_u16().unwrap(),
        options         : vec!(TcpOpts::END),
        data            : vec!(0, 1)
    }
}
