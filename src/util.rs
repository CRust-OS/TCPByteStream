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

