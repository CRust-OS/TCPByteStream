#[macro_use]
extern crate bitflags;

trait U8ToU32 {
    fn to_u32(&self) -> Option<u32>;
}

impl<T> U8ToU32 for T where T : AsRef<[u8]> {
    fn to_u32(&self) -> Option<u32> {
        let data : &[u8] = self.as_ref();
        if data.len() != 4 {
            None
        } else {
            Some(
                  ((data[0] as u32) << 24) 
                | ((data[1] as u32) << 16)
                | ((data[2] as u32) << 8)
                |  data[3] as u32
            )
        }
    }
}

impl U8ToU32 for [u8] {
    fn to_u32(&self) -> Option<u32> {
        (self).to_u32()
    }
}

trait U8ToU16 {
    fn to_u16(&self) -> Option<u16>;
}

impl<T> U8ToU16 for T where T : AsRef<[u8]> {
    fn to_u16(&self) -> Option<u16> {
        let data : &[u8] = self.as_ref();
        if data.len() != 2 {
            None
        } else {
            Some(((data[0] as u16) << 8) | (data[1] as u16))
        }
    }
}

impl U8ToU16 for [u8] {
    fn to_u16(&self) -> Option<u16> {
        (self).to_u16()
    }
}

trait U16ToU8 {
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

trait U32ToU8 {
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

/// TCP Control flags, Only 9 bits needed
bitflags! {
    flags TcpCTRL : u16 {
        const NS    = 0b100000000,
        const CWR   = 0b010000000,
        const ECE   = 0b001000000,
        const URG   = 0b000100000,
        const ACK   = 0b000010000,
        const PSH   = 0b000001000,
        const RST   = 0b000000100,
        const SYN   = 0b000000010,
        const FIN   = 0b000000001
    }
}

bitflags! {
    flags TcpOptFlags : u8 {
        const END       = 0b00000000,
        const NOP       = 0b00000001,
        const MSS       = 0b00000010,
        const SCALE     = 0b00000011,
        const SACKPERM  = 0b00000100,
        const SACK      = 0b00000101,
        const TIME      = 0b00001000
    }
}

enum TcpOpts {
    MSS(u16),           // Maximum segment size, length should be 4 (SYN only)
    WindowScale(u8),    // Window scale, length should be 3 (SYN only)
    SAckPermitted,      // Selective ACK permitted (SYN only)
    SAck(Vec<(u32, u32)>),     // Selective ACK (variable length, 1-4 bocks of 32 bit begin/end ptrs)
    TimeStamp { time: u32, echo: u32 }      // Timestamp and echo of prev timestamp, length should be 10
}

struct TcpSegment {
    src_port    : u16,          // source port  
    dest_port   : u16,          // dest port
    seq_num     : u32,          // sequence number
    ack_num     : u32,          // ACK number (only relevent if ACK is se
    data_off    : u8,           // Data offset - in practice, only 4 bits, size of TCP header in 32-bit words
    ctrl_flags  : u16,          // Control flags 
    window      : u16,          // TCP Window size
    checksum    : u16,          // TCP checksum
    urg_ptr     : u16,          // Offset from seq num indicating the last urgen data byte
    options     : Vec<TcpOpts>, // TCP Options
    data        : Vec<u8>
}

enum TcpParseError {
    InvalidLength,
    InvalidReserved,
    InvalidDataOffset,
    InvalidChecksum{ expected : u16, actual : u16},
    InvalidOption
}

fn parse_options(options: &[u8]) -> Result<Vec<TcpOpts>, TcpParseError> {
    let mut opts = Vec::new();
    let mut iter = options.into_iter().enumerate();
    //while let Some((i, &byte)) = iter.next() {
    while let Some((i, &byte)) = iter.next() {
        if let Some(opt) = TcpOptFlags::from_bits(byte) {
            match opt {
                END => {},
                NOP => {},
                MSS => {
                    if let Some((_, &len)) = iter.next() {
                        if len != 4 {
                            return Err(TcpParseError::InvalidOption)
                        } else {
                            let a = iter.next();
                            let b = iter.next();
                            match (a, b) {
                                (Some((_, &a)), Some((_, &b))) => {
                                    let mss = [a,b].to_u16().unwrap();
                                    opts.push(TcpOpts::MSS(mss));
                                }, 
                                _ => {
                                    return Err(TcpParseError::InvalidOption)
                                }
                            }
                        }
                    } else {
                        return Err(TcpParseError::InvalidOption)
                    }
                },
                SCALE => {
                    if let Some((_, &len)) = iter.next() {
                        if len != 3 {
                            return Err(TcpParseError::InvalidOption)
                        } else {
                            if let Some((_, &scale)) = iter.next(){
                                opts.push(TcpOpts::WindowScale(scale));
                            } else {
                                return Err(TcpParseError::InvalidOption)
                            }
                        }
                    }
                },
                SACKPERM => {
                    if let Some((_, &len)) = iter.next() {
                        if len != 2 {
                            return Err(TcpParseError::InvalidOption);
                        }
                    }
                },
                SACK => {
                    if let Some((_, &len)) = iter.next() {
                        if len % 8 != 2 || (len-2)/8 > 4 || (len-2)/8 < 1 {
                            return Err(TcpParseError::InvalidOption);
                        } else {
                            let mut left = len - 2;
                            let mut ptrs = Vec::new();

                            while left > 0 {
                                let data = {
                                    let mut data = Vec::new();
                                    for _ in 0..8 {
                                        if let Some((_, &x)) = iter.next() {
                                            data.push(x);
                                        } else {
                                            return Err(TcpParseError::InvalidOption);
                                        }
                                    };
                                    data
                                };
                                let (begin, end) = data.split_at(4);
                                ptrs.push((begin.to_u32().unwrap(), end.to_u32().unwrap()));

                                left = left - 8;
                            }
                            opts.push(TcpOpts::SAck(ptrs));
                        }

                    }
                },
                TIME => {
                    if let Some((_, &len)) = iter.next() {
                        if len != 10 {
                            return Err(TcpParseError::InvalidOption);
                        } else {
                            let data = {
                                let mut data = Vec::new();
                                for _ in 0..8 {
                                    if let Some((_, &x)) = iter.next() {
                                        data.push(x);
                                    } else {
                                        return Err(TcpParseError::InvalidOption);
                                    }
                                };
                                data
                            };
                            let (timestamp, echo) = data.split_at(4);
                            opts.push(TcpOpts::TimeStamp{ 
                                time : timestamp.to_u32().unwrap(), 
                                echo: echo.to_u32().unwrap() 
                            });
                        }
                    }
                },
                _ => {
                    return Err(TcpParseError::InvalidOption)
                }
            }
        } else {
            return Err(TcpParseError::InvalidOption)
        }
    };
    Ok(opts)
}

impl TcpSegment {
    pub fn parse<T : AsRef<[u8]>>(segment : T) -> Result<TcpSegment, TcpParseError> {
        let segment : &[u8] = segment.as_ref();

        if segment.len() < 16 {
            Err(TcpParseError::InvalidLength)
        } else {
            let src_port = segment[0..2].to_u16().unwrap();
            let dest_port = segment[2..4].to_u16().unwrap();
            let seq_num = segment[4..8].to_u32().unwrap();
            let ack_num = segment[8..12].to_u32().unwrap();

            if segment[0] & 0xF0 < 5 {
                Err(TcpParseError::InvalidDataOffset)
            } else if segment[0] & 0b00001110 != 0 {
                Err(TcpParseError::InvalidReserved)
            } else {
                let data_offset = (segment[12] & 0xF0) >> 4;
                let flags = segment[12..14].to_u16().unwrap() & 0x01FF;
                let window_size = segment[14..16].to_u16().unwrap();
                let checksum = segment[16..18].to_u16().unwrap();
                let urgent_ptr = segment[18..20].to_u16().unwrap();
                let options = try!(parse_options(&segment[20..(data_offset*4) as usize]));
                let data = segment[(data_offset*4) as usize ..].iter().cloned().collect::<Vec<u8>>();
                Ok(TcpSegment{
                    src_port    : src_port,
                    dest_port   : dest_port,
                    seq_num     : seq_num,
                    ack_num     : ack_num,
                    data_off    : data_offset,
                    ctrl_flags  : flags,
                    window      : window_size,
                    checksum    : checksum,
                    urg_ptr     : urgent_ptr,
                    options     : options,
                    data        : data
                })
            }
        }
    }
}

#[cfg(test)]
mod test {
    mod test_conv_traits {
        mod test_u8_to_u32 {
            use ::{U8ToU32};

            #[test]
            fn test_invalid_length_short(){
                let x : [u8; 3] = [1,2,3];
                assert_eq!(x.to_u32(), None);
            }

            #[test]
            fn test_invalid_length_long(){
                let x : [u8; 5] = [1,2,3,4,5];
                assert_eq!(x.to_u32(), None);
            }

            #[test]
            fn test_works() {
                let x : [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
                assert_eq!(x.to_u32(), Some(0xdeadbeef));
            }
        }

        mod test_u8_to_u16 {
            use ::U8ToU16;

            #[test]
            fn test_invalid_length_short() {
                let x : [u8; 1] = [1];
                assert_eq!(x.to_u16(), None);
            }

            #[test]
            fn test_invalid_length_long() {
                let x : [u8; 3] = [1,2,3];
                assert_eq!(x.to_u16(), None);
            }

            #[test]
            fn test_works() {
                let x : [u8; 2] = [0xB0, 0x0b];
                assert_eq!(x.to_u16(), Some(0xB00B));
            }
        }

        mod test_u16_to_u8 {
            use ::U16ToU8;
            fn test_it_works(){
                let x : u16 = 0xB00B;
                assert_eq!(x.to_u8(), [0xB0, 0x0B]);
            }
        } 

        mod test_u32_to_u8 {
            use ::U32ToU8;

            fn test_it_works(){
                let x : u32 = 0xDEADBEEF;
                assert_eq!(x.to_u8(), [0xDE, 0xAD, 0xBE, 0xEF]);
            }
        }
    }
}
