#![allow(unused_imports)]

#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate nom;

mod util;
mod parser;
use util::{U8ToU16, U8ToU32, U32ToU8, U16ToU8, U32ToU16};

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TcpOpts {
    END,
    NOP,
    MSS(u16),           // Maximum segment size, length should be 4 (SYN only)
    WindowScale(u8),    // Window scale, length should be 3 (SYN only)
    SAckPermitted,      // Selective ACK permitted (SYN only)
    SAck(Vec<(u32, u32)>),     // Selective ACK (variable length, 1-4 bocks of 32 bit begin/end ptrs)
    TimeStamp { time: u32, echo: u32 }      // Timestamp and echo of prev timestamp, length should be 10
}

impl TcpOpts {
    fn opt_flag(&self) -> TcpOptFlags {
        match self {
            &TcpOpts::END => END,
            &TcpOpts::NOP => NOP,
            &TcpOpts::MSS(_) => MSS,
            &TcpOpts::WindowScale(_) => SCALE,
            &TcpOpts::SAckPermitted => SACKPERM,
            &TcpOpts::SAck(_) => SACK,
            &TcpOpts::TimeStamp{time : _ , echo: _} => TIME
        }
    }
}

trait TcpOptStream {
    fn as_u16_stream(&self) -> Vec<u16>;
}

impl TcpOptStream for Vec<TcpOpts> {
    fn as_u16_stream(&self) -> Vec<u16> {
        let mut data = Vec::with_capacity(self.len()*4);    // Easier to allocate a larger buffer than needed; reduce allocations

        for opt in self.iter() {
            data.push(opt.opt_flag().bits());
            match opt {
                &TcpOpts::END | &TcpOpts::NOP => {},
                &TcpOpts::MSS(mss) => {
                    data.push(0x04);
                    data.extend(mss.to_u8().iter());
                },
                &TcpOpts::WindowScale(scale) => {
                    data.push(0x03);
                    data.push(scale);
                },
                &TcpOpts::SAckPermitted => {
                    data.push(0x02);
                }
                &TcpOpts::SAck(ref ptrs) => {
                    data.push((ptrs.len() as u8)*8 + 2);
                    for &(ref a, ref b) in ptrs.iter() {
                        data.extend(a.to_u8().iter());
                        data.extend(b.to_u8().iter());
                    }
                },
                &TcpOpts::TimeStamp{time : ref t, echo: ref e} => {
                    data.push(0x0A);
                    data.extend(t.to_u8().iter());
                    data.extend(e.to_u8().iter());
                }
            }
        }

        data.chunks(2).map(|chunk| {
            if chunk.len() == 1 {
                (chunk[0] as u16) << 8
            } else {
                ((chunk[0] as u16) << 8) | (chunk[1] as u16)
            }
        }).collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpSegment {
    //pub pseudo_header   : IPv4PseudoHeader, // IPv4/IPv6 pseudo header
    pub src_port        : u16,              // source port  
    pub dest_port       : u16,              // dest port
    pub seq_num         : u32,              // sequence number
    pub ack_num         : u32,              // ACK number (only relevent if ACK is se
    pub data_off        : u8,               // Data offset - in practice, only 4 bits, size of TCP header in 32-bit words
    pub ctrl_flags      : u16,              // Control flags 
    pub window          : u16,              // TCP Window size
    pub checksum        : u16,              // TCP checksum
    pub urg_ptr         : u16,              // Offset from seq num indicating the last urgen data byte
    pub options         : Vec<TcpOpts>,     // TCP Options
    //options_orig    : Vec<u8>,
    pub data            : Vec<u8>           // application layer data
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IPv4PseudoHeader {
    pub source_addr : u32,
    pub dest_addr   : u32,
    pub protocol    : u8,
    pub tcp_len     : u16
}

// TODO: Add InvalidOption enum for better error messages
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TcpParseError {
    InvalidLength,
    InvalidReserved,
    InvalidDataOffset,
    InvalidChecksum{ expected : u16, actual : u16},
    InvalidOption
}



impl TcpSegment {

    /// Parse the given byte stream into a TcpSegment. At the moment, panicks on failure
    /// TODO: Improve error messages
    pub fn parse<T : AsRef<[u8]>>(segment : T) -> TcpSegment {
        match parser::parse(segment.as_ref()) {
            nom::IResult::Done(_, seg) => seg,
            r => panic!("{:?}", r)
        }

    }
    //pub fn parse_old<T : AsRef<[u8]>>(segment : T) -> Result<TcpSegment, TcpParseError> {
    //let segment : &[u8] = segment.as_ref();
    //let mut segment_iter = segment.iter();


    //if segment.len() < 20 {     20 for TCP segment
    //Err(TcpParseError::InvalidLength)
    //} else {
    //let src_port : u16 = segment_iter.by_ref().take(2).to_u16().unwrap();
    //let dest_port : u16 = segment_iter.by_ref().take(2).to_u16().unwrap();
    //let seq_num : u32 = segment_iter.by_ref().take(4).to_u32().unwrap();
    //let ack_num : u32 = segment_iter.by_ref().take(4).to_u32().unwrap();
    //let b12 : u8 = *segment_iter.next().unwrap();
    //if ((b12 & 0xF0) >> 2) < 5 {
    //Err(TcpParseError::InvalidDataOffset)
    //} else if (b12 & 0b00001110) != 0 {
    //Err(TcpParseError::InvalidReserved)
    //} else {
    //let data_offset = (b12 & 0xF0) >> 4;
    //let flags = [b12, *segment_iter.next().unwrap()].iter().to_u16().unwrap() & 0x01FF;
    //let window_size = segment_iter.by_ref().take(2).to_u16().unwrap();
    //let checksum = segment_iter.by_ref().take(2).to_u16().unwrap();
    //let urgent_ptr = segment_iter.by_ref().take(2).to_u16().unwrap();
    //let options_orig = segment_iter.by_ref().take(4*data_offset as usize - 20).cloned().collect::<Vec<u8>>();
    //let options = try!(parse_options(&mut segment_iter.by_ref().take(4*data_offset as usize - 20)));
    //let options = try!(parse_options(&mut options_orig.clone().iter()));
    //let data = segment_iter.cloned().collect::<Vec<u8>>();

    //let parsed = TcpSegment{
    //pseudo_header   : header,
    //src_port        : src_port,
    //dest_port       : dest_port,
    //seq_num         : seq_num,
    //ack_num         : ack_num,
    //data_off        : data_offset,
    //ctrl_flags      : flags,
    //window          : window_size,
    //checksum        : checksum,
    //urg_ptr         : urgent_ptr,
    //options         : options,
    //options_orig    : options_orig,
    //data            : data
    //};

    //Ok(parsed)
    //}
    //}
    //}

    pub fn calculate_checksum(&self, pseudo_header : IPv4PseudoHeader) -> u16 {
        let add_u16 = |sum: &mut u32, x: u16|{
            *sum = *sum + x as u32;
            if (*sum & 0x80000000) != 0 {
                *sum = (*sum & 0xFFFF) + *sum >> 16;
            }
        };
        let add_u32 = |sum : &mut u32, x: u32|{
            let (a, b) = x.to_u16();
            add_u16(sum, a);
            add_u16(sum, b);
        };

        let mut checksum : u32 = 0;
        let sum : &mut u32 = &mut checksum;

        add_u32(sum, pseudo_header.source_addr);
        add_u32(sum, pseudo_header.dest_addr);
        add_u16(sum, pseudo_header.protocol as u16);
        add_u16(sum, pseudo_header.tcp_len);
        add_u16(sum, self.src_port);
        add_u16(sum, self.dest_port);
        add_u32(sum, self.seq_num);
        add_u32(sum, self.ack_num);
        add_u16(sum, ((self.data_off as u16) << 12) | self.ctrl_flags);
        add_u16(sum, self.window);
        add_u16(sum, self.urg_ptr);

        for x in self.options.as_u16_stream() {
            add_u16(sum, x);
        }

        for chunk in self.data.chunks(2) {
            if chunk.len() == 1 {
                add_u16(sum, (chunk[0] as u16) << 8);
            } else {
                add_u16(sum, chunk.iter().to_u16().unwrap())
            }
        }

        while (*sum >> 16) > 0 {
            *sum = (*sum & 0xFFFF) + (*sum >> 16)
        };


        !((*sum & 0x0000FFFF) as u16)
    }
}

#[cfg(test)]
mod test {
    use super::{TcpSegment,IPv4PseudoHeader,TcpCTRL, TcpOpts, SYN, ACK}; 
    use util::{U8ToU16, U8ToU32, U32ToU8, U16ToU8, U32ToU16};

    #[test]
    fn check_parse_ok_1(){
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


}
