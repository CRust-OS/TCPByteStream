#![cfg_attr(feature = "core", feature(no_std))]
#![cfg_attr(feature = "core", feature(collections))]
#![cfg_attr(feature = "core", no_std)]

#![allow(unused_imports)]
#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate nom;

#[cfg(feature = "core")]
extern crate collections;

#[cfg(feature = "core")]
mod std {
    #[macro_use]
    pub use core::{fmt, iter, option, ops, slice, mem};
    pub use collections::{boxed, vec, string};
    pub mod prelude {
        pub use core::prelude as v1;
    }
}

use std::vec::Vec;


pub mod util;
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

    pub fn as_bytestream(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(self.data.len() + (self.data_off as usize)*4);
        data.extend(self.src_port.to_u8().iter());
        data.extend(self.dest_port.to_u8().iter());
        data.extend(self.seq_num.to_u8().iter());
        data.extend(self.ack_num.to_u8().iter());
        data.extend((((self.data_off as u16) << 12) | (self.ctrl_flags & 0x1FF)).to_u8().iter());
        data.extend(self.window.to_u8().iter());
        data.extend(self.checksum.to_u8().iter());
        data.extend(self.urg_ptr.to_u8().iter());
        for x in self.options.as_u16_stream() {
            data.extend(x.to_u8().iter())
        };
        data.extend(self.data.iter());
        data
    }
}

