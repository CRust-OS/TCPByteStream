use nom::{IResult, rest, be_u8, be_u16, be_u32, eof};
use nom::IResult::*;
use super::{TcpOpts, TcpSegment, TcpParseError, END, NOP, MSS, SCALE, SACKPERM, SACK, TIME};
use std::vec::Vec;

#[derive(Debug)]
struct DataOffsetFlags{
    data_off: u8,
    flags   : u16
}
named!(data_flags<DataOffsetFlags>, chain!(
    data : bits!(separated_pair!(take_bits!(u8, 4), tag_bits!(u8, 3, 0b000), take_bits!(u8, 1))) ~
    flags: be_u8,
    ||{
        DataOffsetFlags{
            data_off    : data.0,
            flags       : ((data.1 as u16) << 8) | (flags as u16)
        }
    }
));
named!(parse_end<TcpOpts>, chain!(
            tag!(&[END.bits()]),
    ||{
        TcpOpts::END
    }
));
named!(parse_nop<TcpOpts>, chain!(
            tag!(&[NOP.bits()]),
    ||{
        TcpOpts::NOP
    }
));
named!(parse_mss<TcpOpts>, chain!(
            tag!(&[MSS.bits()]) ~
            tag!(&[0x04])       ~
    mss:    be_u16,
    ||{
        TcpOpts::MSS(mss)
    }
));
named!(parse_scale<TcpOpts>, chain!(
            tag!(&[SCALE.bits()])   ~
            tag!(&[0x03])           ~
    scale:  be_u8,
    ||{
        TcpOpts::WindowScale(scale)
    }
));
named!(parse_sackperm<TcpOpts>, chain!(
            tag!(&[SACKPERM.bits()]) ~
            tag!(&[0x02]),
    ||{
        TcpOpts::SAckPermitted
    }
));
named!(parse_sack<TcpOpts>, chain!(
            tag!(&[SACK.bits()]) ~
    len:    be_u8                ~
    data:   count!(pair!(be_u32, be_u32), ((len-2)/8) as usize),
    ||{
        TcpOpts::SAck(data)
    }
));
named!(parse_time<TcpOpts>, chain!(
            tag!(&[TIME.bits()])    ~
            tag!(&[0x0A])           ~
    data:   pair!(be_u32, be_u32)   ,
    ||{
        TcpOpts::TimeStamp{
            time: data.0,
            echo: data.1
        }
    }
));

named!(parse_opts<Vec<TcpOpts> >, chain!(
    data: many0!(alt!(
                        parse_end       |
                        parse_nop       |
                        parse_mss       |
                        parse_scale     |
                        parse_sackperm  |
                        parse_sack      |
                        parse_time
                     ))    ~
          eof,
    ||{
        data
    }
));

named!(pub parse<&[u8], TcpSegment>, chain!(
        src_port:       be_u16  ~
        dest_port:      be_u16  ~
        seq_num:        be_u32  ~
        ack_num:        be_u32  ~
        offset_flags:   data_flags ~
        window:         be_u16  ~
        checksum:       be_u16  ~
        urg_ptr:        be_u16  ~
        options:        flat_map!(take!((4*offset_flags.data_off as usize) - 20), parse_opts)             ~
        data:           rest,
        ||{
            TcpSegment{
                src_port:       src_port,
                dest_port:      dest_port, 
                seq_num:        seq_num,
                ack_num:        ack_num,
                data_off:       offset_flags.data_off,  
                ctrl_flags:     offset_flags.flags,
                window:         window,
                checksum:       checksum,
                urg_ptr:        urg_ptr,
                options:        options,
                data:           data.iter().cloned().collect()
            }
        }
));
