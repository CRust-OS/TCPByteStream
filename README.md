# TCP Byte Stream
An implementation of parsing TCP, abstracted as parsing a byte stream. Implemented as a class project for ECSE 414 - Intro to Telecom Networks - Fall 2015

# Requirements
For benchmarking: `libpcap-dev`, `libtrace-dev`

# TODO
- More tests with different types of flags/options
    - Currently have MSS, TCP SACK Permitted, Timestamps, NOP, Window scale for opts
    - Only SYN for flag
- Benchmark
- Document
