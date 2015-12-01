.PHONY: clean

PROJECT_ROOT=..
FLAMEGRAPH_ROOT=$(PROJECT_ROOT)/tools/FlameGraph

TMP:=$(shell mktemp -d)
$(shell sudo chown $(USER) $(TMP))

flame: c_benchmark.svg rust_benchmark.svg

c_benchmark.svg: c_benchmark
	perf record -o $(TMP)/perf.data -F 10000 -g -- ./c_benchmark 100_packets.pcap
	perf script -i $(TMP)/perf.data > $(TMP)/out.perf
	sudo chown $(USER) $(TMP)/out.perf
	$(FLAMEGRAPH_ROOT)/stackcollapse-perf.pl $(TMP)/out.perf > $(TMP)/out.folded
	$(FLAMEGRAPH_ROOT)/flamegraph.pl $(TMP)/out.folded > c_benchmark.svg

rust_benchmark.svg: rust_benchmark
	perf record -o $(TMP)/perf.data -F 10000 -g -- ./rust_benchmark 100_packets.pcap
	perf script -i $(TMP)/perf.data > $(TMP)/out.perf
	sudo chown $(USER) $(TMP)/out.perf
	$(FLAMEGRAPH_ROOT)/stackcollapse-perf.pl $(TMP)/out.perf > $(TMP)/out.folded
	$(FLAMEGRAPH_ROOT)/flamegraph.pl $(TMP)/out.folded > rust_benchmark.svg

rust_benchmark:
	cargo build --release --features=use_pcap
	cp $(PROJECT_ROOT)/target/release/tcp_byte_stream rust_benchmark

c_benchmark: benches.c
	gcc benches.c -g -ltrace -O3 -o c_benchmark

clean:
	rm *.svg
	rm c_benchmark
	rm rust_benchmark
