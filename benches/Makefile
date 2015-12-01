.PHONY: clean

PROJECT_ROOT=..
FLAMEGRAPH_ROOT=$(PROJECT_ROOT)/tools/FlameGraph

c_flame: c_benchmark
	sudo perf record -F 3000 -g -- ./c_benchmark 100_packets.pcap
	sudo perf script > out.perf
	sudo chown $(USER) out.perf
	$(FLAMEGRAPH_ROOT)/stackcollapse-perf.pl out.perf > out.folded
	$(FLAMEGRAPH_ROOT)/flamegraph.pl out.folded > c_benchmark.svg

rust_flame: rust_benchmark
	sudo perf record -F 10000 -g -- ./rust_benchmark
	sudo perf script > out.perf
	sudo chown $(USER) out.perf
	$(FLAMEGRAPH_ROOT)/stackcollapse-perf.pl out.perf > out.folded
	$(FLAMEGRAPH_ROOT)/flamegraph.pl out.folded > rust_benchmark.svg

c_benchmark: benches.c
	gcc benches.c -g -ltrace -O3 -o c_benchmark

clean:
	rm perf.*
	rm *.perf
	rm *.folded
	rm *.svg
	rm c_benchmark
	rm rust_benchmark
