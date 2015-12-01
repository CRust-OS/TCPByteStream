.PHONY: clean

PROJECT_ROOT=..
FLAMEGRAPH_ROOT=$(PROJECT_ROOT)/tools/FlameGraph

c_flame: c_benchmark
	sudo perf record -F 3000 -g -- ./c_benchmark
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

c_benchmark: test.c
	gcc test.c -g -ltrace -O3 -o c_benchmark
