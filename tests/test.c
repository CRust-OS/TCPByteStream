#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <libtrace.h>

void iferr(libtrace_t *trace)
{
	libtrace_err_t err = trace_get_err(trace);
	if (err.err_num==0)
		return;
	printf("Error: %s\n",err.problem);
	exit(1);
}

int test(libtrace_t* trace) {
	int psize = 0;
	libtrace_packet_t* packet = trace_create_packet();
	while ((psize = trace_read_packet(trace, packet)) > 0);
	trace_destroy_packet(packet);
	return psize;
}

int main(char** args) {
	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("Starting...\n");

	long int total_ns;
	struct timespec start_time;
	struct timespec end_time;
	int exit_code = 0;
	int i;
	for (i = 0; i < 1000; i++) {
		clock_gettime(CLOCK_MONOTONIC, &start_time);
		libtrace_t* trace = trace_create("pcap:100_packets.pcap");
		iferr(trace);
		trace_start(trace);
		exit_code = test(trace);
		clock_gettime(CLOCK_MONOTONIC, &end_time);
		total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000 + (end_time.tv_nsec - start_time.tv_nsec);
		if (exit_code != 0) break;
	}
	if (exit_code == 0) {
		printf("Took %ld nanoseconds.\n", total_ns / 1000);
	} else {
		printf("Error! %d on iter %d\n", exit_code, i);
	}

}
