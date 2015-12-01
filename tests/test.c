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

void test(libtrace_packet_t** packets, int len) {
    int i = 0;
    while (i < len) {
        libtrace_tcp_t* tcp = trace_get_tcp(packets[i++]);
        uint32_t rem;
        void* data = trace_get_payload_from_tcp(tcp, &rem);
    }
}

int main(char** args) {
	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("Starting...\n");

	long int total_ns;
	struct timespec start_time;
	struct timespec end_time;
	int exit_code = 0;
	int i, psize = 0;

    libtrace_packet_t **packets = malloc(100 * sizeof(libtrace_packet_t*));
    i = 0;

    libtrace_t* trace = trace_create("pcap:100_packets.pcap");
    iferr(trace);
    trace_start(trace);
    libtrace_packet_t* packet = trace_create_packet();
	while ((psize = trace_read_packet(trace, packet)) > 0){
        libtrace_tcp_t* tcp = trace_get_tcp(packet);
        if(tcp != NULL){
            packets[i++] = packet;
            packet = trace_create_packet();
        } 

    }
    int len = i;

	for (i = 0; i < 1000; i++) {
		clock_gettime(CLOCK_MONOTONIC, &start_time);
        test(packets, len);
		clock_gettime(CLOCK_MONOTONIC, &end_time);
		total_ns += (end_time.tv_sec - start_time.tv_sec) * 1000000000 + (end_time.tv_nsec - start_time.tv_nsec);
	}

    int runs = i;

    for (i = 0; i < len; i++){
        trace_destroy_packet(packets[i]);
    }

    free(packets);

    printf("RUNS: %d, total_ns: %ld\n", runs, total_ns);
    printf("Took %ld nanoseconds.\n", total_ns/runs);

}
