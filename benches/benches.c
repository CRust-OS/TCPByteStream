#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int main(int argc, char* argv[]) {
	if(argc != 2) { 
		fprintf(stderr, "Missing *.pcap file path as argument");
		exit(1);
	}
	char* filepath = argv[1];

	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("Starting...\n");

	long int total_ns;
	struct timespec start_time;
	struct timespec end_time;
	int exit_code = 0;
	int i, psize = 0;

	libtrace_packet_t **packets = malloc(100 * sizeof(libtrace_packet_t*));
	i = 0;

	char* trace_string = malloc(5 + strlen(filepath) + 1);
	strcpy(trace_string, "pcap:");
	strcat(trace_string, filepath);
	libtrace_t* trace = trace_create(trace_string);

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
	printf("Took %ld nanoseconds.\n", total_ns/runs);
}
