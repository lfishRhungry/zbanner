#include <string.h>
#include <stdio.h>

#include "stateless-probes.h"

/*
This is an Application Probe(or Request) Plugin System
*/



extern struct StatelessProbe NullProbe;
extern struct StatelessProbe GetRequestProbe;
extern struct StatelessProbe LzrProbe;
extern struct StatelessProbe LzrWaitProbe;
extern struct StatelessProbe LzrHttpProbe;
extern struct StatelessProbe LzrFtpProbe;
//! ADD YOUR PROBE HERE



static struct StatelessProbe *stateless_probes[] = {
	&NullProbe, /* its also the default probe*/
	&GetRequestProbe,
	&LzrProbe,
	&LzrWaitProbe,
	&LzrHttpProbe,
    &LzrFtpProbe,
	//! ADD YOUR PROBE HERE
};


struct StatelessProbe *get_stateless_probe(const char *name)
{
	int len = (int)(sizeof(stateless_probes)/sizeof(struct StatelessProbe *));
	for (int i = 0; i < len; i++) {
		if (!strcmp(stateless_probes[i]->name, name)) {
			return stateless_probes[i];
		}
	}
	return NULL;
}

static char *get_probe_type_name(enum StatelessProbeType type)
{
	switch (type) {
		case Raw_Probe:
			return "raw";
		case Tcp_Probe:
			return "tcp";
		case Udp_Probe:
			return "udp";
		default:
			break;
	}
	return "unknown";
}

void list_all_probes()
{
	int len = (int)(sizeof(stateless_probes)/sizeof(struct StatelessProbe *));
	printf("\nNow contains %d stateless probes:\n\n", len);

	for (int i = 0; i < len; i++) {
		printf("========================\n\n");
		printf("Probe Name: %s\n", stateless_probes[i]->name);
		printf("Probe Type: %s\n", get_probe_type_name(stateless_probes[i]->type));
		printf("Probe Help:\n%s\n", stateless_probes[i]->help_text);
	}
	printf("========================\n");
}
