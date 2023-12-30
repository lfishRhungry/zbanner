#include <string.h>
#include <stdio.h>

#include "stateless-probes.h"

/*
This is an Application Probe(or Request) Plugin System
*/



extern struct StatelessProbe NullProbe;
extern struct StatelessProbe GetRequestProbe;
//! ADD YOUR PROBE HERE



static struct StatelessProbe *stateless_probes[] = {
	&NullProbe, /* its also the default probe*/
	&GetRequestProbe
	//! ADD YOUR PROBE HERE
};


struct StatelessProbe *get_stateless_probe(const char *name) {
	int len = (int)(sizeof(stateless_probes)/sizeof(struct StatelessProbe *));
	for (int i = 0; i < len; i++) {
		if (!strcmp(stateless_probes[i]->name, name)) {
			return stateless_probes[i];
		}
	}
	return NULL;
}

void list_all_probes()
{
	int len = (int)(sizeof(stateless_probes)/sizeof(struct StatelessProbe *));
	printf("\nNow contains %d stateless probes:\n\n", len);

	for (int i = 0; i < len; i++) {
		printf("========================\n\n");
		printf("Probe Name: %s\n", stateless_probes[i]->name);
		printf("Probe Help:\n%s\n", stateless_probes[i]->help_text);
	}
	printf("========================\n");
}
