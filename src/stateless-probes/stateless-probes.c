#include <string.h>

#include "stateless-probes.h"

/*
This is an Application Probe(or Request) Plugin System
*/



extern struct StatelessProbe NullProbe;
//! ADD YOUR PROBE HERE



static struct StatelessProbe *stateless_probes[] = {
	&NullProbe /* its also the default probe*/
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
