#include "scan_modules.h"

static struct ScanModule *scan_modules[] = {
    0
};

struct ScanModule *get_scan_by_name(const char *name)
{
	int len = (int)(sizeof(struct ScanModule)/sizeof(struct StatelessProbe *));
	for (int i = 0; i < len; i++) {
		if (!strcmp(scan_modules[i]->name, name)) {
			return scan_modules[i];
		}
	}
	return NULL;
}

void list_all_scans()
{
	int len = (int)(sizeof(scan_modules)/sizeof(struct ScanModule *));
	printf("\nNow contains %d ScanModules:\n\n", len);

	for (int i = 0; i < len; i++) {
		printf("========================\n\n");
		printf("ScanModule Name: %s\n", scan_modules[i]->name);
		printf("Description:\n%s\n", scan_modules[i]->description);
	}
	printf("========================\n");
}
