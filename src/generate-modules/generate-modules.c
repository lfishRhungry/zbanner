#include "generate-modules.h"
#include "../util-out/xprint.h"
#include "../util-out/logger.h"
#include "../util-data/safe-string.h"

// clang-format off
//! ADD YOUR GENERATOR HERE
extern Generator BlackRockGen;

//! ADD YOUR GENERATOR HERE
static Generator *generate_modules_list[] = {
    &BlackRockGen, /* its also the default generator*/
};
// clang-format on

Generator *get_generate_module_by_name(const char *name) {
    int len = (int)ARRAY_SIZE(generate_modules_list);
    for (int i = 0; i < len; i++) {
        if (!strcmp(generate_modules_list[i]->name, name)) {
            return generate_modules_list[i];
        }
    }
    return NULL;
}

void list_all_generate_modules() {
    int len = (int)ARRAY_SIZE(generate_modules_list);

    printf("\n");
    printf(XPRINT_STAR_LINE);
    printf("\n");
    printf("      Now contains [%d] GenerateModules\n", len);
    printf(XPRINT_STAR_LINE);
    printf("\n");
    printf("\n");

    for (int i = 0; i < len; i++) {
        printf(XPRINT_DASH_LINE);
        printf("\n");
        printf("\n");
        printf("  GenerateModule Name: %s\n", generate_modules_list[i]->name);
        printf("  Description:\n");
        xprint(generate_modules_list[i]->desc, 6, 80);
        printf("\n");
        printf("\n");
    }
    printf(XPRINT_DASH_LINE);
    printf("\n");
    printf("\n");
}

void help_generate_module(Generator *module) {
    if (!module) {
        LOG(LEVEL_ERROR, "No specified generate module.\n");
        return;
    }

    printf("\n");
    printf(XPRINT_DASH_LINE);
    printf("\n");
    printf("\n");
    printf("  GenerateModule Name: %s\n", module->name);
    printf("\n");
    printf("  Description:\n");
    xprint(module->desc, 6, 80);
    printf("\n");
    printf("\n");
    if (module->params) {
        for (unsigned j = 0; module->params[j].name; j++) {
            if (!module->params[j].help_text)
                continue;

            printf("  --%s", module->params[j].name);
            for (unsigned k = 0; module->params[j].alt_names[k]; k++) {
                printf(", --%s", module->params[j].alt_names[k]);
            }
            printf("\n");
            xprint(module->params[j].help_text, 6, 80);
            printf("\n\n");
        }
    }
    printf(XPRINT_DASH_LINE);
    printf("\n");
    printf("\n");
}

bool generate_init_nothing(const XConf *xconf) { return true; }

/*implemented `generate_modules_close`*/
void generate_close_nothing(const XConf *xconf) {}