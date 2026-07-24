#include "kernel_module_kit_umbrella.h"
#include <string>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>

SKROOT_MODULE_NAME("TEESimulator-RS")
SKROOT_MODULE_VERSION("6.0.1")
SKROOT_MODULE_DESC("Software simulation for Android hardware-backed key pairs with key attestation")
SKROOT_MODULE_AUTHOR("JingMatrix, Enginex0, xiaoxun")
SKROOT_MODULE_UUID32("teesimulator601skpro202607210000")

static std::string clean_path(const char* path) {
    std::string p = path ? path : "";
    while (!p.empty() && p.back() == '/') {
        p.pop_back();
    }
    return p;
}

int skroot_module_main(const char* root_key, const char* module_private_dir)
{
    std::string mod_dir = clean_path(module_private_dir);
    std::string service_path = mod_dir + "/service.sh";

    struct stat st;
    if (stat(service_path.c_str(), &st) != 0) {
        return -1;
    }

    chmod(service_path.c_str(), 0755);

    std::string cmd = "nohup sh " + service_path + " > /dev/null 2>&1 &";
    system(cmd.c_str());

    return 0;
}
