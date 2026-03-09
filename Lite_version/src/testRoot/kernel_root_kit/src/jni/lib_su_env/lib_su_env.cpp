#include <unistd.h>
#include <iostream>
#include <string>
#include "lib_su_env_inline.h"

void so_entry() {
    char k_path[] = {'P', 'A', 'T', 'H', '\0'};
    std::string who = getenv(k_path);
    std::string su_dir_path = const_cast<char*>(static_inline_su_dir_path);
    if(who.find(su_dir_path) != std::string::npos) {
        return;
    }
    std::string newWho = su_dir_path;
    newWho += ":";
    newWho += who;
    setenv(k_path, newWho.c_str(), 1);
}

extern "C" void __attribute__((constructor)) inject_su_path_entry() {
    so_entry();
}
