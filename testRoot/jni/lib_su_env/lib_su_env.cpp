#include <unistd.h>
#include <iostream>
#include <string>
#include "lib_su_env_inline.h"

void so_entry() {
    std::string who = getenv("PATH");
    if(who.find(const_cast<char*>(static_inline_su_path)) != std::string::npos) {
        return;
    }
    std::string newWho = const_cast<char*>(static_inline_su_path);
    newWho += ":";
    newWho += who;
    setenv("PATH", newWho.c_str(), 1);
}

extern "C" void __attribute__((constructor)) inject_su_path_entry() {
    so_entry();
}
