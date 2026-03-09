#pragma once
#include <string>
#include <unistd.h>

static void android_open_url(const std::string& url) {
    std::string cmd = "am start -a android.intent.action.VIEW -d " + url;
    FILE * fp = popen(cmd.c_str(), "r");
    if(fp) pclose(fp);
}