#include "kernel_module_kit_umbrella.h"

// SKRoot模块入口函数
int skroot_module_main(const char* root_key, const char* module_private_dir) {
    printf("[module_background_service_example] hello\n");
    pid_t child = fork();
    if (child == 0) {
        //读取配置文件内容
        std::string value;
        KModErr err = kernel_module::read_string_disk_storage("myKey", value);
        if(is_ok(err)) {
            printf("[module_background_service_example] read storage succeed: value: %s\n", value.c_str());
        } else {
            printf("[module_background_service_example] read storage failed: %s\n", to_string(err).c_str());
        }
        _exit(0);
    }
    return 0;
}


// WebUI HTTP服务器回调函数
class MyWebHttpHandler : public kernel_module::WebUIHttpHandler { // HTTP服务器基于civetweb库
public:
    bool handlePost(CivetServer* server, struct mg_connection* conn, const std::string& path, const std::string& body) override {
        printf("POST request\nPath: %s\nBody: %s\n", path.c_str(), body.c_str());

        std::string resp;
        if(path == "/getPid") resp = std::to_string(getpid());
        else if(path == "/getUid") resp = std::to_string(getuid());
        else if(path == "/getValue") kernel_module::read_string_disk_storage("myKey", resp);
        else if(path == "/setValue") resp = is_ok(kernel_module::write_string_disk_storage("myKey", body.c_str())) ? "OK" : "FAILED";
        
        kernel_module::webui::send_text(conn, 200, resp);
        return true;
    }
};

// SKRoot 模块名片
// 字段说明见 module_descriptor.h
SKROOT_MODULE_NAME("后台服务运行 Demo")
SKROOT_MODULE_VERSION("1.0.0")
SKROOT_MODULE_DESC("演示创建一个后台常驻服务")
SKROOT_MODULE_AUTHOR("SKRoot")
SKROOT_MODULE_ID32("wAMFLlmwBMi1vNQz5MnJ0GG5yQrXG6Ex")
SKROOT_MODULE_WEB_UI(MyWebHttpHandler)