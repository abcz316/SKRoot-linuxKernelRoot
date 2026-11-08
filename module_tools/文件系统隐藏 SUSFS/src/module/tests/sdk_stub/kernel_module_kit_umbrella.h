#pragma once
#include <string>
#include <cstdint>
struct mg_request_info { const char* remote_addr="127.0.0.1"; int server_port=23456, remote_port=23457; };
struct mg_connection { mg_request_info info; std::string host="127.0.0.1:23456", origin="http://127.0.0.1:23456", token; int status=0; std::string body; };
struct CivetServer {};
const mg_request_info* mg_get_request_info(mg_connection*);
const char* mg_get_header(mg_connection*,const char*);
namespace skroot_env { int get_root(const char*); }
inline bool is_failed(int result) { return result!=0; }
namespace kernel_module {
class WebUIHttpHandler {
public:
 virtual ~WebUIHttpHandler()=default;
 virtual void onPrepareCreate(const char*,const char*,uint32_t) {}
 virtual bool handleGet(CivetServer*,mg_connection*,const std::string&,const std::string&) { return false; }
 virtual bool handlePost(CivetServer*,mg_connection*,const std::string&,const std::string&) { return false; }
};
namespace webui { bool send_json(mg_connection*,int,const std::string&); }
}
#define SKROOT_MODULE_NAME(value)
#define SKROOT_MODULE_VERSION(value)
#define SKROOT_MODULE_DESC(value)
#define SKROOT_MODULE_AUTHOR(value)
#define SKROOT_MODULE_ID32(value)
#define SKROOT_MODULE_WEB_UI(value)
#define SKROOT_MODULE_ON_INSTALL(value)
#define SKROOT_MODULE_ON_UNINSTALL(value)
