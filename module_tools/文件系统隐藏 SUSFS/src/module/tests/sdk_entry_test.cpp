// Host-only route/authentication test; all root, daemon and file operations are mocks.
#include "../sdk_entry.cpp"
#include <cassert>
#include <cstring>
#include <iostream>
namespace { int starts=0,stops=0,requests=0,files=0,metadata=0; std::string last_directory,last_route; }
const mg_request_info* mg_get_request_info(mg_connection* c) { return &c->info; }
const char* mg_get_header(mg_connection* c,const char* name) {
 if(!std::strcmp(name,"Host"))return c->host.c_str();
 if(!std::strcmp(name,"Origin"))return c->origin.empty()?nullptr:c->origin.c_str();
 if(!std::strcmp(name,"X-SKRoot-Session"))return c->token.empty()?nullptr:c->token.c_str();
 return nullptr;
}
namespace skroot_env { int get_root(const char* key) { return std::strcmp(key,"test-root"); } }
namespace kernel_module::webui { bool send_json(mg_connection* c,int status,const std::string& body) { c->status=status;c->body=body;return true; } }
namespace file_manager {
std::string randomHex(std::size_t size) { return std::string(size*2,'a'); }
FileBroker::~FileBroker()=default;
bool FileBroker::start(const std::string&) { return true; }
ApiReply FileBroker::handle(const std::string&,const std::string&) { ++files;return {200,"{\"ok\":true}"}; }
}
namespace app_metadata {
Service::Service(Runner runner):m_runner(std::move(runner)) {}
void Service::configure(const std::string& path,std::function<bool()> init) { m_dex_path=path;m_initialize=std::move(init); }
Reply Service::handle(const std::string&) { ++metadata;return {200,"{\"ok\":true}"}; }
}
namespace susfs::management { std::string quote(std::string_view text) { return "\""+std::string(text)+"\""; } }
namespace susfs::embedded {
bool start(const std::string& dir,std::string&) { ++starts;last_directory=dir;return true; }
bool stop(const std::string& dir,std::string&) { ++stops;last_directory=dir;return true; }
Reply request(const std::string& dir,const std::string& route,const std::string&) { ++requests;last_directory=dir;last_route=route;return {200,"{\"ok\":true}"}; }
}
int main() {
 SusfsWeb ui;mg_connection c;
 ui.onPrepareCreate("test-root","/private/module",23456);assert(starts==1&&last_directory=="/private/module");
 assert(!ui.handleGet(nullptr,&c,"/index.html",""));assert(!ui.handleGet(nullptr,&c,"/vendor/editor.js",""));
 assert(ui.handlePost(nullptr,&c,"/api/session","{}")&&c.status==200&&c.body.find(std::string(64,'a'))!=std::string::npos);
 assert(ui.handlePost(nullptr,&c,"/api/susfs/status","{}")&&c.status==401&&requests==0);
 c.token=std::string(64,'a');assert(ui.handlePost(nullptr,&c,"/api/susfs/status","{}")&&c.status==200&&last_route=="/status");
 assert(ui.handleGet(nullptr,&c,"/api/susfs/config-get","")&&last_route=="/config");
 assert(ui.handlePost(nullptr,&c,"/api/files/list","{}")&&c.status==200&&files==1);
 assert(ui.handlePost(nullptr,&c,"/api/apps/metadata","{}")&&c.status==200&&metadata==1);
 c.origin="https://evil.example";assert(ui.handlePost(nullptr,&c,"/api/files/list","{}")&&c.status==403&&files==1);
 c.origin="";c.host="evil.example";assert(ui.handleGet(nullptr,&c,"/index.html","")&&c.status==403);
 c.host="127.0.0.1:23456";c.info.remote_addr="192.0.2.1";assert(ui.handlePost(nullptr,&c,"/api/session","{}")&&c.status==403);
 assert(skroot_module_main("wrong","/private/module")==1&&starts==1);
 assert(skroot_module_main("test-root","/private/module")==0&&starts==2);
 assert(module_on_install("wrong","/private/module")!=""&&stops==0);
 assert(module_on_install("test-root","/private/module")==""&&stops==1);
 module_on_uninstall("wrong","/private/module");assert(stops==1);
 module_on_uninstall("test-root","/private/module");assert(stops==2);
 std::cout<<"SDK handler auth, route aliases, private service and lifecycle mocks passed\n";
}
