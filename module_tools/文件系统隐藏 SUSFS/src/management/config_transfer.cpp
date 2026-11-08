#include "config_transfer.hpp"
#include "common.hpp"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <cstdlib>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>
namespace susfs::management {
namespace {
constexpr std::size_t limit=524288;
constexpr std::size_t file_limit=limit+1024; // Small export envelope around a full-size config.
bool path_ok(const std::string& path) {
 return !path.empty()&&path.front()=='/'&&path.size()<4096&&path.find('\0')==std::string::npos;
}
bool fail(std::string& error,const char* reason){error=reason;return false;}
bool same_file(const struct stat& a,const struct stat& b){
 return a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_size==b.st_size&&
  a.st_mtim.tv_sec==b.st_mtim.tv_sec&&a.st_mtim.tv_nsec==b.st_mtim.tv_nsec;
}
}
bool import_config_file(const std::string& path,Config& imported,std::string& error){
 if(!path_ok(path))return fail(error,"invalid_import_path");
 const int fd=open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
 if(fd<0)return fail(error,std::strerror(errno));
 struct stat before{},after{};
 if(fstat(fd,&before)||!S_ISREG(before.st_mode)||before.st_size<=0||before.st_size>static_cast<off_t>(file_limit)){
  close(fd);return fail(error,"invalid_or_oversized_config_file");
 }
 std::string data;data.reserve(static_cast<std::size_t>(before.st_size));
 for(;;){char chunk[8192];const auto n=read(fd,chunk,sizeof(chunk));
  if(n<0&&errno==EINTR)continue;
  if(n<0){const auto e=errno;close(fd);return fail(error,std::strerror(e));}
  if(!n)break;
  if(data.size()+static_cast<std::size_t>(n)>file_limit){close(fd);return fail(error,"config_file_too_large");}
  data.append(chunk,static_cast<std::size_t>(n));
 }
 const bool stable=!fstat(fd,&after)&&same_file(before,after);close(fd);
 if(!stable)return fail(error,"config_file_changed");
 auto envelope=parse_json(data,error,file_limit);if(!envelope)return false;
 std::string config_data=data;
 if(const auto* format=member(envelope.get(),"format")){
  std::string name;
  const auto* version=member(envelope.get(),"format_version");
  if(!json_string(format,name)||name!="susfs4skp-config"||!cJSON_IsNumber(version)||version->valuedouble!=1)
   return fail(error,"unsupported_config_export");
  const auto* config=member(envelope.get(),"config");if(!cJSON_IsObject(config))return fail(error,"missing_export_config");
  char* printed=cJSON_PrintUnformatted(config);if(!printed)return fail(error,"out_of_memory");
  config_data=printed;cJSON_free(printed);
 }
 Config value;if(!parse_config(config_data,value,error)||!config_writable(value,error))return false;
 imported=std::move(value);error.clear();return true;
}
bool export_config_file(const std::string& path,const Config& config,std::string& error){
 if(!path_ok(path))return fail(error,"invalid_export_path");
 const auto data="{\"format\":\"susfs4skp-config\",\"format_version\":1,\"config\":"+serialize_config(config)+"}\n";
 if(data.size()>file_limit)return fail(error,"config_file_too_large");
 // Prepare off to the side, then publish without replacing any user file.
 const auto slash=path.rfind('/');
 std::string temporary=path.substr(0,slash+1)+".susfs-config-XXXXXX";
 const int fd=mkstemp(temporary.data());
 if(fd<0)return fail(error,std::strerror(errno));
 (void)fcntl(fd,F_SETFD,FD_CLOEXEC);
 std::size_t offset=0;bool ok=true;
 while(offset<data.size()){
  const auto n=write(fd,data.data()+offset,data.size()-offset);
  if(n<0&&errno==EINTR)continue;
  if(n<=0){ok=false;break;}offset+=static_cast<std::size_t>(n);
 }
 if(ok&&fsync(fd))ok=false;
 const int code=errno;if(close(fd)&&ok){ok=false;error=std::strerror(errno);}
 if(!ok){unlink(temporary.c_str());if(error.empty())error=std::strerror(code);return false;}
 // Atomic publication with no replacement, including when the destination
 // appears while the export is being written. Supported by the current LKM
 // target's Linux VFS; unsupported filesystems return their actual error.
#if defined(SYS_renameat2)
 const auto renamed=syscall(SYS_renameat2,AT_FDCWD,temporary.c_str(),AT_FDCWD,path.c_str(),1U);
 const int rename_error=errno;
#else
 const int renamed=-1,rename_error=EOPNOTSUPP;
#endif
 if(renamed){unlink(temporary.c_str());return fail(error,rename_error==EEXIST?"export_file_exists":std::strerror(rename_error));}
 error.clear();return true;
}
}
