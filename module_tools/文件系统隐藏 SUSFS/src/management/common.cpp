// SPDX-License-Identifier: GPL-2.0-only
#include "common.hpp"
#include <algorithm>
#include <charconv>
#include <cstring>
#include <limits>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <cerrno>

namespace susfs::management {
bool valid_utf8(std::string_view text) {
    for(std::size_t i=0;i<text.size();) {
        auto a=static_cast<unsigned char>(text[i++]);if(a<128)continue;
        unsigned n;std::uint32_t code,min;
        if(a>=0xc2&&a<=0xdf){n=1;code=a&31;min=0x80;}
        else if(a>=0xe0&&a<=0xef){n=2;code=a&15;min=0x800;}
        else if(a>=0xf0&&a<=0xf4){n=3;code=a&7;min=0x10000;}
        else return false;
        if(i+n>text.size())return false;
        while(n--){auto b=static_cast<unsigned char>(text[i++]);if((b&0xc0)!=0x80)return false;code=(code<<6)|(b&63);}
        if(code<min||code>0x10ffff||(code>=0xd800&&code<=0xdfff))return false;
    }
    return true;
}
Json parse_json(std::string_view text,std::string& error,std::size_t limit) {
    error.clear();auto fail=[&](const char* why){error=why;return Json(nullptr,cJSON_Delete);};
    if(text.empty()||text.size()>limit||!valid_utf8(text))return fail("invalid_json_size_or_utf8");
    unsigned depth=0;bool string=false;
    for(std::size_t i=0;i<text.size();++i) {
        const unsigned char c=text[i];if(!c)return fail("json_nul");
        if(string&&c=='\\') {
            if(i+1>=text.size())return fail("invalid_json_escape");
            if(text[i+1]=='u'&&text.substr(i+2,4)=="0000")return fail("json_nul");
            ++i;continue;
        }
        if(c=='"'){string=!string;continue;}
        if(!string&&(c=='{'||c=='[')){if(++depth>32)return fail("json_depth");}
        if(!string&&(c=='}'||c==']')){if(!depth)return fail("json_brackets");--depth;}
    }
    if(string||depth)return fail("invalid_json");
    const std::string copy(text);const char* end=nullptr;
    Json result(cJSON_ParseWithLengthOpts(copy.c_str(),copy.size()+1,&end,1),cJSON_Delete);
    if(!result)return fail("invalid_json");
    const auto unique=[](const auto& self,const cJSON* node)->bool {
        if(cJSON_IsString(node)&&(!node->valuestring||!valid_utf8(node->valuestring)))return false;
        std::set<std::string> seen;
        for(auto* child=node->child;child;child=child->next) {
            if(cJSON_IsObject(node)&&(!child->string||!valid_utf8(child->string)||!seen.insert(child->string).second))return false;
            if(!self(self,child))return false;
        }
        return true;
    };
    if(!unique(unique,result.get()))return fail("duplicate_json_key_or_utf8");
    return result;
}
bool json_keys(const cJSON* object,const std::set<std::string>& allowed,bool exact) {
    if(!cJSON_IsObject(object))return false;
    std::set<std::string> seen;
    for(auto* p=object->child;p;p=p->next)
        if(!p->string||!allowed.count(p->string)||!seen.insert(p->string).second)return false;
    return !exact||seen==allowed;
}
const cJSON* member(const cJSON* object,const char* name){return cJSON_GetObjectItemCaseSensitive(object,name);}
bool decimal(std::string_view text,std::uint64_t& value) {
    if(text.empty()||(text.size()>1&&text.front()=='0'))return false;
    auto r=std::from_chars(text.data(),text.data()+text.size(),value);
    return r.ec==std::errc{}&&r.ptr==text.data()+text.size();
}
bool signed_decimal(std::string_view text,std::int64_t& value) {
    const auto digits=text.size()&&text[0]=='-'?text.substr(1):text;
    if(digits.empty()||(digits.size()>1&&digits.front()=='0')||text=="-0")return false;
    auto r=std::from_chars(text.data(),text.data()+text.size(),value);
    return r.ec==std::errc{}&&r.ptr==text.data()+text.size();
}
bool json_string(const cJSON* value,std::string& output){if(!cJSON_IsString(value)||!value->valuestring)return false;output=value->valuestring;return valid_utf8(output);}
std::string quote(std::string_view value) {
    std::string out="\"";static constexpr char digits[]="0123456789abcdef";
    for(unsigned char c:value) {
        if(c=='"'||c=='\\'){out+='\\';out+=static_cast<char>(c);}
        else if(c<32){out+="\\u00";out+=digits[c>>4];out+=digits[c&15];}
        else out+=static_cast<char>(c);
    }
    return out+'"';
}
bool package_name(std::string_view name) {
    if(name.empty()||name.size()>255)return false;
    bool first=true;
    for(unsigned char c:name) {
        if(c=='.'){if(first)return false;first=true;continue;}
        const bool letter=(c>='a'&&c<='z')||(c>='A'&&c<='Z');
        if(!letter&&(first||!((c>='0'&&c<='9')||c=='_')))return false;
        first=false;
    }
    return !first;
}
bool canonical_path(std::string_view path) {
    if(path.size()<2||path.size()>255||path.front()!='/'||path.back()=='/'||!valid_utf8(path))return false;
    std::size_t start=1;
    for(std::size_t i=1;i<=path.size();++i) {
        if(i<path.size()&&(static_cast<unsigned char>(path[i])<32||path[i]==127))return false;
        if(i==path.size()||path[i]=='/') {
            auto part=path.substr(start,i-start);if(part.empty()||part=="."||part=="..")return false;start=i+1;
        }
    }
    return true;
}
}
