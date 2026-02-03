#pragma once
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include "private_mod_api_runtime_helper.h"
#include "private_skroot_api_runtime_helper.h"
#include "../module_web_ui_http_handler.h"
#include "../module_base_install_callback.h"

#define ____INTERNEL_SKROOT_MODULE_MAIN __skroot_module_main_18fdf393885363712349ef3de5411bd5
inline char skroot_module_name_5d1745f8a8fb4814fb0dbb5aab27bbca[1024] = {0};
#define ___MOD_NAME_TAG_BEGIN  "de1f663bcae792d7c9ed1a21cdaeff00331fe11b074f0303e018f43998f8db3e"
#define ___MOD_NAME_TAG_END    "04429c3f7172e4cce7ac7a5d44b75631ce91777b5f2a5eec076a3a508a76fb17"
#define ___MOD_NAME(val) \
    extern "C" void Error_Missing_SKRoot_Module_Name__Please_define_SKROOT_MODULE_NAME() { \
        strncpy(skroot_module_name_5d1745f8a8fb4814fb0dbb5aab27bbca, ___MOD_NAME_TAG_BEGIN val ___MOD_NAME_TAG_END, sizeof(skroot_module_name_5d1745f8a8fb4814fb0dbb5aab27bbca) - 1); \
    }; \
    extern "C" __attribute__((visibility("default"))) __attribute__((used, weak)) int ____INTERNEL_SKROOT_MODULE_MAIN(const char* root_key, const char* module_private_dir) { \
        extern void Error_Missing_SKRoot_Module_Name__Please_define_SKROOT_MODULE_NAME(); \
        extern void Error_Missing_SKRoot_Module_Version__Please_define_SKROOT_MODULE_VERSION(); \
        extern void Error_Missing_SKRoot_Module_Descriptor__Please_define_SKROOT_MODULE_DESC(); \
        extern void Error_Missing_SKRoot_Module_Author__Please_define_SKROOT_MODULE_AUTHOR(); \
        extern void Error_Missing_SKRoot_Module_UUID32__Please_define_SKROOT_MODULE_UUID32(); \
        Error_Missing_SKRoot_Module_Name__Please_define_SKROOT_MODULE_NAME(); \
        Error_Missing_SKRoot_Module_Version__Please_define_SKROOT_MODULE_VERSION();  \
        Error_Missing_SKRoot_Module_Descriptor__Please_define_SKROOT_MODULE_DESC();  \
        Error_Missing_SKRoot_Module_Author__Please_define_SKROOT_MODULE_AUTHOR();  \
        Error_Missing_SKRoot_Module_UUID32__Please_define_SKROOT_MODULE_UUID32();  \
        if(strlen(skroot_module_name_5d1745f8a8fb4814fb0dbb5aab27bbca) == 0) printf("");  \
        if(strlen(skroot_module_ver_61432c728da7c34d7fd698461a36a421) == 0) printf("");  \
        if(strlen(skroot_module_desc_c658b5f0a346f94d52b96379fc26b0c4) == 0) printf(""); \
        if(strlen(skroot_module_author_857d43a4f1978f830f6a2dc91d840338) == 0) printf(""); \
        if(strlen(skroot_module_uuid_927fa0e9f491cdcbd07e8a647f09e1e2) == 0) printf(""); \
        if(strlen(skroot_module_update_json_7310fa0a06d95799b3f9beaf60e26e85) == 0) printf(""); \
        extern void __compile_save_min_support_sdk_ver(void); \
        __compile_save_min_support_sdk_ver(); \
        extern void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(const char*); \
        __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(root_key); \
        return skroot_module_main(root_key, module_private_dir); \
    }

inline char skroot_module_ver_61432c728da7c34d7fd698461a36a421[1024] = {0};
#define ___MOD_VERSION_TAG_BEGIN  "7dc74a2b86805f2cd0f45c6a82d384fd568e341c6f05af17c7229c9ba6d4318b"
#define ___MOD_VERSION_TAG_END    "8dbc019a6e51fe8d4a3db9feaf05535d70879f35626050cd4131bfe323ecefc2"
#define ___MOD_VERSION(val) \
    extern "C" void Error_Missing_SKRoot_Module_Version__Please_define_SKROOT_MODULE_VERSION() { \
        strncpy(skroot_module_ver_61432c728da7c34d7fd698461a36a421, ___MOD_VERSION_TAG_BEGIN val ___MOD_VERSION_TAG_END, sizeof(skroot_module_ver_61432c728da7c34d7fd698461a36a421) - 1); \
    };
    
inline char skroot_module_desc_c658b5f0a346f94d52b96379fc26b0c4[1024] = {0};
#define ___MOD_DESC_TAG_BEGIN  "05c62cd446c811e772c94d97fd546738328f7c6b9967ed135190ef37ff06d866"
#define ___MOD_DESC_TAG_END    "ed02c95e091c66100d6f2f4554f96392b2951b394ba042278eed8f236f43e1a3"
#define ___MOD_DESC(val) \
    extern "C" void Error_Missing_SKRoot_Module_Descriptor__Please_define_SKROOT_MODULE_DESC() { \
        strncpy(skroot_module_desc_c658b5f0a346f94d52b96379fc26b0c4, ___MOD_DESC_TAG_BEGIN val ___MOD_DESC_TAG_END, sizeof(skroot_module_desc_c658b5f0a346f94d52b96379fc26b0c4) - 1); \
    };
    
inline char skroot_module_author_857d43a4f1978f830f6a2dc91d840338[1024] = {0};
#define ___MOD_AUTHOR_TAG_BEGIN  "1f39b220291a2fb6e4fec95f179d0faf833ca534ef8ab2ffc4bd893768694451"
#define ___MOD_AUTHOR_TAG_END    "d409c886fd6cedd694c1b126fd19eccd90e2463e04154c193effc7103ce63f1c"
#define ___MOD_AUTHOR(val) \
    extern "C" void Error_Missing_SKRoot_Module_Author__Please_define_SKROOT_MODULE_AUTHOR() { \
        strncpy(skroot_module_author_857d43a4f1978f830f6a2dc91d840338, ___MOD_AUTHOR_TAG_BEGIN val ___MOD_AUTHOR_TAG_END, sizeof(skroot_module_author_857d43a4f1978f830f6a2dc91d840338) - 1); \
    };
    
inline char skroot_module_uuid_927fa0e9f491cdcbd07e8a647f09e1e2[1024] = {0};
#define ___MOD_UUID32_TAG_BEGIN  "b33dcddd88c07d079a8e0e9ec6ab976f15f2edba46cab91a61234cfbb982111c"
#define ___MOD_UUID32_TAG_END    "3020d9a6c07a30e2649dd29a72d7e57121f0c0ca457b6d21dca5a69acbe6c2c4"
#define ___MOD_UUID32(val) \
    template <std::size_t N> \
    consteval void uuid32_check_bd8a9bbb16b9b755b96a9f2bc0114e13(const char (&s)[N]) { \
        static_assert(N == 33, "SKROOT_MODULE_UUID32: 长度必须为32个字符"); \
    } \
    extern "C" void Error_Missing_SKRoot_Module_UUID32__Please_define_SKROOT_MODULE_UUID32() { \
        uuid32_check_bd8a9bbb16b9b755b96a9f2bc0114e13(val); \
        strncpy(skroot_module_uuid_927fa0e9f491cdcbd07e8a647f09e1e2, ___MOD_UUID32_TAG_BEGIN val ___MOD_UUID32_TAG_END, sizeof(skroot_module_uuid_927fa0e9f491cdcbd07e8a647f09e1e2) - 1); \
        extern void __set_current_module_uuid32_1b0494ae8a788541db46b82cc1f0577c(const char*); \
        __set_current_module_uuid32_1b0494ae8a788541db46b82cc1f0577c(val); \
    };
    
inline char skroot_module_update_json_7310fa0a06d95799b3f9beaf60e26e85[1024] = {0};
#define ___MOD_UPDATE_JSON_TAG_BEGIN  "4363a6368f39d93cabadc121f9bfa51626da9f19699b68470d7a4fd46a9ad541"
#define ___MOD_UPDATE_JSON_TAG_END    "9f2efdc4b7e133634ec4c1ecd85975f560be89962733a0a7b228f1160d8d0ebc"
#define ___MOD_UPDATE_JSON(val) \
    inline int ____skroot_update_json_reg_token_4217f56a580ff098290dfd8c50aa11b9 = []() { \
        strncpy(skroot_module_update_json_7310fa0a06d95799b3f9beaf60e26e85, ___MOD_UPDATE_JSON_TAG_BEGIN val ___MOD_UPDATE_JSON_TAG_END, sizeof(skroot_module_update_json_7310fa0a06d95799b3f9beaf60e26e85) - 1); \
        return 0; \
    }();

inline kernel_module::WebUIHttpHandler* skroot_web_ui_handler_6f9d89cc84c2ea1bf7364fc1afda99b5 = nullptr;
inline char skroot_web_ui_enable_flag_e0c73f6473a0e653be67875a3cf23a53[1024] = {0};
#define ___MOD_WEB_UI_FLAG_BEGIN "8af75246e3afc7bd603439f7d241de26"
#define ___MOD_WEB_UI_FLAG_END "f8d65c7fde28dbbbad9926ce0bdb16bc"
#define ___MOD_WEB_UI(HttpHandlerClass) \
    inline HttpHandlerClass __skroot_web_ui_handler_a36c64badf0f0cb63a14b0229738d955;   \
    inline int ____skroot_web_ui_reg_token_e451c82c405b3e5f5c7f1e635742e544 = []() { \
        skroot_web_ui_handler_6f9d89cc84c2ea1bf7364fc1afda99b5 = &__skroot_web_ui_handler_a36c64badf0f0cb63a14b0229738d955; \
        strncpy(skroot_web_ui_enable_flag_e0c73f6473a0e653be67875a3cf23a53, ___MOD_WEB_UI_FLAG_BEGIN ___MOD_WEB_UI_FLAG_END, sizeof(skroot_web_ui_enable_flag_e0c73f6473a0e653be67875a3cf23a53) - 1); \
        return 0; \
    }();

#define ____INTERNEL_SKROOT_MODULE_ON_INSTALL __skroot_module_on_install_k6JkibrjUwzXFpshvFuIwdUNRP4fYtLA
inline decltype(&module_on_install) skroot_module_on_install_func_jngvokk4mlkkwbg92nj1u7vkhyjan2qj = nullptr;
inline char skroot_module_on_install_enable_flag_wnx27u34cpuazxit73f52qkylnq89f3s[1024] = {0};
#define ___MOD_ON_INSTALL_FLAG_BEGIN "za5hrnp5r0rjm1dnjld7xoc6tza0qvdd"
#define ___MOD_ON_INSTALL_FLAG_END "v2ltlw5plpqec7yr5ifeuta24l3rv7ep"
#define ___MOD_ON_INSTALL(callback) \
    inline int ____skroot_module_on_install_reg_token_bdc5immbyggdvjc8qh0vk817i8hfd74f = []() { \
        skroot_module_on_install_func_jngvokk4mlkkwbg92nj1u7vkhyjan2qj = &callback; \
        strncpy(skroot_module_on_install_enable_flag_wnx27u34cpuazxit73f52qkylnq89f3s, ___MOD_ON_INSTALL_FLAG_BEGIN ___MOD_ON_INSTALL_FLAG_END, sizeof(skroot_module_on_install_enable_flag_wnx27u34cpuazxit73f52qkylnq89f3s) - 1); \
        return 0; \
    }();\
    extern "C" __attribute__((visibility("default"))) __attribute__((used, weak)) void ____INTERNEL_SKROOT_MODULE_ON_INSTALL(const char* root_key, const char* module_private_dir, void (*cb)(const char* reason)) { \
        if(!skroot_module_on_install_func_jngvokk4mlkkwbg92nj1u7vkhyjan2qj) return;\
        extern void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(const char*); \
        __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(root_key); \
        cb(skroot_module_on_install_func_jngvokk4mlkkwbg92nj1u7vkhyjan2qj(root_key, module_private_dir).c_str()); \
    };

#define ____INTERNEL_SKROOT_MODULE_ON_UNINSTALL __skroot_module_on_uninstall_epmoso85hw4w1rzjagiuzdmnyqamk7ep
inline decltype(&module_on_uninstall) skroot_module_on_uninstall_func_lv5biogiKlWBDvrs1clgywqMPwmqXkry = nullptr;
inline char skroot_module_on_uninstall_enable_flag_ngln4z5zaku6lil4vrz2jtpoecb64avp[1024] = {0};
#define ___MOD_ON_UNINSTALL_FLAG_BEGIN "hft0lrndcqfoff3vankyj5drv30apccd"
#define ___MOD_ON_UNINSTALL_FLAG_END "p6tv4rinog5a0rl83tzp2ac6fl0uyqhk"
#define ___MOD_ON_UNINSTALL(callback) \
    inline int ____skroot_module_on_uninstall_reg_token_hu8jz8grph4qiicr6lrexkkgamy6dvaw = []() { \
        skroot_module_on_uninstall_func_lv5biogiKlWBDvrs1clgywqMPwmqXkry = &callback; \
        strncpy(skroot_module_on_uninstall_enable_flag_ngln4z5zaku6lil4vrz2jtpoecb64avp, ___MOD_ON_UNINSTALL_FLAG_BEGIN ___MOD_ON_UNINSTALL_FLAG_END, sizeof(skroot_module_on_uninstall_enable_flag_ngln4z5zaku6lil4vrz2jtpoecb64avp) - 1); \
        return 0; \
    }();\
    extern "C" __attribute__((visibility("default"))) __attribute__((used, weak)) void ____INTERNEL_SKROOT_MODULE_ON_UNINSTALL(const char* root_key, const char* module_private_dir) { \
        if(!skroot_module_on_uninstall_func_lv5biogiKlWBDvrs1clgywqMPwmqXkry) return;\
        extern void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(const char*); \
        __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(root_key); \
        skroot_module_on_uninstall_func_lv5biogiKlWBDvrs1clgywqMPwmqXkry(root_key, module_private_dir); \
    };


#ifndef FOLDER_HEAD_ROOT_KEY_LEN
#define FOLDER_HEAD_ROOT_KEY_LEN 16
#endif

#define ____INTERNEL_SKROOT_MODULE_WEB_UI_MAIN __skroot_module_web_ui_main_ceb6f0bbebe5c8978eb2168799aa0ca4
#define ____INTERNEL_SKROOT_MODULE_LAST_WEB_UI_SERVER_PORT __skroot_module_last_web_ui_server_port_db2a2bebe2b190482ad0ac73996c7b86
extern "C" __attribute__((visibility("default"))) __attribute__((used, weak)) void ____INTERNEL_SKROOT_MODULE_WEB_UI_MAIN(const char* root_key, const char* module_private_dir, const char* module_webroot_dir, const char* mod_uuid, int port, KModErr& err) {
    if(strlen(skroot_web_ui_enable_flag_e0c73f6473a0e653be67875a3cf23a53) == 0) printf("");
    KModErr unsafe_module_start_web_ui_server(const char* root_key, const char* module_private_dir, const char* module_webroot_dir, const char* mod_uuid, kernel_module::WebUIHttpHandler* handler, int port);
    err = unsafe_module_start_web_ui_server(root_key, module_private_dir, module_webroot_dir, mod_uuid, skroot_web_ui_handler_6f9d89cc84c2ea1bf7364fc1afda99b5, port);
}

extern "C" __attribute__((visibility("default"))) __attribute__((used, weak)) void ____INTERNEL_SKROOT_MODULE_LAST_WEB_UI_SERVER_PORT(int& out_port, KModErr& err) {
    if(strlen(skroot_web_ui_enable_flag_e0c73f6473a0e653be67875a3cf23a53) == 0) printf("");
    KModErr unsafe_module_get_last_web_ui_server_port(int& out_port);
    err = unsafe_module_get_last_web_ui_server_port(out_port);
}

#ifdef KERNEL_MODULE_KIT_TEST
    extern "C" int fake_skroot_module_main(const char* root_key) {
        extern void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(const char*);
        __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(root_key);
        extern void __set_current_module_uuid32_1b0494ae8a788541db46b82cc1f0577c(const char*);
        __set_current_module_uuid32_1b0494ae8a788541db46b82cc1f0577c("u5BcRRTUwMqU6A6iLkG90jTEq8EXShrE");
        return 0;
    }
#endif