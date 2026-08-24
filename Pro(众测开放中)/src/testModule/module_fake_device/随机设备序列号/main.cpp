#include <iostream>
#include <string>
#include <sstream>
#include <string_view>
#include <random>
#include <cctype>
#include "kernel_module_kit_umbrella.h"

#include "resetprop_helper.h"
#include "patch_soc_info_show.h"
#include "patch_msm_get_serial_number.h"
#include "boot_session_utils.h"

#define MODULE_DESC_CN_TEXT "随机伪装硬件序列号(ro.serialno)、内核级伪装高通serial_number，无挂载"

static std::string generate_new_sn(std::string_view original_sn);
static std::string generate_new_sn_safe_numeric(std::string_view original_sn);
using SnGenerator = std::string (*)(std::string_view);
struct PropertySpoofItem {
    const char* property_name;
    const char* storage_key;
    SnGenerator generator;
};
static constexpr PropertySpoofItem kPropertySpoofItems[] = {
    { "ro.serialno",           "new_sn",          generate_new_sn },
    { "ro.boot.emmcid",        "new_emmcid",      generate_new_sn },
    { "ro.boot.bootload_sn",   "new_bootload_sn", generate_new_sn },
};

// 生成新序列号的核心函数
static std::string generate_new_sn(std::string_view original_sn) {
    // 使用 thread_local 保证在多线程环境下安全，且只初始化一次随机数引擎
    thread_local std::random_device rd;
    thread_local std::mt19937 gen(rd());
    
    // 定义随机数分布范围
    std::uniform_int_distribution<int> dist_digit(0, 9);
    std::uniform_int_distribution<int> dist_alpha(0, 25);

    std::string new_sn;
    // 提前分配内存，避免字符串在追加过程中发生动态重分配，追求极致性能
    new_sn.reserve(original_sn.size());

    for (char ch : original_sn) {
        char new_char = ch;
        
        // 注意：传入 cctype 系列函数的 char 需要强转为 unsigned char 以避免 UB (未定义行为)
        if (std::isdigit(static_cast<unsigned char>(ch))) {
            do {
                new_char = '0' + dist_digit(gen);
            } while (new_char == ch);
        } 
        else if (std::islower(static_cast<unsigned char>(ch))) {
            do {
                new_char = 'a' + dist_alpha(gen);
            } while (new_char == ch);
        } 
        else if (std::isupper(static_cast<unsigned char>(ch))) {
            do {
                new_char = 'A' + dist_alpha(gen);
            } while (new_char == ch);
        }
        
        // 其他符号（如连字符等）不作处理，直接追加
        new_sn.push_back(new_char);
    }

    return new_sn;
}

static std::string generate_new_sn_safe_numeric(std::string_view original_sn) {
    thread_local std::mt19937 gen(std::random_device{}());

    std::uniform_int_distribution<int> dist_digit(0, 9);
    std::uniform_int_distribution<int> dist_digit_nonzero(1, 9);
    std::uniform_int_distribution<int> dist_digit_u32_first(1, 3);
    std::uniform_int_distribution<int> dist_alpha(0, 25);

    std::string new_sn;
    new_sn.reserve(original_sn.size());

    bool all_digits = !original_sn.empty();
    for (char ch : original_sn) {
        if (!std::isdigit(static_cast<unsigned char>(ch))) {
            all_digits = false;
            break;
        }
    }

    for (size_t i = 0; i < original_sn.size(); ++i) {
        char ch = original_sn[i];
        char new_char = ch;
        unsigned char uch = static_cast<unsigned char>(ch);

        if (std::isdigit(uch)) {
            do {
                if (all_digits && original_sn.size() == 10 && i == 0) {
                    // 10位纯数字时，首位限制到 1~3，保证不会超过 uint32_t 最大值
                    new_char = static_cast<char>('0' + dist_digit_u32_first(gen));
                } else if (all_digits && original_sn.size() > 1 && i == 0 && ch != '0') {
                    // 尽量避免首位变成 0，保持外观像正常数字
                    new_char = static_cast<char>('0' + dist_digit_nonzero(gen));
                } else {
                    new_char = static_cast<char>('0' + dist_digit(gen));
                }
            } while (new_char == ch);
        } else if (std::islower(uch)) {
            do {
                new_char = static_cast<char>('a' + dist_alpha(gen));
            } while (new_char == ch);
        } else if (std::isupper(uch)) {
            do {
                new_char = static_cast<char>('A' + dist_alpha(gen));
            } while (new_char == ch);
        }

        new_sn.push_back(new_char);
    }

    return new_sn;
}

static void generate_and_store_property(const PropertySpoofItem& item) {
    const std::string old_value = get_system_property(item.property_name);
    if (old_value.empty()) {
        printf("%s is empty, skip\n", item.property_name);
        return;
    }
    const std::string new_value = item.generator(old_value);
    printf("old %s: %s\n", item.property_name, old_value.c_str());
    printf("new %s: %s\n", item.property_name, new_value.c_str());
    kernel_module::write_string_disk_storage(item.storage_key, new_value.c_str());
}

static void load_and_apply_property(const PropertySpoofItem& item) {
    const std::string old_value = get_system_property(item.property_name);
    std::string new_value;
    kernel_module::read_string_disk_storage(item.storage_key, new_value);
    printf("old %s: %s\n", item.property_name, old_value.c_str());
    printf("new %s: %s\n", item.property_name, new_value.c_str());
    if (new_value.empty()) return;
    resetprop::set_property_value(item.property_name, new_value.c_str(), ResetPropMode::kNoTrigger);
}

static KModErr patch_kernel_handler(const std::string& fake_soc_sn) {
    using SymbolMatchMode = kernel_module::SymbolMatchMode;
	using SymbolHit = kernel_module::SymbolHit;
    uint64_t soc_info_show = 0;
    SymbolHit msm_get_serial_number = {0};
    kernel_module::kallsyms_lookup_name("soc_info_show", soc_info_show);
	kernel_module::kallsyms_lookup_name("socinfo:msm_get_serial_number", msm_get_serial_number, SymbolMatchMode::Prefix);
	printf("soc_info_show: %lx\n", soc_info_show);
	printf("%s: %lx\n", msm_get_serial_number.name[0] ? msm_get_serial_number.name : "socinfo:msm_get_serial_number",
       msm_get_serial_number.addr);

    if(!soc_info_show && !msm_get_serial_number.addr) return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;

    PatchBase patchBase;
    if(soc_info_show) {
        PatchSocInfoShow patchSocInfoShow(patchBase, soc_info_show);
        KModErr err = patchSocInfoShow.patch_soc_info_show(fake_soc_sn);
        printf("patch soc_info_show ret: %s\n", to_string(err).c_str());
        RETURN_IF_ERROR(err);
    }
    if(msm_get_serial_number.addr) {
        PatchMsmGetSerialNumber patchMsmGetSerialNumber(patchBase, msm_get_serial_number.addr);
        KModErr err = patchMsmGetSerialNumber.patch_msm_get_serial_number(fake_soc_sn);
        printf("patch msm_get_serial_number ret: %s\n", to_string(err).c_str());
        RETURN_IF_ERROR(err);
    }
    return KModErr::OK;
}

static std::string read_soc_sn() {
    constexpr const char* kPath = "/sys/devices/soc0/serial_number";
    int fd = ::open(kPath, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return {};
    std::string sn;
    char buf[256];
    while (true) {
        ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n > 0) {
            sn.append(buf, static_cast<size_t>(n));
            continue;
        }
        if (n == 0) break;
        if (errno == EINTR) continue;
        ::close(fd);
        return {};
    }
    ::close(fd);
    while (!sn.empty() && (sn.back() == '\n' || sn.back() == '\r')) sn.pop_back();
    return sn;
}

static bool verify_properties() {
    for (const auto& item : kPropertySpoofItems) {
        std::string expected_value;
        kernel_module::read_string_disk_storage(item.storage_key, expected_value);
        // 这个属性本来就不存在 / 安装时没有生成，直接跳过
        if (expected_value.empty()) continue;

        const std::string actual_value = get_system_property(item.property_name);
        if (actual_value != expected_value) {
            printf("verify %s failed, expected: %s, actual: %s\n", item.property_name, expected_value.c_str(), actual_value.c_str());
            return false;
        }
    }
    return true;
}

// SKRoot模块入口函数
int skroot_module_main(const char* root_key, const char* module_private_dir) {
    std::string first_install_boot_session;
    kernel_module::read_string_disk_storage("first_install_boot_session", first_install_boot_session);
    if(boot_session_utils::read_boot_session() == first_install_boot_session) {
        printf("Please restart your phone and try again\n");
        return -1;
    }
    
    kernel_module::set_current_module_description(MODULE_DESC_CN_TEXT);
    std::string resetprop_bin_path = std::string(module_private_dir) + "resetprop";
    resetprop::init(resetprop_bin_path);

    for (const auto& item : kPropertySpoofItems) {
        load_and_apply_property(item);
    }
    if(!verify_properties()) {
        printf("verify properties failed\n");
        kernel_module::set_current_module_description("设置失败，请查看日志");
        return -1;
    }
    printf("verify properties success\n");

    std::string old_soc_sn = read_soc_sn();
    std::string new_soc_sn;
    kernel_module::read_string_disk_storage("new_soc_sn", new_soc_sn);
    printf("old soc sn: %s\n", old_soc_sn.c_str());
    printf("new soc sn: %s\n", new_soc_sn.c_str());
    if(!new_soc_sn.empty()) {
        KModErr err = patch_kernel_handler(new_soc_sn);
        if(is_failed(err)) return -1;
        if(old_soc_sn != new_soc_sn) {
            printf("ERROR, SOC SN are different.\n");
            return -1;
        }   
    }
    return 0;
}


std::string module_on_install(const char* root_key, const char* module_private_dir) {
    printf("welcome modify sn module!\n");
    for (const auto& item : kPropertySpoofItems) {
        generate_and_store_property(item);
    }
    std::string old_soc_sn = read_soc_sn();
    if (!old_soc_sn.empty()) {
        std::string new_soc_sn = generate_new_sn_safe_numeric(old_soc_sn);
        printf("old soc sn: %s\n", old_soc_sn.c_str());
        printf("new soc sn: %s\n", new_soc_sn.c_str());
        kernel_module::write_string_disk_storage("new_soc_sn", new_soc_sn.c_str());
    }
    kernel_module::set_current_module_run_state(skroot_env::ModuleRunState::Abnormal);
    kernel_module::set_current_module_description("【注意】首次使用，需重启手机后才生效！！！！！");
    kernel_module::write_string_disk_storage("first_install_boot_session", boot_session_utils::read_boot_session().c_str());
    return "";
}
// SKRoot 模块名片
// 字段说明见 module_descriptor.h
SKROOT_MODULE_NAME("随机设备序列号")
SKROOT_MODULE_VERSION("1.0.2")
SKROOT_MODULE_DESC(MODULE_DESC_CN_TEXT)
SKROOT_MODULE_AUTHOR("SKRoot & 蜃 & 杨")
SKROOT_MODULE_ON_INSTALL(module_on_install)
SKROOT_MODULE_ID32("mZ0lUavxLGTMnwCRDlnSyAZPmZUZpgI0")
SKROOT_MODULE_UPDATE_JSON("https://abcz316.github.io/SKRoot-linuxKernelRoot/module_fake_device/modify_ro_serialno_update.json")