#include <set>

#include "file_utils.h"
#include "patch_c_show.h"
#include "kernel_module_kit_umbrella.h"

#define FAKE_CPUINFO_FILENAME "fake_cpuinfo.txt"

using namespace file_utils;
struct simple_seq_operations {
	uint64_t start = 0;
	uint64_t next = 0;
	uint64_t stop = 0;
	uint64_t show = 0;
};

static KModErr patch_kernel_handler(const std::string& fake_cpuinfo) {
    uint64_t cpuinfo_op = 0;
    RETURN_IF_ERROR(kernel_module::kallsyms_lookup_name("cpuinfo_op", cpuinfo_op));
    printf("cpuinfo_op: %lx\n", cpuinfo_op);

    uint64_t c_show = 0;
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(cpuinfo_op + offsetof(simple_seq_operations, show), &c_show, sizeof(c_show)));
    printf("c_show: %lx\n", c_show);

    PatchBase patchBase;
    PatchCShow patchCShow(patchBase, c_show);
    KModErr err = patchCShow.patch_c_show(fake_cpuinfo);
    return err;
}

// SKRoot模块入口函数
int skroot_module_main(const char* root_key, const char* module_private_dir) {
    std::string fake_cpuinfo;
    read_text_file(FAKE_CPUINFO_FILENAME, fake_cpuinfo);
    printf("fake_cpuinfo len:%zu\n", fake_cpuinfo.length());
    KModErr err = patch_kernel_handler(fake_cpuinfo);
    printf("patch_kernel_handler ret:%s\n", to_string(err).c_str());
    return is_ok(err) ? 0 : -1;
}

// SKRoot 模块名片
// 字段说明见 module_descriptor.h
SKROOT_MODULE_NAME("伪装CPU信息为麒麟9000s")
SKROOT_MODULE_VERSION("1.0.0")
SKROOT_MODULE_DESC("内核级伪装/proc/cpuinfo为麒麟9000s，无挂载。有的娱乐App成功欺骗，有的娱乐App会提示环境异常。【安全提示】测试本模块时，请勿直接上大号，务必先用小号尝试！")
SKROOT_MODULE_AUTHOR("SKRoot & Auto")
SKROOT_MODULE_ID32("DrAofKWAYs3XO0Js4YBzB3ecqMQVdzkH")
SKROOT_MODULE_UPDATE_JSON("https://abcz316.github.io/SKRoot-linuxKernelRoot/module_fake_device/auto_fake_cpuinfo_update.json")