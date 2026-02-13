#include <iostream>
#include "kernel_module_kit_umbrella.h"

using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

KModErr run_kernel_shellcode(uint64_t & result) {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    auto a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    
    // TODO: 在此开始输入你的aarch64 asm指令
    aarch64_asm_mov_x(a, x0, 0x12345);
    kernel_module::arm64_module_asm_func_end(a, x0);
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(a);
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, result));
    return KModErr::OK;
}

/***************************************************************************
 * SKRoot 模块入口函数（必须提供）
 * 被执行时机：在 zygote64 进程启动前。
 * 参数：
 *   root_key           ROOT 密钥文本。
 *   module_private_dir	模块私有目录（受隐藏保护；需隐藏的文件请放在此目录）。
 * 返回值：默认 0；任意返回值仅记录到日志，便于排查。
 * 说明：skroot_module_main 返回后，代表本模块执行结束。如需继续运行请fork();
 ***************************************************************************/
int skroot_module_main(const char* root_key, const char* module_private_dir) {
    printf("[module_hello_world] starting... \n");
    printf("[module_hello_world] root_key len=%zu\n", strlen(root_key));
    printf("[module_hello_world] module_private_dir=%s\n", module_private_dir);

    // 开始执行内核shellcode。
    uint64_t result = 0;
	KModErr err = run_kernel_shellcode(result);
    printf("run_kernel_shellcode err: %s\n", to_string(err).c_str());
    printf(result == 0x12345 ? "OK" : "FAILED");
    printf("\n");
    return (int)result;
}

// SKRoot 模块名片
SKROOT_MODULE_NAME("演示模块名称")	// 在此填写模块名称
SKROOT_MODULE_VERSION("1.0.0")		// 在此填写模块版本号
SKROOT_MODULE_DESC("演示模块描述")	// 在此填写模块描述文本
SKROOT_MODULE_AUTHOR("演示作者名字") // 在此填写模块作者
SKROOT_MODULE_UUID32("3608c9af28db4dcfc05c32bbc584753e") // 在此填写模块UUID，32个随机字符 [0-9a-zA-Z]