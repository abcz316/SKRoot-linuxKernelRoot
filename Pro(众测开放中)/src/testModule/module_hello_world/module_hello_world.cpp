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
 * 
 * 执行时机：本入口函数会在 Android 早期阶段执行，此时 Zygote64 尚未启动。
 * 
 * 参数：
 *   root_key            ROOT 密钥文本。
 *   module_private_dir  模块私有目录（受隐藏保护；需要隐藏的文件建议放在此目录）。
 * 
 * 返回值：
 *   0    表示模块入口正常结束；
 *   非0  表示模块执行异常，返回值会记录到日志，便于排查。
 *
 * 使用说明：
 *   该入口应以快速、无阻塞的代码为主，并在执行后尽快返回。
 *
 *   适合直接执行：
 *   - 安装内核 Hook；
 *   - 修改 Android 系统属性；
 *   - 不依赖系统服务的初始化操作。
 *
 *   建议 fork() 到后台后执行：
 *   - 网络请求、大量文件扫描等耗时操作；
 *   - 依赖 Android Framework、Binder 服务或应用进程的操作；
 *   - 持续运行的监控、守护及其他业务逻辑；
 *   - 循环等待或其他可能长时间占用入口的操作。
 *
 *   后台子进程应先等待约 5～10 秒，或确认系统环境已就绪后再继续执行，以免影响系统启动。
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
// 字段说明见 module_descriptor.h
SKROOT_MODULE_NAME("演示模块名称")
SKROOT_MODULE_VERSION("1.0.0")
SKROOT_MODULE_DESC("演示模块描述")
SKROOT_MODULE_AUTHOR("演示作者名字")
SKROOT_MODULE_ID32("3608c9af28db4dcfc05c32bbc584753e")