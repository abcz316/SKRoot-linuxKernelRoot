#ifndef ONEPLUS_BYPASS_BRIDGE_H
#define ONEPLUS_BYPASS_BRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 在 SELinux 变成 permissive 之后调用（见 uaf_plant.c 的 selinux 阶段）。
 * 返回 0 表示非 OPlus 设备或绕过成功，非 0 是 kit 的错误码。
 */
int check_oplus_device_bypass(void);

#ifdef __cplusplus
}
#endif

#endif /* ONEPLUS_BYPASS_BRIDGE_H */
