package com.linux.permissionmanager.hotload;

import com.linux.permissionmanager.utils.FileUtils;

import java.io.File;

/**
 * 热启动引导脚本生成。只做字符串/字节拼接，不依赖 Activity。
 */
public final class GuideScripts {

    private GuideScripts() {}

    public static String getCve2026_43499(File ghostSo) {
        String absPath = ghostSo.getAbsolutePath();
        return "#!/system/bin/sh\n" +
                "SCRIPT_PATH=$(realpath \"$0\")\n" +
                "if [ \"$(id -u)\" -ne 0 ]; then\n" +
                "    echo \"[+] Currently not in root privileges, requesting root authorization to rerun the script...\"\n" +
                "    echo \"[DEBUG] argv1 pre-check: $(stat -c '%s' \"$SCRIPT_PATH\" 2>&1)\"\n" +
                "    " + absPath + " \"$SCRIPT_PATH\" \"$SCRIPT_PATH\"\n" +
                "    exit 0\n" +
                "fi\n";
    }

    public static String getCve2026_98260(File ghostSo, String script) {
        byte[] ghostBytes;
        try {
            // adb shell 读不到 nativeLibraryDir，只能由 App 自己读出来再随脚本下发
            ghostBytes = FileUtils.readFileBytes(ghostSo);
        } catch (Exception e) {
            ghostBytes = null;
        }
        if (ghostBytes == null || ghostBytes.length == 0) {
            return "#!/system/bin/sh\n" +
                    "echo \"[!] Failed to read " + ghostSo.getName() + ", please reinstall the APP.\"\n" +
                    "exit 1\n";
        }

        final String shPath = "/data/local/tmp/skroot_cve98260.sh";
        final String soPath = "/data/local/tmp/skroot_cve98260.so";
        final String heredocTag = "__SKROOT_98260_PAYLOAD_EOF__";
        final String soHeredocTag = "__SKROOT_98260_SO_EOF__";
        String scriptText = script.endsWith("\n") ? script : script + "\n";
        String soBase64 = FileUtils.toBase64Lines(ghostBytes, 76);

        return "#!/system/bin/sh\n" +
                "SH_PATH=\"" + shPath + "\"\n" +
                "SO_PATH=\"" + soPath + "\"\n" +
                "\n" +
                "echo \"[+] Releasing script to $SH_PATH ...\"\n" +
                "rm -f \"$SH_PATH\" \"$SH_PATH.ko\" 2>/dev/null\n" +
                "cat > \"$SH_PATH\" << '" + heredocTag + "'\n" +
                scriptText +
                heredocTag + "\n" +
                "if [ ! -s \"$SH_PATH\" ]; then\n" +
                "    echo \"[!] Failed to release script: $SH_PATH\"\n" +
                "    exit 1\n" +
                "fi\n" +
                "chmod 755 \"$SH_PATH\"\n" +
                "\n" +
                "echo \"[+] Releasing exploit to $SO_PATH ...\"\n" +
                "rm -f \"$SO_PATH\" 2>/dev/null\n" +
                "base64 -d > \"$SO_PATH\" << '" + soHeredocTag + "'\n" +
                soBase64 +
                soHeredocTag + "\n" +
                "if [ \"$(stat -c '%s' \"$SO_PATH\" 2>/dev/null)\" != \"" + ghostBytes.length + "\" ]; then\n" +
                "    echo \"[!] Failed to release exploit: $SO_PATH\"\n" +
                "    exit 1\n" +
                "fi\n" +
                "chmod 755 \"$SO_PATH\"\n" +
                "\n" +
                "\"$SO_PATH\" auto \"$SH_PATH\"\n" +
                "rm -f \"$SO_PATH\" 2>/dev/null\n";
    }
}
