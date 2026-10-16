package com.linux.permissionmanager.utils.repack;

import android.content.Context;
import android.graphics.drawable.Drawable;
import com.linux.permissionmanager.utils.AppCertUtils;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.Set;

/**
 * APK 生成器主入口：只负责配置校验、执行顺序和结果发布。
 * 图标、ZIP、Manifest、证书和 DEX 分别交给独立工具类处理。
 */
public final class ApkGenerator {
    private static final Pattern PERMISSION_NAME = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+");
    private ApkGenerator() {}

    /** 输入 APK 和输出 APK 由外部决定；每次 generate 都重新生成随机签名。 */
    public static final class GenerateOptions {
        public File sourceApk;               // 必传：原 APK，可以是自身 base.apk
        public File outputApk;               // 必传：输出的新 APK
        public String newPackageName;        // null 时不修改安装包名
        public String oldEntryActivityName; // 可选：原入口 Activity 完整类名；需和 newEntryActivityName 同时设置
        public String newEntryActivityName; // 可选：新入口 Activity 完整类名；会同步改 Manifest + classes*.dex
        public String newAppName;            // null 时不修改应用显示名称
        public String newVersionName;        // null 时不修改 versionName
        public Integer newVersionCode;       // null 时不修改 versionCode，正整数
        public Long targetApkSize;           // null 不填充，仅允许指定不小于原 APK 的目标字节数
        public boolean removeAppIcon = false; // true：删除 Manifest 中图标声明
        public Drawable customIcon;            // 可选：替换 App 图标，来自 getApplicationIcon()
        public IconPaths iconPaths;            // customIcon 非 null 时必传：实际 APK ZIP 内的三个 PNG 路径
        public Map<String, byte[]> soReplacements = Collections.emptyMap(); // 可不替换 .so
        public Set<String> removePermissions = new LinkedHashSet<>(); // 可选：删除 manifest 直接子节点 uses-permission，可批量

        // 证书主体配置。默认使用预设信息；可直接指定外部读取的 AppCertUtils.CertInfo。
        public AppCertUtils.CertInfo certInfo = createDefaultCertInfo();

        private static AppCertUtils.CertInfo createDefaultCertInfo() {
            AppCertUtils.CertInfo info = new AppCertUtils.CertInfo();
            info.certCN = "APK Signer Android";
            info.certO = "Google Inc.";
            info.certOU = "Android";
            info.certL = "Mountain View";
            info.certST = "California";
            info.certC = "US";
            return info;
        }
    }


    /**
     * 动态图标模板在【编译后的 APK ZIP】中的路径，不是源码 res/ 的文件路径。
     * 调用方用 unzip -l 或 ZipFile.entries() 获取实际条目名。
     * 三个路径都必须指向当前 APK 内已存在的 .png 文件。
     */
    public static final class IconPaths {
        public final String legacyPng;
        public final String foregroundPng;
        public final String backgroundPng;

        public IconPaths(String legacyPng, String foregroundPng, String backgroundPng) {
            this.legacyPng = legacyPng;
            this.foregroundPng = foregroundPng;
            this.backgroundPng = backgroundPng;
        }
    }

    /** 在工作线程中调用；每次执行均生成全新的 RSA 密钥对和自签名证书，不持久化私钥。 */
    public static File generate(Context context, GenerateOptions options) throws Exception {
        if (context == null || options == null) throw new IllegalArgumentException("context/options == null");
        if (options.sourceApk == null || options.outputApk == null) {
            throw new IllegalArgumentException("sourceApk/outputApk 必须指定");
        }
        Set<String> safePermissions = validateRemovePermissions(options.removePermissions);
        if (options.removeAppIcon && options.customIcon != null) {
            throw new IllegalArgumentException("removeAppIcon 与 customIcon 不能同时启用");
        }
        if (options.newPackageName == null && options.newAppName == null && options.newVersionName == null && options.newVersionCode == null && options.targetApkSize == null
                && !options.removeAppIcon && options.customIcon == null
                && options.oldEntryActivityName == null && options.newEntryActivityName == null
                && (options.soReplacements == null || options.soReplacements.isEmpty()) && safePermissions.isEmpty()) {
            throw new IllegalArgumentException("未指定任何 APK 修改操作");
        }

        // 两个类名必须同时设置；禁止只改 Manifest 或只改 DEX。
        if ((options.oldEntryActivityName == null) != (options.newEntryActivityName == null)) {
            throw new IllegalArgumentException("oldEntryActivityName/newEntryActivityName 必须同时提供");
        }
        if (options.newVersionCode != null && options.newVersionCode <= 0) throw new IllegalArgumentException("newVersionCode 必须大于 0");
        if (options.targetApkSize != null && options.targetApkSize <= 0) throw new IllegalArgumentException("targetApkSize 必须大于 0");
        if (options.oldEntryActivityName != null) {
            EntryDexRenamer.validateClassName(options.oldEntryActivityName);
            EntryDexRenamer.validateClassName(options.newEntryActivityName);
            if (options.oldEntryActivityName.equals(options.newEntryActivityName)) {
                throw new IllegalArgumentException("新旧入口 Activity 类名不能相同");
            }
        }

        File source = options.sourceApk.getCanonicalFile();
        File output = options.outputApk.getCanonicalFile();
        if (!source.isFile() || !source.canRead()) throw new IOException("无法读取原始 APK: " + source);
        if (options.targetApkSize != null && options.targetApkSize < source.length()) throw new IllegalArgumentException("只允许增大 APK：目标大小不能小于原 APK 大小（" + source.length() + " 字节）");
        if (source.equals(output)) throw new IllegalArgumentException("输出路径不能覆盖原 APK");
        Map<String, byte[]> safeReplacements = new LinkedHashMap<>(ApkZipRebuilder.copyAndValidateReplacements(options.soReplacements));
        if (options.customIcon != null) {
            // PNG 数据统一由这里生成，ZIP 重打包过程只认识 ZIP 路径和字节数据。
            safeReplacements.putAll(ApkIconProcessor.renderIconReplacements(options.customIcon, options.iconPaths));
        }
        // 在耗时的 ZIP 重打包前完成校验并快照证书主体参数。
        byte[] certificateSubject = ApkRandomSigner.encodeCertificateSubject(options.certInfo);
        File outputDir = output.getParentFile();
        if (outputDir == null || (!outputDir.isDirectory() && !outputDir.mkdirs())) {
            throw new IOException("无法创建 APK 输出目录: " + outputDir);
        }

        File unsigned = File.createTempFile("apk-unsigned-", ".apk", context.getCacheDir());
        File staging = File.createTempFile("apk-signed-", ".apk", outputDir);
        try {
            ApkZipRebuilder.assertRealApk(source);
            if (options.oldEntryActivityName != null) {
                EntryDexRenamer.validateDexClasses(source, options.oldEntryActivityName, options.newEntryActivityName);
            }
            Set<String> replaced = ApkZipRebuilder.rebuildApk(source, unsigned, safeReplacements,
                    options.newPackageName, options.newAppName, options.newVersionName, options.newVersionCode,
                    options.removeAppIcon, options.oldEntryActivityName, options.newEntryActivityName, context.getCacheDir(), safePermissions);
            Set<String> missing = new LinkedHashSet<>(safeReplacements.keySet());
            missing.removeAll(replaced);
            if (!missing.isEmpty()) throw new IOException("APK 缺少以下待替换文件（请核对编译后的 ZIP 路径）: " + missing);
            if (options.targetApkSize != null) ApkZipRebuilder.increaseApkSize(unsigned, options.targetApkSize);

            // 签名证书完全由内部随机生成，ApkRandomSigner 同时负责验签。
            ApkRandomSigner.signAndVerify(unsigned, staging, certificateSubject);
            if (options.targetApkSize != null && staging.length() < options.targetApkSize) throw new IOException("签名后的 APK 未达到目标体积：" + staging.length() + " < " + options.targetApkSize);

            // 在同一文件系统优先原子覆盖旧输出，防止异常时损坏已有文件。
            try {
                java.nio.file.Files.move(staging.toPath(), output.toPath(),
                        java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                java.nio.file.Files.move(staging.toPath(), output.toPath(),
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
            return output;
        } finally {
            unsigned.delete();
            staging.delete();
        }
    }

    private static Set<String> validateRemovePermissions(Set<String> permissions) {
        if (permissions == null || permissions.isEmpty()) return Collections.emptySet();
        Set<String> result = new LinkedHashSet<>();
        for (String name : permissions) {
            if (name == null || !PERMISSION_NAME.matcher(name).matches()) throw new IllegalArgumentException("无效权限名称: " + name);
            result.add(name);
        }
        return result;
    }

}
