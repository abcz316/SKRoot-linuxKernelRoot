package com.linux.permissionmanager.utils.repack;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/** ZIP 条目替换、旧签名清理、未压缩 .so 16 KB 对齐。 */
final class ApkZipRebuilder {
    private static final Pattern SO_ENTRY_PATH = Pattern.compile("lib/[A-Za-z0-9_-]+/[A-Za-z0-9_.+-]+\\.so");
    private static final int PAGE_ALIGNMENT = 16 * 1024;
    private static final int FILE_ALIGNMENT = 4;
    private static final int ZIPALIGN_EXTRA_FIELD_ID = 0xD935;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] ZERO_BLOCK = new byte[64 * 1024];
    private ApkZipRebuilder() {}

    static void assertRealApk(File apk) throws IOException {
        try (ZipFile zip = new ZipFile(apk)) {
            if (zip.getEntry("AndroidManifest.xml") == null || zip.getEntry("classes.dex") == null) {
                throw new IOException("输入文件不是带有 Manifest 和 classes.dex 的基础 APK: " + apk);
            }
        }
    }

    static Map<String, byte[]> copyAndValidateReplacements(Map<String, byte[]> replacements) {
        if (replacements == null || replacements.isEmpty()) return Collections.emptyMap();
        Map<String, byte[]> result = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> entry : replacements.entrySet()) {
            String name = entry.getKey();
            if (name == null || !SO_ENTRY_PATH.matcher(name).matches()) {
                throw new IllegalArgumentException("无效的 APK .so 路径: " + name);
            }
            if (entry.getValue() == null) throw new IllegalArgumentException(".so 替换内容为 null: " + name);
            result.put(name, entry.getValue().clone());
        }
        return result;
    }

    static Set<String> rebuildApk(File inputApk, File outputApk,
                                          Map<String, byte[]> replacements,
                                          String newPackageName, String newAppName, String newVersionName, Integer newVersionCode,
                                          boolean removeAppIcon, String oldEntryActivityName, String newEntryActivityName,
                                          File cacheDir, Set<String> removePermissions) throws IOException {
        Set<String> replaced = new LinkedHashSet<>();
        try (ZipFile zin = new ZipFile(inputApk);
             PositionOutputStream counting = new PositionOutputStream(new BufferedOutputStream(new FileOutputStream(outputApk)));
             ZipOutputStream zout = new ZipOutputStream(counting)) {
            Enumeration<? extends ZipEntry> entries = zin.entries();
            while (entries.hasMoreElements()) {
                ZipEntry src = entries.nextElement();
                String name = src.getName();
                if (isOldSignatureFile(name)) continue;

                boolean replace = replacements.containsKey(name);
                boolean replaceManifest = (newPackageName != null || newAppName != null || newVersionName != null || newVersionCode != null || removeAppIcon
                        || oldEntryActivityName != null || (removePermissions != null && !removePermissions.isEmpty())) && "AndroidManifest.xml".equals(name);
                boolean replaceDex = oldEntryActivityName != null && EntryDexRenamer.isDexEntry(name);
                byte[] contents = null;
                if (replace) {
                    contents = replacements.get(name);
                } else if (replaceManifest) {
                    try (InputStream in = zin.getInputStream(src)) {
                        contents = ApkManifestEditor.patch(readLimited(in, 16 * 1024 * 1024), newPackageName, newAppName,
                                newVersionName, newVersionCode, removeAppIcon, oldEntryActivityName, newEntryActivityName);
                        if (removePermissions != null && !removePermissions.isEmpty()) contents = ApkManifestEditor.removeUsesPermissions(contents, removePermissions);
                    }
                } else if (replaceDex) {
                    try (InputStream in = zin.getInputStream(src)) {
                        // 未包含入口类的 dex 不重新序列化，避免无意义地修改所有 DEX。
                        contents = EntryDexRenamer.rewriteIfContains(
                                readLimited(in, 256 * 1024 * 1024), oldEntryActivityName,
                                newEntryActivityName, cacheDir);
                    }
                }
                boolean stored = replace || src.isDirectory() || src.getMethod() == ZipEntry.STORED;
                ZipEntry dst = new ZipEntry(name);
                if (src.getTime() >= 0) dst.setTime(src.getTime());
                if (src.getComment() != null) dst.setComment(src.getComment());

                if (stored) {
                    dst.setMethod(ZipEntry.STORED);
                    if (contents != null) {
                        CRC32 crc = new CRC32();
                        crc.update(contents);
                        dst.setSize(contents.length);
                        dst.setCompressedSize(contents.length);
                        dst.setCrc(crc.getValue());
                    } else {
                        if (src.getSize() < 0 || src.getCrc() < 0) {
                            throw new IOException("STORED entry lacks size/CRC: " + name);
                        }
                        dst.setSize(src.getSize());
                        dst.setCompressedSize(src.getSize());
                        dst.setCrc(src.getCrc());
                    }
                    // 对齐未压缩 .so 的数据偏移，签名后仍需保持对齐。
                    int align = name.endsWith(".so") ? PAGE_ALIGNMENT : FILE_ALIGNMENT;
                    dst.setExtra(createAlignmentExtra(counting.position(), name, align));
                } else if (src.getMethod() == ZipEntry.DEFLATED) {
                    dst.setMethod(ZipEntry.DEFLATED);
                } else {
                    throw new IOException("Unsupported ZIP method: " + src.getMethod() + ", " + name);
                }

                zout.putNextEntry(dst);
                if (contents != null) {
                    zout.write(contents);
                    if (replace) replaced.add(name);
                } else if (!src.isDirectory()) {
                    try (InputStream in = zin.getInputStream(src)) {
                        copy(in, zout);
                    }
                }
                zout.closeEntry();
            }
        }
        return replaced;
    }

    /**
     * 在重打包完成、签名之前调用，只允许把未签名 APK 增大到至少 targetSize 字节。
     * 填充条目为 assets/ + 4~12 位随机小写字母 + .dat 扩展名；使用 STORED，避免零字节被压缩。
     * 签名本身会继续增加少量字节，因此 targetSize 是最终 APK 的近似下限，而非精确大小。
     */
    static void increaseApkSize(File unsignedApk, long targetSize) throws IOException {
        if (unsignedApk == null || !unsignedApk.isFile()) throw new IOException("未签名 APK 不存在: " + unsignedApk);
        if (targetSize <= 0) throw new IllegalArgumentException("targetSize 必须大于 0");
        if (targetSize < unsignedApk.length()) throw new IllegalArgumentException("只允许增大 APK：目标 " + targetSize + " 字节，当前 " + unsignedApk.length() + " 字节");
        if (targetSize == unsignedApk.length()) return;

        File parent = unsignedApk.getAbsoluteFile().getParentFile();
        File temp = File.createTempFile("apk-padding-", ".apk", parent);
        try {
            String path;
            try (ZipFile zip = new ZipFile(unsignedApk)) {
                do { path = "assets/" + randomPaddingName() + ".dat"; } while (zip.getEntry(path) != null);
            }
            long paddingBytes = targetSize - unsignedApk.length();
            // 正常情况下 ZIP 新条目本身还会带来几十字节的结构开销。
            // 若重打包使其他元数据变短，则补足差额后重试，确保最终不小于 targetSize。
            for (int i = 0; i < 3; i++) {
                writePaddedZip(unsignedApk, temp, path, paddingBytes);
                if (temp.length() >= targetSize) break;
                paddingBytes += targetSize - temp.length();
            }
            if (temp.length() < targetSize) throw new IOException("APK 填充未达到目标大小");
            try { Files.move(temp.toPath(), unsignedApk.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING); }
            catch (AtomicMoveNotSupportedException e) { Files.move(temp.toPath(), unsignedApk.toPath(), StandardCopyOption.REPLACE_EXISTING); }
        } finally { if (temp.exists()) temp.delete(); }
    }

    private static String randomPaddingName() {
        int length = 4 + RANDOM.nextInt(9);
        StringBuilder name = new StringBuilder(length);
        for (int i = 0; i < length; i++) name.append((char) ('a' + RANDOM.nextInt(26)));
        return name.toString();
    }

    private static void writePaddedZip(File original, File padded, String paddingPath, long paddingBytes) throws IOException {
        if (paddingBytes < 0) throw new IllegalArgumentException("paddingBytes < 0");
        CRC32 crc = new CRC32();
        for (long remaining = paddingBytes; remaining > 0;) {
            int count = (int) Math.min(ZERO_BLOCK.length, remaining);
            crc.update(ZERO_BLOCK, 0, count);
            remaining -= count;
        }
        try (ZipFile zin = new ZipFile(original);
             PositionOutputStream counting = new PositionOutputStream(new BufferedOutputStream(new FileOutputStream(padded)));
             ZipOutputStream zout = new ZipOutputStream(counting)) {
            Enumeration<? extends ZipEntry> entries = zin.entries();
            while (entries.hasMoreElements()) {
                ZipEntry src = entries.nextElement();
                String name = src.getName();
                ZipEntry dst = new ZipEntry(name);
                if (src.getTime() >= 0) dst.setTime(src.getTime());
                if (src.getComment() != null) dst.setComment(src.getComment());
                if (src.getMethod() == ZipEntry.STORED || src.isDirectory()) {
                    if (src.getSize() < 0 || src.getCrc() < 0) throw new IOException("STORED entry 缺少大小或 CRC: " + name);
                    dst.setMethod(ZipEntry.STORED);
                    dst.setSize(src.getSize());
                    dst.setCompressedSize(src.getSize());
                    dst.setCrc(src.getCrc());
                    dst.setExtra(createAlignmentExtra(counting.position(), name, name.endsWith(".so") ? PAGE_ALIGNMENT : FILE_ALIGNMENT));
                } else if (src.getMethod() == ZipEntry.DEFLATED) {
                    dst.setMethod(ZipEntry.DEFLATED);
                } else {
                    throw new IOException("Unsupported ZIP method: " + src.getMethod() + ", " + name);
                }
                zout.putNextEntry(dst);
                if (!src.isDirectory()) try (InputStream in = zin.getInputStream(src)) { copy(in, zout); }
                zout.closeEntry();
            }
            ZipEntry padding = new ZipEntry(paddingPath);
            padding.setMethod(ZipEntry.STORED);
            padding.setSize(paddingBytes);
            padding.setCompressedSize(paddingBytes);
            padding.setCrc(crc.getValue());
            padding.setExtra(createAlignmentExtra(counting.position(), paddingPath, FILE_ALIGNMENT));
            zout.putNextEntry(padding);
            for (long remaining = paddingBytes; remaining > 0;) {
                int count = (int) Math.min(ZERO_BLOCK.length, remaining);
                zout.write(ZERO_BLOCK, 0, count);
                remaining -= count;
            }
            zout.closeEntry();
        }
    }

    /**
     * ZIP local file header: 30 bytes + UTF8 name + extra。该 extra 的格式遵循
     * Android zipalign 0xD935 定义：id(2), dataSize(2), alignment(2), padding(N)。
     */
    private static byte[] createAlignmentExtra(long localHeaderOffset, String name, int alignment) {
        int nameBytes = name.getBytes(StandardCharsets.UTF_8).length;
        long dataStartWithoutPadding = localHeaderOffset + 30L + nameBytes + 6L;
        int padding = (int) ((alignment - (dataStartWithoutPadding % alignment)) % alignment);
        byte[] extra = new byte[6 + padding];
        putU16(extra, 0, ZIPALIGN_EXTRA_FIELD_ID);
        putU16(extra, 2, 2 + padding);
        putU16(extra, 4, alignment);
        return extra;
    }

    private static void putU16(byte[] bytes, int offset, int value) {
        bytes[offset] = (byte) value;
        bytes[offset + 1] = (byte) (value >>> 8);
    }

    private static boolean isOldSignatureFile(String name) {
        if (!name.regionMatches(true, 0, "META-INF/", 0, "META-INF/".length())) return false;
        String leaf = name.substring("META-INF/".length());
        if (leaf.indexOf('/') >= 0) return false;
        String upper = leaf.toUpperCase(Locale.ROOT);
        return upper.endsWith(".SF") || upper.endsWith(".RSA") || upper.endsWith(".DSA")
                || upper.endsWith(".EC") || upper.endsWith(".MF")
                || upper.startsWith("SIG-");
    }

    private static byte[] readLimited(InputStream in, int limit) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int read;
        while ((read = in.read(buf)) != -1) {
            if (read > limit - out.size()) throw new IOException("AndroidManifest.xml 过大");
            out.write(buf, 0, read);
        }
        return out.toByteArray();
    }

    private static long copy(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[64 * 1024];
        long total = 0;
        int n;
        while ((n = in.read(buffer)) != -1) {
            out.write(buffer, 0, n);
            total += n;
        }
        return total;
    }

    private static final class PositionOutputStream extends FilterOutputStream {
        private long count;
        PositionOutputStream(OutputStream out) { super(out); }
        long position() { return count; }
        @Override public void write(int b) throws IOException { out.write(b); count++; }
        @Override public void write(byte[] b, int off, int len) throws IOException {
            out.write(b, off, len);
            count += len;
        }
    }

}
