package com.linux.permissionmanager.utils.repack;

import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.rewriter.DexRewriter;
import com.android.tools.smali.dexlib2.rewriter.RewriterModule;
import com.android.tools.smali.dexlib2.rewriter.Rewriters;
import com.android.tools.smali.dexlib2.rewriter.TypeRewriter;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Enumeration;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 仅重命名一个预设的入口 Activity 类型，其他业务 Activity 保持不变。
 * 需要 Google 官方 com.android.tools.smali:smali-dexlib2:3.0.10 依赖。
 * 不处理任意反射字符串、JNI 硬编码字符串、DEX 以外的私有协议引用。
 */
final class EntryDexRenamer {
    private static final Pattern JAVA_CLASS = Pattern.compile(
            "[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)+");
    private static final Pattern DEX_ENTRY = Pattern.compile("classes(?:[2-9]|[1-9][0-9]+)?\\.dex");

    private EntryDexRenamer() {}

    static void validateClassName(String className) {
        if (className == null || className.length() > 512 || !JAVA_CLASS.matcher(className).matches()) {
            throw new IllegalArgumentException("Activity 必须使用合法完整类名: " + className);
        }
    }

    static boolean isDexEntry(String name) {
        return name != null && DEX_ENTRY.matcher(name).matches();
    }

    private static String descriptor(String className) {
        return "L" + className.replace('.', '/') + ";";
    }

    /** 在开始修改输出 APK 之前完整检查 multidex，必须有一个原类且没有目标类冲突。 */
    static void validateDexClasses(File apk, String oldClass, String newClass) throws IOException {
        final String oldDesc = descriptor(oldClass);
        final String newDesc = descriptor(newClass);
        int oldCount = 0;
        int newCount = 0;
        int dexCount = 0;
        try (ZipFile zip = new ZipFile(apk)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (!isDexEntry(entry.getName())) continue;
                dexCount++;
                try (InputStream input = new BufferedInputStream(zip.getInputStream(entry))) {
                    DexBackedDexFile dex = DexBackedDexFile.fromInputStream(null, input);
                    for (ClassDef cls : dex.getClasses()) {
                        if (oldDesc.equals(cls.getType())) oldCount++;
                        if (newDesc.equals(cls.getType())) newCount++;
                    }
                } catch (Exception e) {
                    throw new IOException("读取 DEX 失败: " + entry.getName() + "，原因=" + e.getClass().getSimpleName() + ": " + e.getMessage(), e);
                }
            }
        }
        if (dexCount == 0 || oldCount != 1 || newCount != 0) {
            throw new IOException("DEX 入口类检查失败：原类数量=" + oldCount
                    + ", 新类冲突数量=" + newCount + ", DEX 数量=" + dexCount
                    + "。请确认 R8/ProGuard 没有合并或重命名 EntryActivity");
        }
    }

    /**
     * 此 DEX 不含目标类则返回 null，表示直接保留原数据；
     * 命中时通过 dexlib2 正式重建整个 DEX 的类型定义及所有相关类型引用。
     */
    static byte[] rewriteIfContains(byte[] dexBytes, String oldClass, String newClass,
                                    File cacheDir) throws IOException {
        final String oldDesc = descriptor(oldClass);
        final String newDesc = descriptor(newClass);
        try {
            DexBackedDexFile dex = DexBackedDexFile.fromInputStream(null,
                    new ByteArrayInputStream(dexBytes));
            int found = 0;
            for (ClassDef cls : dex.getClasses()) {
                if (oldDesc.equals(cls.getType())) found++;
            }
            if (found == 0) return null;
            if (found != 1) throw new IOException("DEX 内原入口类重复: " + oldClass);

            DexRewriter rewriter = new DexRewriter(new RewriterModule() {
                @Override public TypeRewriter getTypeRewriter(Rewriters rewriters) {
                    return new TypeRewriter() {
                        @Override protected String rewriteUnwrappedType(String value) {
                            return oldDesc.equals(value) ? newDesc : value;
                        }
                    };
                }
            });
            DexFile rewritten = rewriter.getDexFileRewriter().rewrite(dex);
            File scratch = File.createTempFile("rewritten-entry-", ".dex", cacheDir);
            try {
                DexPool.writeTo(scratch.getAbsolutePath(), rewritten);
                byte[] out = Files.readAllBytes(scratch.toPath());
                DexBackedDexFile check = DexBackedDexFile.fromInputStream(null,
                        new ByteArrayInputStream(out));
                boolean hasNew = false;
                for (ClassDef cls : check.getClasses()) {
                    if (oldDesc.equals(cls.getType())) throw new IOException("DEX 重写后仍存在原入口类");
                    if (newDesc.equals(cls.getType())) hasNew = true;
                }
                if (!hasNew) throw new IOException("DEX 重写后找不到新入口类");
                return out;
            } finally {
                scratch.delete();
            }
        } catch (RuntimeException e) {
            throw new IOException("DEX 重命名失败: " + oldClass + " → " + newClass, e);
        }
    }
}
