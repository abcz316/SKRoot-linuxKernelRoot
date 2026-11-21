package com.linux.permissionmanager.repack;

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
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 批量重命名 DEX 中的 Class 定义。
 * 需要 Google 官方 com.android.tools.smali:smali-dexlib2:3.0.10 依赖。
 * 不处理任意反射字符串、JNI 硬编码字符串及 DEX 以外的私有协议引用。
 */
final class DexClassRenamer {
    private static final Pattern JAVA_CLASS = Pattern.compile(
            "[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)+");
    private static final Pattern DEX_ENTRY = Pattern.compile("classes(?:[2-9]|[1-9][0-9]+)?\\.dex");

    private DexClassRenamer() {}

    static void validateClassName(String className) {
        if (className == null || className.length() > 512 || !JAVA_CLASS.matcher(className).matches()) {
            throw new IllegalArgumentException("Class 必须使用合法完整类名: " + className);
        }
    }

    static boolean isDexEntry(String name) {
        return name != null && DEX_ENTRY.matcher(name).matches();
    }

    private static String descriptor(String className) {
        return "L" + className.replace('.', '/') + ";";
    }

    private static Map<String, String> toDescriptorMap(Map<String, String> classRenames) {
        Map<String, String> result = new LinkedHashMap<>();
        if (classRenames == null) return result;
        for (Map.Entry<String, String> entry : classRenames.entrySet()) {
            result.put(descriptor(entry.getKey()), descriptor(entry.getValue()));
        }
        return result;
    }

    /**
     * 在开始重打包前检查全部 multidex：每个旧类必须恰好定义一次，目标类不能与未重命名的类冲突。
     * 如果目标类名本身也是本次映射中的旧类名，则允许，因为所有映射会同时执行，而非链式替换。
     */
    static void validateDexClasses(File apk, Map<String, String> classRenames) throws IOException {
        if (classRenames == null || classRenames.isEmpty()) return;

        Map<String, String> descriptorMap = toDescriptorMap(classRenames);
        Map<String, Integer> oldCounts = new LinkedHashMap<>();
        Set<String> allClassDescriptors = new LinkedHashSet<>();
        Set<String> sourceDescriptors = new LinkedHashSet<>(descriptorMap.keySet());
        int dexCount = 0;
        for (String oldDescriptor : sourceDescriptors) oldCounts.put(oldDescriptor, 0);

        try (ZipFile zip = new ZipFile(apk)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (!isDexEntry(entry.getName())) continue;
                dexCount++;
                try (InputStream input = new BufferedInputStream(zip.getInputStream(entry))) {
                    DexBackedDexFile dex = DexBackedDexFile.fromInputStream(null, input);
                    for (ClassDef cls : dex.getClasses()) {
                        String type = cls.getType();
                        allClassDescriptors.add(type);
                        Integer count = oldCounts.get(type);
                        if (count != null) oldCounts.put(type, count + 1);
                    }
                } catch (Exception e) {
                    throw new IOException("读取 DEX 失败: " + entry.getName() + "，原因=" + e.getClass().getSimpleName() + ": " + e.getMessage(), e);
                }
            }
        }

        if (dexCount == 0) throw new IOException("APK 中没有找到 classes*.dex");

        for (Map.Entry<String, String> entry : descriptorMap.entrySet()) {
            String oldDescriptor = entry.getKey();
            String newDescriptor = entry.getValue();
            int oldCount = oldCounts.get(oldDescriptor);
            if (oldCount != 1) {
                throw new IOException("DEX 原 Class 检查失败：" + entry.getKey() + "，定义数量=" + oldCount + "，要求恰好为 1");
            }
            if (allClassDescriptors.contains(newDescriptor) && !sourceDescriptors.contains(newDescriptor)) {
                throw new IOException("DEX 新 Class 名称冲突：" + entry.getValue() + " 已被 APK 中其他未重命名的 Class 使用");
            }
        }
    }

    /**
     * 当前 DEX 不包含任何待重命名的 Class 定义时返回 null，调用方直接保留原始 DEX 字节。
     * 命中时使用同一份映射一次性重建 DEX；映射按原始类型匹配，不进行链式替换。
     */
    static byte[] rewriteIfContains(byte[] dexBytes, Map<String, String> classRenames,
                                    File cacheDir) throws IOException {
        if (classRenames == null || classRenames.isEmpty()) return null;

        Map<String, String> descriptorMap = toDescriptorMap(classRenames);
        try {
            DexBackedDexFile dex = DexBackedDexFile.fromInputStream(null, new ByteArrayInputStream(dexBytes));
            Map<String, Integer> expectedTargetCounts = new LinkedHashMap<>();
            Set<String> originalTypes = new LinkedHashSet<>();
            for (ClassDef cls : dex.getClasses()) {
                String type = cls.getType();
                originalTypes.add(type);
                String target = descriptorMap.get(type);
                if (target != null) {
                    Integer count = expectedTargetCounts.get(target);
                    expectedTargetCounts.put(target, count == null ? 1 : count + 1);
                }
            }
            if (expectedTargetCounts.isEmpty()) return null;

            Set<String> targetDescriptors = new LinkedHashSet<>(descriptorMap.values());
            DexRewriter rewriter = new DexRewriter(new RewriterModule() {
                @Override public TypeRewriter getTypeRewriter(Rewriters rewriters) {
                    return new TypeRewriter() {
                        @Override protected String rewriteUnwrappedType(String value) {
                            String replacement = descriptorMap.get(value);
                            return replacement == null ? value : replacement;
                        }
                    };
                }
            });
            DexFile rewritten = rewriter.getDexFileRewriter().rewrite(dex);
            File scratch = File.createTempFile("rewritten-classes-", ".dex", cacheDir);
            try {
                DexPool.writeTo(scratch.getAbsolutePath(), rewritten);
                byte[] out = Files.readAllBytes(scratch.toPath());
                DexBackedDexFile check = DexBackedDexFile.fromInputStream(null, new ByteArrayInputStream(out));
                Map<String, Integer> outputCounts = new LinkedHashMap<>();
                for (ClassDef cls : check.getClasses()) {
                    String type = cls.getType();
                    Integer count = outputCounts.get(type);
                    outputCounts.put(type, count == null ? 1 : count + 1);
                }

                for (Map.Entry<String, Integer> expected : expectedTargetCounts.entrySet()) {
                    int actual = outputCounts.containsKey(expected.getKey()) ? outputCounts.get(expected.getKey()) : 0;
                    if (actual != expected.getValue()) {
                        throw new IOException("DEX 重写结果校验失败：目标 Class=" + expected.getKey() + "，预期定义数量=" + expected.getValue() + "，实际=" + actual);
                    }
                }
                // 原类名若没有同时作为其他规则的目标类名，重写后就不应再有对应定义。
                for (String oldDescriptor : descriptorMap.keySet()) {
                    if (targetDescriptors.contains(oldDescriptor)) continue;
                    if (originalTypes.contains(oldDescriptor) && outputCounts.containsKey(oldDescriptor)) {
                        throw new IOException("DEX 重写后仍存在原 Class：" + oldDescriptor);
                    }
                }
                return out;
            } finally {
                //noinspection ResultOfMethodCallIgnored
                scratch.delete();
            }
        } catch (RuntimeException e) {
            throw new IOException("DEX 批量 Class 重命名失败: " + e.getMessage(), e);
        }
    }
}
