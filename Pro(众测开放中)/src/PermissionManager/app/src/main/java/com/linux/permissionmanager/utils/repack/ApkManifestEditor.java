package com.linux.permissionmanager.utils.repack;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** 二进制 AndroidManifest.xml 包名、Activity、应用名称、版本号和图标属性编辑。 */
final class ApkManifestEditor {
    private ApkManifestEditor() {}
    private static final int RES_XML_TYPE = 0x0003;
    private static final int RES_STRING_POOL_TYPE = 0x0001;
    private static final int RES_XML_START_ELEMENT_TYPE = 0x0102;
    private static final int RES_XML_END_ELEMENT_TYPE = 0x0103;
    private static final int TYPE_STRING = 0x03;
    private static final int TYPE_INT_DEC = 0x10;
    private static final int UTF8_FLAG = 0x100;
    private static final int SORTED_FLAG = 0x01;
    private static final int MAX_MANIFEST_SIZE = 16 * 1024 * 1024;
    private static final Pattern PACKAGE_NAME = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+");

    private static final String ANDROID_URI = "http://schemas.android.com/apk/res/android";

    static byte[] patch(byte[] xml, String newPackageName, String newAppName, String newVersionName,
                        Integer newVersionCode, boolean removeAppIcon, String oldEntryActivityName, String newEntryActivityName) throws IOException {
        if (newPackageName != null && (newPackageName.length() > 255 || !PACKAGE_NAME.matcher(newPackageName).matches())) {
            throw new IllegalArgumentException("无效的新包名: " + newPackageName);
        }
        if (newAppName != null) {
            if (newAppName.isEmpty() || newAppName.trim().isEmpty() || newAppName.length() > 1024) {
                throw new IllegalArgumentException("应用显示名称不能为空或超过 1024 字符");
            }
            for (int i = 0; i < newAppName.length(); i++) {
                if (Character.isISOControl(newAppName.charAt(i))) {
                    throw new IllegalArgumentException("应用显示名称不能包含控制字符");
                }
            }
        }
        if (newVersionCode != null && newVersionCode <= 0) throw new IllegalArgumentException("newVersionCode 必须大于 0");
        if (newVersionName != null && (newVersionName.trim().isEmpty() || newVersionName.length() > 1024)) throw new IllegalArgumentException("newVersionName 不能为空或超过 1024 字符");
        if (newVersionName != null) for (int i = 0; i < newVersionName.length(); i++) if (Character.isISOControl(newVersionName.charAt(i))) throw new IllegalArgumentException("newVersionName 不能包含控制字符");
        if (xml == null || xml.length < 8 || xml.length > MAX_MANIFEST_SIZE
                || u16(xml, 0) != RES_XML_TYPE || u16(xml, 2) < 8 || u32(xml, 4) != xml.length) {
            throw new IOException("不是有效的二进制 AndroidManifest.xml");
        }
        StringPool pool = null;
        int poolOffset = -1, poolSize = -1;
        int depth = 0, roots = 0, appLabelCount = 0, versionNameCount = 0, versionCodeCount = 0;
        int versionCodeOffset = -1;
        int originalAppLabelType = -1, originalAppLabelData = 0;
        String oldPackageName = null;
        int entryActivityCount = 0;
        List<AttributePatch> patches = new ArrayList<>();
        int cursor = u16(xml, 2);
        while (cursor < xml.length) {
            require(xml, cursor, 8);
            int type = u16(xml, cursor);
            int headerSize = u16(xml, cursor + 2);
            long length = uint32(xml, cursor + 4);
            if (headerSize < 8 || length < headerSize || length > xml.length - cursor)
                throw new IOException("AXML chunk 长度错误: offset=" + cursor);
            int chunkSize = (int) length;
            if (type == RES_STRING_POOL_TYPE) {
                if (pool != null) throw new IOException("重复的 AXML 字符串池");
                poolOffset = cursor;
                poolSize = chunkSize;
                pool = new StringPool(xml, cursor, chunkSize);
            } else if (type == RES_XML_START_ELEMENT_TYPE) {
                if (pool == null || headerSize < 16 || chunkSize < 36) throw new IOException("AXML 元素结构错误");
                String element = pool.get(u32(xml, cursor + 20));
                depth++;
                if (depth == 1) {
                    roots++;
                    if (!"manifest".equals(element)) throw new IOException("根元素不是 manifest");
                }
                int attrsStart = u16(xml, cursor + 24);
                int attrsSize = u16(xml, cursor + 26);
                int attrsCount = u16(xml, cursor + 28);
                long start = (long) cursor + 16 + attrsStart;
                if (attrsSize < 20 || attrsCount > 10000 || start < cursor + 36
                        || start + (long) attrsSize * attrsCount > cursor + chunkSize) {
                    throw new IOException("AXML 属性表损坏: " + element);
                }
                for (int i = 0; i < attrsCount; i++) {
                    int at = (int) (start + (long) i * attrsSize);
                    String namespace = pool.get(u32(xml, at));
                    String attribute = pool.get(u32(xml, at + 4));
                    if (u16(xml, at + 12) < 8) throw new IOException("损坏的 AXML TypedValue");
                    if (depth == 1 && namespace == null && "package".equals(attribute)) {
                        if (oldPackageName != null) throw new IOException("重复的 manifest package 属性");
                        oldPackageName = readStringAttribute(xml, pool, at);
                        if (newPackageName != null && !oldPackageName.equals(newPackageName)) {
                            patches.add(new AttributePatch(at, newPackageName, false));
                        }
                    } else if (depth == 1 && ANDROID_URI.equals(namespace) && "versionName".equals(attribute)) {
                        versionNameCount++;
                        if (newVersionName != null) patches.add(new AttributePatch(at, newVersionName, true));
                    } else if (depth == 1 && ANDROID_URI.equals(namespace) && "versionCode".equals(attribute)) {
                        versionCodeCount++;
                        if (newVersionCode != null) versionCodeOffset = at;
                    } else if (oldEntryActivityName != null
                            && ANDROID_URI.equals(namespace)
                            && ("name".equals(attribute) && "activity".equals(element)
                                || "targetActivity".equals(attribute) && "activity-alias".equals(element)
                                || "parentActivityName".equals(attribute)
                                    && ("activity".equals(element) || "activity-alias".equals(element)))) {
                        String literal = readStringAttribute(xml, pool, at);
                        String resolved = literal.startsWith(".") ? oldPackageName + literal
                                : literal.indexOf('.') < 0 ? oldPackageName + "." + literal : literal;
                        if (oldEntryActivityName.equals(resolved)) {
                            if ("activity".equals(element) && "name".equals(attribute)) entryActivityCount++;
                            patches.add(new AttributePatch(at, newEntryActivityName, false));
                        } else if (newPackageName != null && !oldPackageName.equals(newPackageName)
                                && isComponentClassAttribute(element, attribute)
                                && (literal.startsWith(".") || literal.indexOf('.') < 0)) {
                            patches.add(new AttributePatch(at, resolved, false));
                        }
                    } else if (newAppName != null && depth == 2 && "application".equals(element)
                            && ANDROID_URI.equals(namespace) && "label".equals(attribute)) {
                        appLabelCount++;
                        originalAppLabelType = xml[at + 15] & 0xff;
                        originalAppLabelData = u32(xml, at + 16);
                        // android:label 通常是 TYPE_REFERENCE（@string/app_name），直接改成字面字符串。
                        patches.add(new AttributePatch(at, newAppName, true));
                    } else if (newAppName != null && appLabelCount == 1 && depth >= 3
                            && ANDROID_URI.equals(namespace) && "label".equals(attribute)
                            && ("activity".equals(element) || "activity-alias".equals(element)
                            || "intent-filter".equals(element))
                            && (xml[at + 15] & 0xff) == originalAppLabelType
                            && u32(xml, at + 16) == originalAppLabelData) {
                        // 原 Activity/别名/IntentFilter 显式引用了同一个 app_name，保持桌面显示名称一致。
                        patches.add(new AttributePatch(at, newAppName, true));
                    } else if (newPackageName != null && oldPackageName != null
                            && !oldPackageName.equals(newPackageName) && ANDROID_URI.equals(namespace)) {
                        String newValue = null;
                        if ("provider".equals(element) && "authorities".equals(attribute)) {
                            String value = readStringAttribute(xml, pool, at);
                            newValue = rewriteAuthorities(value, oldPackageName, newPackageName);
                        } else if (isComponentClassAttribute(element, attribute)) {
                            String value = readStringAttribute(xml, pool, at);
                            if (value.startsWith(".")) newValue = oldPackageName + value;
                            else if (value.indexOf('.') < 0 && !value.isEmpty()) newValue = oldPackageName + "." + value;
                        }
                        if (newValue != null) patches.add(new AttributePatch(at, newValue, false));
                    }
                }
            } else if (type == RES_XML_END_ELEMENT_TYPE) {
                if (pool == null || depth == 0 || headerSize < 16 || chunkSize < 24) throw new IOException("AXML 结束元素结构错误");
                depth--;
            }
            cursor += chunkSize;
        }
        if (cursor != xml.length || depth != 0 || roots != 1 || oldPackageName == null) {
            throw new IOException("Manifest 结构损坏或缺少 package");
        }
        if (oldEntryActivityName != null && entryActivityCount != 1) {
            throw new IOException("Manifest 必须恰好注册一个原入口 Activity: "
                    + oldEntryActivityName + "，找到 " + entryActivityCount + " 个");
        }
        if (newVersionName != null && versionNameCount != 1) throw new IOException("Manifest 必须恰好有一个 android:versionName，实际找到 " + versionNameCount + " 个");
        if (newVersionCode != null && versionCodeCount != 1) throw new IOException("Manifest 必须恰好有一个 android:versionCode，实际找到 " + versionCodeCount + " 个");
        if (newAppName != null && appLabelCount != 1) {
            throw new IOException("需要且只能有一个 <application android:label>，实际找到 " + appLabelCount
                    + " 个；请在源 APK 的 application 中声明 android:label");
        }
        if (patches.isEmpty() && newVersionCode == null) return removeAppIcon ? stripIconAttributes(xml) : xml.clone();
        LinkedHashMap<String,Integer> newStrings = new LinkedHashMap<>();
        for (AttributePatch patch : patches) {
            if (pool.indexOf(patch.value) == -1 && !newStrings.containsKey(patch.value)) {
                newStrings.put(patch.value, pool.count + newStrings.size());
            }
        }
        byte[] updatedPool = newStrings.isEmpty() ? null : pool.appendAll(newStrings.keySet());
        byte[] result;
        int delta = 0;
        if (updatedPool == null) {
            result = xml.clone();
        } else {
            delta = updatedPool.length - poolSize;
            result = new byte[xml.length + delta];
            System.arraycopy(xml, 0, result, 0, poolOffset);
            System.arraycopy(updatedPool, 0, result, poolOffset, updatedPool.length);
            System.arraycopy(xml, poolOffset + poolSize, result, poolOffset + updatedPool.length, xml.length - poolOffset - poolSize);
            putU32(result, 4, result.length);
        }
        for (AttributePatch patch : patches) {
            int index = pool.indexOf(patch.value);
            if (index == -1) index = newStrings.get(patch.value);
            int at = patch.offset + (patch.offset >= poolOffset + poolSize ? delta : 0);
            // typedValue: TYPE_STRING; 更新原始值 rawValue 以及类型化值 data。
            if (!patch.changeTypeToString && (result[at + 15] & 0xff) != TYPE_STRING) {
                throw new IOException("Manifest 属性不是 TYPE_STRING");
            }
            // 直接写入 literal string，覆盖旧的 @string/app_name 资源引用。
            if (patch.changeTypeToString) result[at + 15] = (byte) TYPE_STRING;
            putU32(result, at + 8, index);
            putU32(result, at + 16, index);
        }
        if (newVersionCode != null) {
            int at = versionCodeOffset + (versionCodeOffset >= poolOffset + poolSize ? delta : 0);
            // versionCode 采用 Res_value.TYPE_INT_DEC，并清除原始字符串引用。
            putU32(result, at + 8, -1);
            result[at + 15] = (byte) TYPE_INT_DEC;
            putU32(result, at + 16, newVersionCode);
        }
        return removeAppIcon ? stripIconAttributes(result) : result;
    }

    /**
     * 从已编译的 AXML 起始标签中彻底移除 android:icon / android:roundIcon 属性。
     * 不修改 string pool 或资源本身；缩短 START_ELEMENT chunk 并修正相关长度与属性索引。
     */
    private static byte[] stripIconAttributes(byte[] xml) throws IOException {
        final int rootHeader = u16(xml, 2);
        ByteArrayOutputStream out = new ByteArrayOutputStream(xml.length);
        out.write(xml, 0, rootHeader);
        StringPool pool = null;
        boolean changed = false;
        int cursor = rootHeader;
        while (cursor < xml.length) {
            require(xml, cursor, 8);
            int type = u16(xml, cursor);
            int headerSize = u16(xml, cursor + 2);
            long length = uint32(xml, cursor + 4);
            if (headerSize < 8 || length < headerSize || length > xml.length - cursor) {
                throw new IOException("AXML chunk 长度错误: offset=" + cursor);
            }
            int chunkSize = (int) length;
            if (type == RES_STRING_POOL_TYPE) {
                if (pool != null) throw new IOException("重复的 AXML 字符串池");
                pool = new StringPool(xml, cursor, chunkSize);
            }
            if (type != RES_XML_START_ELEMENT_TYPE) {
                out.write(xml, cursor, chunkSize);
                cursor += chunkSize;
                continue;
            }
            if (pool == null || headerSize < 16 || chunkSize < 36) {
                throw new IOException("AXML 起始元素结构错误");
            }
            int attrsStart = u16(xml, cursor + 24);
            int attrsSize = u16(xml, cursor + 26);
            int attrsCount = u16(xml, cursor + 28);
            long start = (long) cursor + 16 + attrsStart;
            long end = start + (long) attrsSize * attrsCount;
            if (attrsSize < 20 || attrsSize % 4 != 0 || attrsCount > 10000
                    || start < cursor + 36 || end > cursor + chunkSize) {
                throw new IOException("AXML 属性列表损坏");
            }
            boolean[] removed = new boolean[attrsCount];
            int removedCount = 0;
            for (int i = 0; i < attrsCount; i++) {
                int at = (int) (start + (long) i * attrsSize);
                String namespace = pool.get(u32(xml, at));
                String attribute = pool.get(u32(xml, at + 4));
                if (ANDROID_URI.equals(namespace)
                        && ("icon".equals(attribute) || "roundIcon".equals(attribute))) {
                    removed[i] = true;
                    removedCount++;
                }
            }
            if (removedCount == 0) {
                out.write(xml, cursor, chunkSize);
                cursor += chunkSize;
                continue;
            }
            changed = true;
            int newChunkSize = chunkSize - removedCount * attrsSize;
            byte[] chunk = new byte[newChunkSize];
            int prefixSize = (int) (start - cursor);
            System.arraycopy(xml, cursor, chunk, 0, prefixSize);
            int dstAt = prefixSize;
            for (int i = 0; i < attrsCount; i++) {
                if (!removed[i]) {
                    System.arraycopy(xml, (int) (start + (long) i * attrsSize), chunk, dstAt, attrsSize);
                    dstAt += attrsSize;
                }
            }
            int trailingOffset = (int) end;
            System.arraycopy(xml, trailingOffset, chunk, dstAt, cursor + chunkSize - trailingOffset);
            putU32(chunk, 4, newChunkSize);
            putU16(chunk, 28, attrsCount - removedCount);
            // idIndex / classIndex / styleIndex 是 1-based 属性索引。
            for (int indexOffset : new int[]{30, 32, 34}) {
                int oldIndex = u16(chunk, indexOffset);
                if (oldIndex == 0) continue;
                if (oldIndex > attrsCount || removed[oldIndex - 1]) {
                    throw new IOException("AXML 特殊属性索引损坏");
                }
                int removedBefore = 0;
                for (int i = 0; i < oldIndex - 1; i++) {
                    if (removed[i]) removedBefore++;
                }
                putU16(chunk, indexOffset, oldIndex - removedBefore);
            }
            out.write(chunk, 0, chunk.length);
            cursor += chunkSize;
        }
        if (cursor != xml.length) throw new IOException("AXML 结构不完整");
        if (!changed) return xml.clone();
        byte[] updated = out.toByteArray();
        putU32(updated, 4, updated.length);
        return updated;
    }

    /** 仅删除 manifest 的直接子节点 uses-permission，所有同名重复声明都会删除；不修改字符串池和其他节点。 */
    static byte[] removeUsesPermissions(byte[] xml, Set<String> names) throws IOException {
        if (names == null || names.isEmpty()) return xml.clone();
        if (xml.length < 8 || u16(xml, 0) != RES_XML_TYPE || u32(xml, 4) != xml.length) throw new IOException("无效的二进制 Manifest");
        int headerSize = u16(xml, 2), cursor = headerSize, depth = 0, skipDepth = 0, removed = 0;
        if (headerSize < 8 || headerSize > xml.length) throw new IOException("AXML 头长度错误");
        ByteArrayOutputStream out = new ByteArrayOutputStream(xml.length);
        out.write(xml, 0, headerSize);
        StringPool pool = null;
        List<String> elementStack = new ArrayList<>();
        while (cursor < xml.length) {
            require(xml, cursor, 8);
            int type = u16(xml, cursor), chunkHeader = u16(xml, cursor + 2);
            long chunkLength = uint32(xml, cursor + 4);
            if (chunkHeader < 8 || chunkLength < chunkHeader || chunkLength > xml.length - cursor) throw new IOException("AXML chunk 长度错误: " + cursor);
            int chunkSize = (int) chunkLength;
            boolean discard = skipDepth != 0;
            if (type == RES_STRING_POOL_TYPE) {
                if (pool != null) throw new IOException("重复的 AXML 字符串池");
                pool = new StringPool(xml, cursor, chunkSize);
            } else if (type == RES_XML_START_ELEMENT_TYPE) {
                if (pool == null || chunkHeader < 16 || chunkSize < 36) throw new IOException("AXML 起始节点损坏");
                String tag = pool.get(u32(xml, cursor + 20));
                elementStack.add(tag);
                depth++;
                if (skipDepth != 0) throw new IOException("不支持嵌套的 uses-permission 节点");
                if (depth == 2 && "uses-permission".equals(tag)) {
                    int attrStart = u16(xml, cursor + 24), attrSize = u16(xml, cursor + 26), attrCount = u16(xml, cursor + 28);
                    long attrs = (long) cursor + 16 + attrStart;
                    if (attrSize < 20 || attrCount > 10000 || attrs < cursor + 36 || attrs + (long) attrSize * attrCount > cursor + chunkSize) throw new IOException("uses-permission 属性损坏");
                    for (int i = 0; i < attrCount; i++) {
                        int at = (int) (attrs + (long) i * attrSize);
                        if (!ANDROID_URI.equals(pool.get(u32(xml, at))) || !"name".equals(pool.get(u32(xml, at + 4)))) continue;
                        if (u16(xml, at + 12) < 8) throw new IOException("uses-permission name 类型损坏");
                        if (names.contains(readStringAttribute(xml, pool, at))) { skipDepth = depth; discard = true; removed++; }
                        break;
                    }
                }
            } else if (type == RES_XML_END_ELEMENT_TYPE) {
                if (pool == null || chunkHeader < 16 || chunkSize < 24 || depth == 0) throw new IOException("AXML 结束节点损坏");
                String tag = pool.get(u32(xml, cursor + 20));
                if (!tag.equals(elementStack.remove(elementStack.size() - 1))) throw new IOException("AXML 开闭节点不匹配");
                if (skipDepth == depth) { discard = true; skipDepth = 0; }
                depth--;
            }
            if (!discard) out.write(xml, cursor, chunkSize);
            cursor += chunkSize;
        }
        if (cursor != xml.length || depth != 0 || skipDepth != 0) throw new IOException("AXML 节点未闭合");
        if (removed == 0) return xml.clone();
        byte[] result = out.toByteArray();
        putU32(result, 4, result.length);
        return result;
    }

    private static String readStringAttribute(byte[] xml, StringPool pool, int offset) throws IOException {
        if ((xml[offset + 15] & 0xff) != TYPE_STRING) throw new IOException("Manifest 字符串属性类型不正确");
        return pool.get(u32(xml, offset + 16));
    }

    private static boolean isComponentClassAttribute(String element, String attribute) {
        if ("application".equals(element)) {
            return "name".equals(attribute) || "backupAgent".equals(attribute)
                    || "appComponentFactory".equals(attribute) || "manageSpaceActivity".equals(attribute)
                    || "zygotePreloadName".equals(attribute);
        }
        if ("activity".equals(element) || "activity-alias".equals(element)) {
            return "name".equals(attribute) || "parentActivityName".equals(attribute)
                    || ("activity-alias".equals(element) && "targetActivity".equals(attribute));
        }
        return "name".equals(attribute) && ("service".equals(element) || "receiver".equals(element)
                || "provider".equals(element) || "instrumentation".equals(element));
    }

    private static String rewriteAuthorities(String source, String oldPkg, String newPkg) {
        String[] authorities = source.split(";", -1);
        boolean changed = false;
        for (int i = 0; i < authorities.length; i++) {
            String name = authorities[i];
            if (name.equals(oldPkg) || name.startsWith(oldPkg + ".")) {
                authorities[i] = newPkg + name.substring(oldPkg.length());
                changed = true;
            }
        }
        if (!changed) return null;
        return String.join(";", authorities);
    }

    private static final class AttributePatch {
        final int offset;
        final String value;
        final boolean changeTypeToString;
        AttributePatch(int offset, String value, boolean changeTypeToString) {
            this.offset = offset;
            this.value = value;
            this.changeTypeToString = changeTypeToString;
        }
    }

    private static final class StringPool {
        private final byte[] xml;
        private final int offset;
        private final int chunkSize;
        private final int headerSize;
        private final int styleCount;
        private final int flags;
        private final int stringsStart;
        private final int stylesStart;
        private final int[] offsets;
        private final List<String> values;
        final int count;

        StringPool(byte[] source, int start, int size) throws IOException {
            xml = source;
            offset = start;
            chunkSize = size;
            headerSize = u16(xml, offset + 2);
            if (headerSize < 28 || headerSize > size) throw new IOException("String pool header 错误");
            long stringCountLong = uint32(xml, offset + 8);
            long styleCountLong = uint32(xml, offset + 12);
            if (stringCountLong > 1000000 || styleCountLong > 1000000) {
                throw new IOException("String pool 太大");
            }
            count = (int) stringCountLong;
            styleCount = (int) styleCountLong;
            flags = u32(xml, offset + 16);
            stringsStart = u32(xml, offset + 20);
            stylesStart = u32(xml, offset + 24);
            long indexEnd = (long) headerSize + ((long) count + styleCount) * 4;
            int stringsEnd = styleCount == 0 ? size : stylesStart;
            if (indexEnd > size || stringsStart < indexEnd || stringsStart > stringsEnd || stringsEnd > size || (styleCount > 0 && stylesStart == 0)) {
                throw new IOException("String pool offset 超界");
            }
            offsets = new int[count];
            values = new ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                offsets[i] = u32(xml, offset + headerSize + 4 * i);
                int pos = offset + stringsStart + offsets[i];
                if (offsets[i] < 0 || pos < offset + stringsStart || pos >= offset + stringsEnd) {
                    throw new IOException("String pool 字符串偏移错误: " + i);
                }
                values.add(decode(pos, offset + stringsEnd));
            }
        }

        String get(int idx) throws IOException {
            if (idx == -1) return null;
            if (idx < 0 || idx >= count) throw new IOException("AXML 字符串索引超界: " + idx);
            return values.get(idx);
        }

        int indexOf(String value) { return values.indexOf(value); }

        private String decode(int position, int end) throws IOException {
            if ((flags & UTF8_FLAG) != 0) {
                int[] a = readLen8(xml, position, end);
                int[] b = readLen8(xml, a[1], end);
                int n = b[0], p = b[1];
                if (n < 0 || (long) p + n + 1 > end || xml[p + n] != 0) throw new IOException("非法 UTF-8 字符串长度");
                return new String(xml, p, n, StandardCharsets.UTF_8);
            }
            int[] a = readLen16(xml, position, end);
            int n = a[0], p = a[1];
            if (n < 0 || (long) p + n * 2L + 2 > end || u16(xml, p + n * 2) != 0) {
                throw new IOException("非法 UTF-16 字符串长度");
            }
            return new String(xml, p, n * 2, StandardCharsets.UTF_16LE);
        }

        byte[] appendAll(java.util.Collection<String> texts) throws IOException {
            boolean utf8 = (flags & UTF8_FLAG) != 0;
            ByteArrayOutputStream encoded = new ByteArrayOutputStream();
            int[] addedOffsets = new int[texts.size()];
            int j = 0;
            for (String text : texts) {
                addedOffsets[j++] = encoded.size();
                if (utf8) {
                    byte[] data = text.getBytes(StandardCharsets.UTF_8);
                    writeLen8(encoded, text.length());
                    writeLen8(encoded, data.length);
                    encoded.write(data, 0, data.length);
                    encoded.write(0);
                } else {
                    byte[] data = text.getBytes(StandardCharsets.UTF_16LE);
                    writeLen16(encoded, text.length());
                    encoded.write(data, 0, data.length);
                    encoded.write(0);
                    encoded.write(0);
                }
            }
            int oldStringEnd = styleCount == 0 ? chunkSize : stylesStart;
            int oldStringLength = oldStringEnd - stringsStart;
            int newCount = count + texts.size();
            int newStart = align4(headerSize + (newCount + styleCount) * 4);
            int newStylesStart = styleCount > 0 ? align4(newStart + oldStringLength + encoded.size()) : 0;
            int newChunkSize = styleCount > 0 ? align4(newStylesStart + chunkSize - stylesStart)
                    : align4(newStart + oldStringLength + encoded.size());
            byte[] result = new byte[newChunkSize];
            System.arraycopy(xml, offset, result, 0, headerSize);
            putU32(result, 4, newChunkSize);
            putU32(result, 8, newCount);
            putU32(result, 16, flags & ~SORTED_FLAG);
            putU32(result, 20, newStart);
            putU32(result, 24, newStylesStart);
            for (int i = 0; i < count; i++) putU32(result, headerSize + i * 4, offsets[i]);
            for (int i = 0; i < addedOffsets.length; i++) {
                putU32(result, headerSize + (count + i) * 4, oldStringLength + addedOffsets[i]);
            }
            if (styleCount > 0) {
                System.arraycopy(xml, offset + headerSize + count * 4,
                        result, headerSize + newCount * 4, styleCount * 4);
            }
            System.arraycopy(xml, offset + stringsStart, result, newStart, oldStringLength);
            byte[] data = encoded.toByteArray();
            System.arraycopy(data, 0, result, newStart + oldStringLength, data.length);
            if (styleCount > 0) {
                System.arraycopy(xml, offset + stylesStart, result, newStylesStart, chunkSize - stylesStart);
            }
            return result;
        }
    }

    private static int[] readLen8(byte[] bytes, int pos, int end) throws IOException {
        if (pos >= end) throw new IOException("UTF-8 length 越界");
        int value = bytes[pos++] & 255;
        if ((value & 0x80) != 0) {
            if (pos >= end) throw new IOException("UTF-8 length 越界");
            value = ((value & 0x7f) << 8) | (bytes[pos++] & 255);
        }
        return new int[]{value, pos};
    }

    private static int[] readLen16(byte[] bytes, int pos, int end) throws IOException {
        if (pos + 2 > end) throw new IOException("UTF-16 length 越界");
        int value = u16(bytes, pos);
        pos += 2;
        if ((value & 0x8000) != 0) {
            if (pos + 2 > end) throw new IOException("UTF-16 length 越界");
            value = ((value & 0x7fff) << 16) | u16(bytes, pos);
            pos += 2;
        }
        return new int[]{value, pos};
    }

    private static void writeLen8(ByteArrayOutputStream out, int n) throws IOException {
        if (n > 32767) throw new IOException("UTF-8 字符串长度超界");
        if (n > 127) { out.write((n >>> 8) | 0x80); out.write(n & 255); }
        else out.write(n);
    }

    private static void writeLen16(ByteArrayOutputStream out, int n) {
        if (n > 32767) { writeU16(out, (n >>> 16) | 0x8000); writeU16(out, n); }
        else writeU16(out, n);
    }

    private static void writeU16(ByteArrayOutputStream out, int n) {
        out.write(n & 255);
        out.write((n >>> 8) & 255);
    }

    private static int align4(int n) { return (n + 3) & ~3; }

    private static void require(byte[] arr, int offset, int len) throws IOException {
        if (offset < 0 || len < 0 || offset > arr.length - len) {
            throw new IOException("AXML 数据越界 offset=" + offset);
        }
    }

    private static int u16(byte[] a, int at) {
        return (a[at] & 255) | ((a[at + 1] & 255) << 8);
    }

    private static int u32(byte[] a, int at) {
        return (a[at] & 255) | ((a[at + 1] & 255) << 8) | ((a[at + 2] & 255) << 16) | ((a[at + 3] & 255) << 24);
    }

    private static long uint32(byte[] a, int at) { return u32(a, at) & 0xffffffffL; }

    private static void putU16(byte[] bytes, int offset, int value) {
        bytes[offset] = (byte) value;
        bytes[offset + 1] = (byte) (value >>> 8);
    }

    private static void putU32(byte[] a, int at, int v) {
        a[at] = (byte) v;
        a[at + 1] = (byte) (v >>> 8);
        a[at + 2] = (byte) (v >>> 16);
        a[at + 3] = (byte) (v >>> 24);
    }
}
