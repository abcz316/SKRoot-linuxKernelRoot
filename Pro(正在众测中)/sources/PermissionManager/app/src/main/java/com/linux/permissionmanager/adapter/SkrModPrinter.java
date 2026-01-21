package com.linux.permissionmanager.adapter;

import android.text.TextUtils;

import com.linux.permissionmanager.model.SkrModItem;

public final class SkrModPrinter {
    public static String buildModuleMeta(SkrModItem m) {
        StringBuilder sb = new StringBuilder(256);
        sb.append("----- SKRoot 模块详情 -----\n");
        sb.append("名称：").append(nvl(m.getName())).append('\n');
        sb.append("版本：").append(nvl(m.getVer())).append('\n');
        sb.append("描述：").append(nvl(m.getDesc())).append('\n');
        sb.append("作者：").append(nvl(m.getAuthor())).append('\n');
        sb.append("UUID：").append(nvl(m.getUuid())).append('\n');
        sb.append("最低SDK要求：").append(nvl(m.getMiniSdk())).append('\n');

        boolean onlineUpdate = !TextUtils.isEmpty(m.getUpdateJson());
        boolean anyFeature = m.isWebUi() || onlineUpdate;
        if (anyFeature) {
            sb.append("特性：\n");
            if (m.isWebUi()) sb.append("    [+] Web UI\n");
            if (onlineUpdate) sb.append("    [+] Online Update\n");
        }

        sb.append("------------------------------\n");
        return sb.toString();
    }

    public static String buildModuleMetaWithStatus(SkrModItem m) {
        String text = buildModuleMeta(m);
        return text + "运行状态：" + (m.isRunning() ? "运行中" : "未运行") + "\n";
    }

    private static String nvl(String s) {
        return (s == null || s.isEmpty()) ? "（空）" : s;
    }
}
