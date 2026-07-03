package com.linux.permissionmanager.update;

import android.app.Activity;
import android.text.TextUtils;

import com.linux.permissionmanager.AppSettings;
import com.linux.permissionmanager.model.SkrModInstalledItem;
import com.linux.permissionmanager.model.SkrModUpdateInfo;

import java.util.function.BiConsumer;

public class SkrModUpdateCache {
    private static String getModuleUpdateKey(SkrModInstalledItem item) { return "module_update_" + item.getId32(); }

    public static SkrModUpdateInfo getModuleUpdateResponseCache(SkrModInstalledItem item) {
        if (item == null) return null;
        String jsonStr = AppSettings.getString(getModuleUpdateKey(item), "");
        try {
            return SkrModUpdateChecker.parse(jsonStr, item.getVer());
        } catch (Exception e) {}
        return null;
    }

    public static void saveModuleUpdateResponseCache(SkrModInstalledItem item, String jsonStr) {
        if (item == null || TextUtils.isEmpty(jsonStr)) return;
        AppSettings.setString(getModuleUpdateKey(item), jsonStr);
    }
}
