package com.linux.permissionmanager.update;

import android.app.Activity;
import android.util.Log;

import com.linux.permissionmanager.AppSettings;
import com.linux.permissionmanager.bridge.NativeBridge;
import com.linux.permissionmanager.utils.DialogUtils;

public class SkrModInstaller {
    public static void installFromZip(Activity activity, String rootKey, boolean isHotload, String zipFilePath, boolean isDevRunOnceMode) {
        Log.d("SkrModFragment", "Add skr module file path: " + zipFilePath);
        String tip = NativeBridge.installSkrootModule(rootKey, zipFilePath, isDevRunOnceMode);
        if(tip.indexOf("OK") != -1) tip += isHotload ? "，已生效" : "，重启后生效";
        if(tip.indexOf("ERR_MODULE_REQUIRE_MIN_SDK") != -1) tip += "，当前SKRoot环境版本太低，请先升级SKRoot";
        if(tip.indexOf("ERR_MODULE_SDK_TOO_OLD") != -1) tip += "，该模块SDK版本太低，已不支持安装";
        DialogUtils.showMsgDlg(activity, "执行结果", tip, null);
    }

}
