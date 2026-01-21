package com.linux.permissionmanager.update;

import com.linux.permissionmanager.model.AppUpdateInfo;

import org.json.JSONException;
import org.json.JSONObject;

public final class AppUpdateParser {

    private AppUpdateParser() {
        throw new AssertionError("No SkrModUpdateParser instances for you!");
    }

    /**
     * 解析服务器返回的模块更新 JSON，并结合当前版本号，生成 AppUpdateInfo
     *
     * @param jsonStr        服务器返回的 JSON 字符串
     * @param currentVersion 当前本地模块版本号，例如 "0.9.0"
     */
    public static AppUpdateInfo parse(String jsonStr, String currentVersion) throws JSONException {
        if (jsonStr == null || jsonStr.trim().isEmpty()) {
            return null;
        }

        JSONObject obj = new JSONObject(jsonStr);
        String latestVer    = obj.optString("version", "");
        String downloadUrl  = obj.optString("appUrl", "");
        String changelogUrl = obj.optString("changelog", "");
        if (latestVer.isEmpty() || downloadUrl.isEmpty()) {
            // 必要字段缺失，当作无效
            return null;
        }
        boolean hasNew = !latestVer.equals(currentVersion);
        return new AppUpdateInfo(hasNew, latestVer, downloadUrl, changelogUrl);
    }

}
