package com.linux.permissionmanager.update;

import android.app.Activity;
import android.text.TextUtils;
import android.util.Log;

import com.linux.permissionmanager.model.SkrModInstalledItem;
import com.linux.permissionmanager.model.SkrModUpdateInfo;
import com.linux.permissionmanager.utils.NetUtils;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.List;
import java.util.function.BiConsumer;

public class SkrModUpdateChecker {

    private final Activity activity;

    public SkrModUpdateChecker(Activity activity) {
        this.activity = activity;
    }

    /**
     * 单个模块：请求更新信息（在子线程下载，回调已切回 UI 线程）
     */
    public void requestModuleUpdate(
            SkrModInstalledItem item,
            BiConsumer<SkrModInstalledItem, SkrModUpdateInfo> onSuccessUi,
            BiConsumer<SkrModInstalledItem, Exception> onErrorUi
    ) {
        if (item == null) return;

        String updateUrl = item.getUpdateJson();
        if (TextUtils.isEmpty(updateUrl)) {
            // 没有配置更新地址，直接回调「无更新信息」
            if (onSuccessUi != null) activity.runOnUiThread(() -> onSuccessUi.accept(item, null));
            return;
        }

        NetUtils.downloadText(updateUrl, new NetUtils.TextDownloadCallback() {
            @Override
            public void onSuccess(String content) {
                try {
                    SkrModUpdateInfo updateInfo = parse(content, item.getVer());
                    if (onSuccessUi != null) activity.runOnUiThread(() -> onSuccessUi.accept(item, updateInfo));
                } catch (Exception e) {
                    onError(e);
                }
            }

            @Override
            public void onError(Exception e) {
                if (onErrorUi != null) activity.runOnUiThread(() -> onErrorUi.accept(item, e));
            }
        });
    }

    /**
     * 单个模块：请求更新日志内容
     */
    public void requestModuleChangelog(
            SkrModInstalledItem item,
            BiConsumer<SkrModInstalledItem, String> onSuccessUi,
            BiConsumer<SkrModInstalledItem, Exception> onErrorUi
    ) {
        if (item == null || item.getUpdateInfo() == null) {
            if (onErrorUi != null) activity.runOnUiThread(() -> onErrorUi.accept(item, new IllegalStateException("updateInfo is null")));
            return;
        }

        String url = item.getUpdateInfo().getChangelogUrl();
        if (TextUtils.isEmpty(url)) {
            if (onErrorUi != null) activity.runOnUiThread(() -> onErrorUi.accept(item, new IllegalStateException("changelogUrl is empty")));
            return;
        }

        NetUtils.downloadText(url, new NetUtils.TextDownloadCallback() {
            @Override
            public void onSuccess(String content) {
                if (onSuccessUi != null) activity.runOnUiThread(() -> onSuccessUi.accept(item, content));
            }

            @Override
            public void onError(Exception e) {
                if (onErrorUi != null) activity.runOnUiThread(() -> onErrorUi.accept(item, e));
            }
        });
    }

    /**
     * 批量检查所有模块更新
     */
    public void checkAllModulesUpdate(
            List<SkrModInstalledItem> allModules,
            BiConsumer<SkrModInstalledItem, SkrModUpdateInfo> onEachSuccessUi,
            BiConsumer<SkrModInstalledItem, Exception> onEachErrorUi
    ) {
        if (allModules == null || allModules.isEmpty()) return;

        for (SkrModInstalledItem item : allModules) {
            // 没有配置 updateJson 的直接跳过
            if (item.getUpdateJson() == null || item.getUpdateJson().isEmpty()) continue;
            requestModuleUpdate(
                    item,
                    (mod, info) -> {
                        if (onEachSuccessUi != null) onEachSuccessUi.accept(mod, info);
                    },
                    (mod, e) -> {
                        Log.w("SkrModUpdate", "check update failed: " + mod.getName(), e);
                        if (onEachErrorUi != null) onEachErrorUi.accept(mod, e);
                    }
            );
        }
    }

    /**
     * 解析服务器返回的模块更新 JSON，并结合当前版本号，生成 SkrModUpdateInfo
     *
     * @param jsonStr        服务器返回的 JSON 字符串
     * @param currentVersion 当前本地模块版本号，例如 "0.9.0"
     */
    private SkrModUpdateInfo parse(String jsonStr, String currentVersion) throws JSONException {
        if (jsonStr == null || jsonStr.trim().isEmpty()) return null;

        JSONObject obj = new JSONObject(jsonStr);
        String latestVer    = obj.optString("version", "");
        String downloadUrl  = obj.optString("zipUrl", "");
        String changelogUrl = obj.optString("changelog", "");

        if (latestVer.isEmpty() || downloadUrl.isEmpty()) return null;
        boolean hasNew = !latestVer.equals(currentVersion);
        return new SkrModUpdateInfo(hasNew, latestVer, downloadUrl, changelogUrl);
    }
}
