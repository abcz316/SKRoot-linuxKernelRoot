package com.linux.permissionmanager.update;

import android.app.Activity;
import android.text.TextUtils;
import android.util.Log;

import com.linux.permissionmanager.model.SkrModItem;
import com.linux.permissionmanager.model.SkrModUpdateInfo;
import com.linux.permissionmanager.utils.NetUtils;

import org.w3c.dom.Text;

import java.util.List;
import java.util.function.BiConsumer;

public class SkrModUpdateManager {

    private final Activity activity;

    public SkrModUpdateManager(Activity activity) {
        this.activity = activity;
    }

    /**
     * 单个模块：请求更新信息（在子线程下载，回调已切回 UI 线程）
     */
    public void requestModuleUpdate(
            SkrModItem item,
            BiConsumer<SkrModItem, SkrModUpdateInfo> onSuccessUi,
            BiConsumer<SkrModItem, Exception> onErrorUi
    ) {
        if (item == null) return;

        String updateUrl = item.getUpdateJson();
        if (TextUtils.isEmpty(updateUrl)) {
            // 没有配置更新地址，直接回调「无更新信息」
            if (onSuccessUi != null) {
                activity.runOnUiThread(() -> onSuccessUi.accept(item, null));
            }
            return;
        }

        NetUtils.downloadText(updateUrl, new NetUtils.TextDownloadCallback() {
            @Override
            public void onSuccess(String content) {
                try {
                    SkrModUpdateInfo updateInfo = SkrModUpdateParser.parse(content, item.getVer());
                    if (onSuccessUi != null) {
                        activity.runOnUiThread(() -> onSuccessUi.accept(item, updateInfo));
                    }
                } catch (Exception e) {
                    onError(e);
                }
            }

            @Override
            public void onError(Exception e) {
                if (onErrorUi != null) {
                    activity.runOnUiThread(() -> onErrorUi.accept(item, e));
                }
            }
        });
    }

    /**
     * 单个模块：请求更新日志内容
     */
    public void requestModuleChangelog(
            SkrModItem item,
            BiConsumer<SkrModItem, String> onSuccessUi,
            BiConsumer<SkrModItem, Exception> onErrorUi
    ) {
        if (item == null || item.getUpdateInfo() == null) {
            if (onErrorUi != null) {
                activity.runOnUiThread(() -> onErrorUi.accept(item, new IllegalStateException("updateInfo is null")));
            }
            return;
        }

        String url = item.getUpdateInfo().getChangelogUrl();
        if (TextUtils.isEmpty(url)) {
            if (onErrorUi != null) {
                activity.runOnUiThread(() -> onErrorUi.accept(item, new IllegalStateException("changelogUrl is empty")));
            }
            return;
        }

        NetUtils.downloadText(url, new NetUtils.TextDownloadCallback() {
            @Override
            public void onSuccess(String content) {
                if (onSuccessUi != null) {
                    activity.runOnUiThread(() -> onSuccessUi.accept(item, content));
                }
            }

            @Override
            public void onError(Exception e) {
                if (onErrorUi != null) {
                    activity.runOnUiThread(() -> onErrorUi.accept(item, e));
                }
            }
        });
    }

    /**
     * 批量检查所有模块更新
     */
    public void checkAllModulesUpdate(
            List<SkrModItem> allModules,
            BiConsumer<SkrModItem, SkrModUpdateInfo> onEachSuccessUi,
            BiConsumer<SkrModItem, Exception> onEachErrorUi
    ) {
        if (allModules == null || allModules.isEmpty()) return;

        for (SkrModItem item : allModules) {
            // 没有配置 updateJson 的直接跳过
            if (item.getUpdateJson() == null || item.getUpdateJson().isEmpty()) {
                continue;
            }
            requestModuleUpdate(
                    item,
                    (mod, info) -> {
                        if (onEachSuccessUi != null) {
                            onEachSuccessUi.accept(mod, info);
                        }
                    },
                    (mod, e) -> {
                        Log.w("SkrModUpdate", "check update failed: " + mod.getName(), e);
                        if (onEachErrorUi != null) {
                            onEachErrorUi.accept(mod, e);
                        }
                    }
            );
        }
    }
}
