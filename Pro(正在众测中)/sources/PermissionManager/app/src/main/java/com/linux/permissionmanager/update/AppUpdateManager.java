package com.linux.permissionmanager.update;

import android.app.Activity;
import android.text.TextUtils;

import com.linux.permissionmanager.BuildConfig;
import com.linux.permissionmanager.model.AppUpdateInfo;
import com.linux.permissionmanager.utils.NetUtils;

import java.util.function.Consumer;

public class AppUpdateManager {

    private final Activity activity;
    private final String updateJsonUrl = "https://abcz316.github.io/SKRoot-linuxKernelRoot/skroot_pro_app/update.json";

    public AppUpdateManager(Activity activity) {
        this.activity = activity;
    }

    /**
     * 主工程 App：请求更新信息（在子线程下载，回调已切回 UI 线程）
     */
    public void requestAppUpdate(
            Consumer<AppUpdateInfo> onSuccessUi,
            Consumer<Exception> onErrorUi
    ) {
        NetUtils.downloadText(updateJsonUrl, new NetUtils.TextDownloadCallback() {
            @Override
            public void onSuccess(String content) {
                try {
                    AppUpdateInfo updateInfo = AppUpdateParser.parse(content, BuildConfig.VERSION_NAME);
                    if (onSuccessUi != null) {
                        activity.runOnUiThread(() -> onSuccessUi.accept(updateInfo));
                    }
                } catch (Exception e) {
                    onError(e);
                }
            }

            @Override
            public void onError(Exception e) {
                if (onErrorUi != null) {
                    activity.runOnUiThread(() -> onErrorUi.accept(e));
                }
            }
        });
    }

    /**
     * 主工程 App：请求更新日志内容
     */
    public void requestAppChangelog(
            AppUpdateInfo updateInfo,
            Consumer<String> onSuccessUi,
            Consumer<Exception> onErrorUi
    ) {
        if (updateInfo == null) {
            if (onErrorUi != null) {
                activity.runOnUiThread(() -> onErrorUi.accept(new IllegalStateException("updateInfo is null")));
            }
            return;
        }

        String url = updateInfo.getChangelogUrl();
        if (TextUtils.isEmpty(url)) {
            if (onErrorUi != null) {
                activity.runOnUiThread(() -> onErrorUi.accept(new IllegalStateException("changelogUrl is empty")));
            }
            return;
        }

        NetUtils.downloadText(url, new NetUtils.TextDownloadCallback() {
            @Override
            public void onSuccess(String content) {
                if (onSuccessUi != null) {
                    activity.runOnUiThread(() -> onSuccessUi.accept(content));
                }
            }

            @Override
            public void onError(Exception e) {
                if (onErrorUi != null) {
                    activity.runOnUiThread(() -> onErrorUi.accept(e));
                }
            }
        });
    }

}
