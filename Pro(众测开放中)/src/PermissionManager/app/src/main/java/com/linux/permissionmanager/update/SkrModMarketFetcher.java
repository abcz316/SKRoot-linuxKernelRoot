package com.linux.permissionmanager.update;

import android.os.Handler;
import android.os.Looper;

import com.linux.permissionmanager.model.SkrModMarketItem;
import com.linux.permissionmanager.utils.NetUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class SkrModMarketFetcher {
    public static final String MARKET_JSON_URL = "https://abcz316.github.io/SKRoot-linuxKernelRoot/skroot_pro_app/module_market.json";
    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static volatile SkrModMarketFetcher sInstance;

    private final List<Consumer<List<SkrModMarketItem>>> mSuccessCallbacks = new ArrayList<>();
    private final List<Consumer<Exception>> mErrorCallbacks = new ArrayList<>();
    private List<SkrModMarketItem> mCache;
    private boolean mFetching = false;

    public static SkrModMarketFetcher getInstance() {
        if (sInstance == null) {
            synchronized (SkrModMarketFetcher.class) {
                if (sInstance == null) sInstance = new SkrModMarketFetcher();
            }
        }
        return sInstance;
    }

    public void request(Consumer<List<SkrModMarketItem>> onSuccess, Consumer<Exception> onError) {
        synchronized (this) {
            // 有缓存，秒回
            if (mCache != null) {
                postSuccess(onSuccess, mCache);
                return;
            }
            // 没有缓存，先排队
            mSuccessCallbacks.add(onSuccess);
            mErrorCallbacks.add(onError);
            // 防重入：已有请求在飞
            if (mFetching) return;
            mFetching = true;
        }
        fetch();
    }

    private void fetch() {
        NetUtils.downloadText(MARKET_JSON_URL, new NetUtils.TextDownloadCallback() {
            @Override
            public void onSuccess(String content) {
                List<SkrModMarketItem> list;
                try {
                    list = parseMarketJson(content);
                } catch (Exception e) {
                    finishError(e);
                    return;
                }
                finishSuccess(list);
            }

            @Override
            public void onError(Exception e) {
                finishError(e);
            }
        });
    }

    private void finishSuccess(List<SkrModMarketItem> list) {
        List<Consumer<List<SkrModMarketItem>>> tmp;
        synchronized (this) {
            mCache = list;
            mFetching = false;
            tmp = new ArrayList<>(mSuccessCallbacks);
            mSuccessCallbacks.clear();
            mErrorCallbacks.clear();
        }
        for (Consumer<List<SkrModMarketItem>> cb : tmp) postSuccess(cb, list);
    }

    private void finishError(Exception e) {
        List<Consumer<Exception>> tmp;
        synchronized (this) {
            mFetching = false;
            tmp = new ArrayList<>(mErrorCallbacks);
            mSuccessCallbacks.clear();
            mErrorCallbacks.clear();
        }
        for (Consumer<Exception> cb : tmp) postError(cb, e);
    }

    private void postSuccess(Consumer<List<SkrModMarketItem>> cb, List<SkrModMarketItem> list) {
        if (cb != null) MAIN.post(() -> cb.accept(list));
    }

    private void postError(Consumer<Exception> cb, Exception e) {
        if (cb != null) MAIN.post(() -> cb.accept(e));
    }

    public static List<SkrModMarketItem> parseMarketJson(String jsonStr) throws Exception {
        List<SkrModMarketItem> result = new ArrayList<>();
        org.json.JSONObject root = new org.json.JSONObject(jsonStr);
        org.json.JSONArray list = root.optJSONArray("module_list");
        if (list == null) return result;
        for (int i = 0; i < list.length(); i++) {
            org.json.JSONObject it = list.optJSONObject(i);
            if (it == null || it.optBoolean("ban", false)) continue;
            result.add(new SkrModMarketItem(
                    it.optString("chn_name", ""),
                    it.optString("eng_name", ""),
                    it.optString("desc", ""),
                    it.optString("ver", ""),
                    it.optString("id32", ""),
                    it.optString("author", ""),
                    it.optString("update_date", ""),
                    it.optString("source_url", ""),
                    it.optString("download_url", ""),
                    it.optString("download_chn_alert", ""),
                    it.optString("download_eng_alert", "")
            ));
        }
        return result;
    }
}
