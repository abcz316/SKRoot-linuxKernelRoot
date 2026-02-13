package com.linux.permissionmanager.page;

import android.app.Activity;
import android.content.DialogInterface;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.PopupMenu;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.SimpleItemAnimator;

import com.linux.permissionmanager.R;
import com.linux.permissionmanager.adapter.SkrModMarketAdapter;
import com.linux.permissionmanager.bridge.NativeBridge;
import com.linux.permissionmanager.model.SkrModInstalledItem;
import com.linux.permissionmanager.model.SkrModMarketItem;
import com.linux.permissionmanager.update.SkrModDownloader;
import com.linux.permissionmanager.update.SkrModInstaller;
import com.linux.permissionmanager.utils.DialogUtils;
import com.linux.permissionmanager.utils.NetUtils;
import com.linux.permissionmanager.utils.UrlIntentUtils;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

public class SkrModMarketPage {
    private Activity mActivity;
    private String mRootKey = "";

    private final String marketJsonUrl = "https://abcz316.github.io/SKRoot-linuxKernelRoot/skroot_pro_app/module_market.json";

    private EditText mSearchEdit;
    private RecyclerView mSkrModMarketRecyclerView;
    private TextView mTextEmptyTips;
    private LinearLayout mErrorContainer;
    private Button mBtnRetry;

    private List<SkrModMarketItem> mModList = new ArrayList<>();

    private SkrModMarketAdapter mAdapter;

    private boolean mInErrorState = false;

    public SkrModMarketPage(Activity activity, String rootKey) {
        mActivity = activity;
        mRootKey = rootKey;
    }

    public void bindPage(@NonNull View view) {
        mSearchEdit = view.findViewById(R.id.market_search_edit);
        mSearchEdit.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override
            public void afterTextChanged(Editable s) {
                applyFilter(s == null ? "" : s.toString());
            }
        });

        mSkrModMarketRecyclerView = view.findViewById(R.id.skr_mod_market_recycler_view);
        mTextEmptyTips = view.findViewById(R.id.empty_tips_tv);
        mErrorContainer = view.findViewById(R.id.error_container);
        mBtnRetry = view.findViewById(R.id.btn_retry);
        mBtnRetry.setOnClickListener(v -> initMarketList());

        initMarketList();
    }

    public void refreshPage() { setupSkrModRecyclerView(mModList); }

    private void setupSkrModRecyclerView(List<SkrModMarketItem> list) {
        mAdapter = new SkrModMarketAdapter(list, new SkrModMarketAdapter.OnItemClickListener() {
            @Override
            public void onActionsBtnClick(View v, SkrModMarketItem skrmod) { showSkrModItemPopupMenu(v, skrmod); }
        });
        mSkrModMarketRecyclerView.setAdapter(mAdapter);
        mSkrModMarketRecyclerView.setLayoutManager(new LinearLayoutManager(mActivity));
        mSkrModMarketRecyclerView.setVisibility(list.size() == 0 ? View.GONE : View.VISIBLE);
        mTextEmptyTips.setVisibility(list.size() == 0 && mInErrorState == false ? View.VISIBLE : View.GONE);
        mErrorContainer.setVisibility(mInErrorState ? View.VISIBLE : View.GONE);
        RecyclerView.ItemAnimator animator = mSkrModMarketRecyclerView.getItemAnimator();
        if (animator instanceof SimpleItemAnimator) ((SimpleItemAnimator) animator).setSupportsChangeAnimations(false);
    }

    private void onAddSkrMod(String zipFilePath) {
        SkrModInstaller.installFromZip(mActivity, mRootKey, zipFilePath);
        refreshPage();
    }

    private void downloadAndInstallModule(SkrModMarketItem skrMod) {
        String url = skrMod.getDownloadUrl();
        if (TextUtils.isEmpty(url)) return;
        SkrModDownloader downloader = new SkrModDownloader(mActivity);
        downloader.downloadToCache(url, skrMod.getUuid() + "_" + skrMod.getVer() + ".zip", SkrModDownloader.AutoDelete.ON_BOTH,
                new SkrModDownloader.Callback() {
                    @Override
                    public void onSuccess(File file) { onAddSkrMod(file.getAbsolutePath()); }
                    @Override
                    public void onError(Exception e) {
                        DialogUtils.showMsgDlg(mActivity, "下载失败", e != null ? e.getMessage() : "未知错误", null);
                    }
                });
    }

    private void showSelectDownloadDlg(SkrModMarketItem skrMod) {
        final String[] items = {"1.自动下载并安装（推荐）", "2.浏览器手动下载"};
        AlertDialog.Builder builder = new AlertDialog.Builder(mActivity);
        builder.setTitle("选择下载方式");
        builder.setSingleChoiceItems(items, -1, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                dialog.dismiss();
                if(which == 0) downloadAndInstallModule(skrMod);
                else if(which == 1) UrlIntentUtils.openUrl(mActivity, skrMod.getDownloadUrl());
            }
        });
        builder.setNegativeButton("取消", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) { dialog.dismiss(); }
        });
        AlertDialog dialog = builder.create();
        dialog.show();
    }

    private void showDownloadConfirmDlg(SkrModMarketItem skrMod) {
        if(TextUtils.isEmpty(skrMod.getDownloadChnAlert())) { showSelectDownloadDlg(skrMod); return; }
        DialogUtils.showCustomDialog(mActivity, "提示", skrMod.getDownloadChnAlert(), null, "确认",
                (dialog, which) -> {
                    dialog.dismiss();
                    showSelectDownloadDlg(skrMod);
                },
                "取消", (dialog, which) -> {
                    dialog.dismiss();
                }
        );
    }

    private void showSkrModItemPopupMenu(View v, SkrModMarketItem skrMod) {
        PopupMenu popupMenu = new PopupMenu(mActivity, v);
        Menu menu = popupMenu.getMenu();
        popupMenu.getMenuInflater().inflate(R.menu.popup_skr_mod_market_item_menu, menu);

        // 是否显示“查看源代码”菜单
        MenuItem sourceItem = menu.findItem(R.id.source);
        sourceItem.setVisible(!TextUtils.isEmpty(skrMod.getSourceUrl()));

        popupMenu.setOnMenuItemClickListener(item -> {
            int itemId = item.getItemId();
            if (itemId == R.id.download) showDownloadConfirmDlg(skrMod);
            else if (itemId == R.id.source) UrlIntentUtils.openUrl(mActivity, skrMod.getSourceUrl());
            return true;
        });
        popupMenu.show();
    }

    private void initMarketList() {
        requestMarketJson(
                (modArr) -> {
                    mInErrorState = false;
                    if (modArr == null || modArr.size() == 0) return;
                    mModList = modArr;
                    setupSkrModRecyclerView(mModList);
                },
                (e) -> {
                    mInErrorState = true;
                    setupSkrModRecyclerView(mModList);
                }
        );
    }

    private void requestMarketJson(Consumer<List<SkrModMarketItem>> onSuccessUi, Consumer<Exception> onErrorUi) {
        NetUtils.downloadText(marketJsonUrl, new NetUtils.TextDownloadCallback() {
            @Override
            public void onSuccess(String content) {
                try {
                    List<SkrModMarketItem> modArr = parseMarketJson(content);
                    if (onSuccessUi != null) mActivity.runOnUiThread(() -> onSuccessUi.accept(modArr));
                } catch (Exception e) { onError(e); }
            }
            @Override
            public void onError(Exception e) {
                if (onErrorUi != null) mActivity.runOnUiThread(() -> onErrorUi.accept(e));
            }
        });
    }

    private List<SkrModMarketItem> parseMarketJson(String jsonStr) throws JSONException {
        if (jsonStr == null || jsonStr.trim().isEmpty()) return Collections.emptyList();

        JSONObject root = new JSONObject(jsonStr);
        JSONArray list = root.optJSONArray("module_list");
        if (list == null || list.length() == 0) return Collections.emptyList();

        List<SkrModMarketItem> result = new ArrayList<>(list.length());
        for (int i = 0; i < list.length(); i++) {
            JSONObject it = list.optJSONObject(i);
            if (it == null) continue;
            String chnName     = it.optString("chn_name", "");
            String engName     = it.optString("eng_name", "");
            String desc        = it.optString("desc", "");
            String ver         = it.optString("ver", "");
            String uuid        = it.optString("uuid", "");
            String author      = it.optString("author", "");
            String updateDate  = it.optString("update_date", "");
            String sourceUrl = it.optString("source_url", "");
            String downloadUrl = it.optString("download_url", "");
            String downloadChnAlert = it.optString("download_chn_alert", "");
            String downloadEngAlert = it.optString("download_eng_alert", "");
            result.add(new SkrModMarketItem(
                    chnName,
                    engName,
                    desc,
                    ver,
                    uuid,
                    author,
                    updateDate,
                    sourceUrl,
                    downloadUrl,
                    downloadChnAlert,
                    downloadEngAlert
            ));
        }
        return result;
    }

    private void applyFilter(String key) {
        if (mAdapter == null || mModList.size() == 0) return;
        String k = key == null ? "" : key.trim().toLowerCase();
        List<SkrModMarketItem> out = new ArrayList<>();
        if (k.isEmpty()) out.addAll(mModList);
        else {
            for (SkrModMarketItem it : mModList) {
                if (match(it, k)) out.add(it);
            }
        }
        mAdapter.setData(out);
        boolean empty = out.isEmpty();
        mSkrModMarketRecyclerView.setVisibility(empty ? View.GONE : View.VISIBLE);
        mErrorContainer.setVisibility(View.GONE);
        mTextEmptyTips.setVisibility(empty ? View.VISIBLE : View.GONE);
        mTextEmptyTips.setText(k.isEmpty() ? "模块市场暂无内容" : "无匹配结果");
    }

    private boolean match(SkrModMarketItem it, String k) {
        return contains(it.getChnName(), k)
                || contains(it.getEngName(), k)
                || contains(it.getAuthor(), k)
                || contains(it.getDesc(), k)
                || contains(it.getUuid(), k)
                || contains(it.getVer(), k);
    }
    
    private boolean contains(String s, String k) { return s != null && s.toLowerCase().contains(k); }
}
