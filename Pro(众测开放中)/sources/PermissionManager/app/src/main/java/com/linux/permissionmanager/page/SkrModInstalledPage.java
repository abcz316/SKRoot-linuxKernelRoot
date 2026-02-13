package com.linux.permissionmanager.page;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.text.TextUtils;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.PopupMenu;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.SimpleItemAnimator;

import com.linux.permissionmanager.ActivityResultId;
import com.linux.permissionmanager.R;
import com.linux.permissionmanager.adapter.SkrModInstalledAdapter;
import com.linux.permissionmanager.adapter.SkrModPrinter;
import com.linux.permissionmanager.bridge.NativeBridge;
import com.linux.permissionmanager.model.SkrModInstalledItem;
import com.linux.permissionmanager.model.SkrModUpdateInfo;
import com.linux.permissionmanager.update.SkrModDownloader;
import com.linux.permissionmanager.update.SkrModInstaller;
import com.linux.permissionmanager.update.SkrModUpdateChecker;
import com.linux.permissionmanager.utils.DialogUtils;
import com.linux.permissionmanager.utils.FileUtils;
import com.linux.permissionmanager.utils.GetSdcardPermissionsHelper;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class SkrModInstalledPage {
    private Activity mActivity;
    private String mRootKey = "";

    private RecyclerView mSkrModInstalledRecyclerView;
    private TextView mTextEmptyTips;

    private SkrModInstalledAdapter mAdapter;
    private SkrModUpdateChecker mUpdateManager;

    public SkrModInstalledPage(Activity activity, String rootKey) {
        mActivity = activity;
        mRootKey = rootKey;
    }

    public void bindPage(@NonNull View view) {
        mSkrModInstalledRecyclerView = view.findViewById(R.id.skr_mod_installed_recycler_view);
        mTextEmptyTips = view.findViewById(R.id.empty_tips_tv);

        mUpdateManager = new SkrModUpdateChecker(mActivity);
        setupSkrModRecyclerView();
    }

    public void refreshPage() { setupSkrModRecyclerView(); }

    private void setupSkrModRecyclerView() {
        String jsonAll = NativeBridge.getSkrootModuleList(mRootKey, false);
        List<SkrModInstalledItem> listAll = parseSkrModList(jsonAll);
        if(!listAll.isEmpty()) {
            String jsonRunning = NativeBridge.getSkrootModuleList(mRootKey, true);
            List<SkrModInstalledItem> listRunning = parseSkrModList(jsonRunning);
            Set<String> runningUuids = (listRunning == null) ?
                    Collections.emptySet() :
                    listRunning.stream()
                            .map(SkrModInstalledItem::getUuid)
                            .filter(Objects::nonNull)
                            .collect(Collectors.toSet());
            listAll.forEach(it -> it.setRunning(
                    it.getUuid() != null && runningUuids.contains(it.getUuid())
            ));
        }
        mAdapter = new SkrModInstalledAdapter(listAll, new SkrModInstalledAdapter.OnItemClickListener() {
            @Override
            public void onOpenWebUIBtnClick(View v, SkrModInstalledItem skrmod) { onOpenSkrModWebUI(skrmod); }
            @Override
            public void onNewVersionBtnClick(View v, SkrModInstalledItem skrmod) { onUpdateSkrMod(skrmod); }
            @Override
            public void onMoreBtnClick(View v, SkrModInstalledItem skrmod) { showSkrModItemPopupMenu(v, skrmod); }
        });
        mSkrModInstalledRecyclerView.setAdapter(mAdapter);
        mSkrModInstalledRecyclerView.setLayoutManager(new LinearLayoutManager(mActivity));
        mSkrModInstalledRecyclerView.setVisibility(listAll.size() == 0 ? View.GONE : View.VISIBLE);
        mTextEmptyTips.setVisibility(listAll.size() == 0 ? View.VISIBLE : View.GONE);
        RecyclerView.ItemAnimator animator = mSkrModInstalledRecyclerView.getItemAnimator();
        if (animator instanceof SimpleItemAnimator) ((SimpleItemAnimator) animator).setSupportsChangeAnimations(false);
        checkAllModulesUpdate(listAll);
    }

    private List<SkrModInstalledItem> parseSkrModList(String jsonStr) {
        List<SkrModInstalledItem> list = new ArrayList<>();
        try {
            JSONArray jsonArray = new JSONArray(jsonStr);
            for (int i = 0; i < jsonArray.length(); i++) {
                JSONObject jsonObject = jsonArray.getJSONObject(i);
                String name = URLDecoder.decode(jsonObject.getString("name"), "UTF-8");
                String ver = URLDecoder.decode(jsonObject.getString("ver"), "UTF-8");
                String desc = URLDecoder.decode(jsonObject.getString("desc"), "UTF-8");
                String author = URLDecoder.decode(jsonObject.getString("author"), "UTF-8");
                String uuid = URLDecoder.decode(jsonObject.getString("uuid"), "UTF-8");
                String update_json = URLDecoder.decode(jsonObject.getString("update_json"), "UTF-8");
                boolean web_ui = jsonObject.getBoolean("web_ui");
                String min_sdk_ver = URLDecoder.decode(jsonObject.getString("min_sdk_ver"), "UTF-8");
                SkrModInstalledItem e = new SkrModInstalledItem(name, desc, ver, uuid, author, update_json, min_sdk_ver, web_ui, false);
                list.add(e);
            }
        } catch (Exception e) {
            DialogUtils.showMsgDlg(mActivity, "发生错误", jsonStr, null);
            e.printStackTrace();
        }
        return list;
    }

    private void showSkrModItemPopupMenu(View v, SkrModInstalledItem skrMod) {
        PopupMenu popupMenu = new PopupMenu(mActivity, v);
        Menu menu = popupMenu.getMenu();
        popupMenu.getMenuInflater().inflate(R.menu.popup_skr_mod_installed_item_menu, menu);

        // 是否显示“更新”菜单
        MenuItem updateItem = menu.findItem(R.id.update);
        updateItem.setVisible(skrMod.getUpdateJson().length() > 0);

        // 是否显示“更新日志”菜单
        MenuItem changelogItem = menu.findItem(R.id.changelog);
        changelogItem.setVisible(updateItem.isVisible());
        changelogItem.setEnabled(skrMod.hasChangelog());

        popupMenu.setOnMenuItemClickListener(item -> {
            int itemId = item.getItemId();
            if (itemId == R.id.del) onDeleteSkrMod(skrMod);
            else if (itemId == R.id.update) onUpdateSkrMod(skrMod);
            else if (itemId == R.id.changelog) onDownloadChangeLogSkrMod(skrMod);
            else if (itemId == R.id.details) onShowDetailsSkrMod(skrMod);
            return true;
        });
        popupMenu.show();
    }

    private void onAddSkrMod(String zipFilePath) {
        SkrModInstaller.installFromZip(mActivity, mRootKey, zipFilePath);
        refreshPage();
    }

    private void onDeleteSkrMod(SkrModInstalledItem skrMod) {
        DialogUtils.showCustomDialog(mActivity, "确认", "确定要删除 " + skrMod.getName() + " 模块吗？", null, "确定",
				(dialog, which) -> {
                    dialog.dismiss();
                    String tip = NativeBridge.uninstallSkrootModule(mRootKey, skrMod.getUuid());
                    if(tip.indexOf("OK") != -1) tip += "，重启后生效";
                    DialogUtils.showMsgDlg(mActivity, "执行结果", tip, null);
                    refreshPage();
                },
                "取消", (dialog, which) -> dialog.dismiss()
        );
    }

    private void onShowDetailsSkrMod(SkrModInstalledItem skrMod) {
        String details = SkrModPrinter.buildModuleMeta(skrMod);
        DialogUtils.showLogDialog(mActivity, details);
    }

    private void onOpenSkrModWebUI(SkrModInstalledItem skrMod) {
        String tip = NativeBridge.openSkrootModuleWebUI(mRootKey, skrMod.getUuid());
        DialogUtils.showMsgDlg(mActivity, "执行结果", tip, null);
    }

    private void onUpdateSkrMod(SkrModInstalledItem skrMod) {
        mUpdateManager.requestModuleUpdate(
                skrMod,
                (item, info) -> {
                    if (info != null) mAdapter.updateModuleUpdateInfo(item.getUuid(), info);
                    if (info == null || !info.isHasNewVersion()) {
                        DialogUtils.showMsgDlg(mActivity, "提示", "当前已是最新版本", null);
                        return;
                    }
                    String message = "检测到新版本：" + info.getLatestVer() + "\n\n是否下载并更新该模块？";
                    DialogUtils.showCustomDialog(mActivity,"模块更新", message,null,"立即更新", (dialog, which) -> {
                        dialog.dismiss();
                        onDownloadNewSkrMod(item, info);
                    },"取消", (dialog, which) -> dialog.dismiss());
                },
                (item, e) -> DialogUtils.showMsgDlg(mActivity,"提示","检查模块 \"" + item.getName() + "\" 更新失败：" + e.getMessage(),null)
        );
    }

    private void onDownloadChangeLogSkrMod(SkrModInstalledItem skrMod) {
        mUpdateManager.requestModuleChangelog(skrMod,
                (item, content) -> DialogUtils.showLogDialog(mActivity, content),
                (item, e) -> DialogUtils.showMsgDlg(mActivity,"提示", "下载模块 \"" + item.getName() + "\" 的更新日志失败：" + e.getMessage(),null)
        );
    }

    private void checkAllModulesUpdate(List<SkrModInstalledItem> listAll) {
        if (listAll == null || listAll.isEmpty()) return;
        mUpdateManager.checkAllModulesUpdate(
                listAll,
                (mod, info) -> {
                    if (info != null && mAdapter != null) mAdapter.updateModuleUpdateInfo(mod.getUuid(), info);
                },
                (mod, e) -> Log.w("SkrMod", "check update failed: " + mod.getName(), e)
        );
    }

    private void onDownloadNewSkrMod(SkrModInstalledItem skrMod, SkrModUpdateInfo updateInfo) {
        String url = updateInfo.getDownloadUrl();
        if (TextUtils.isEmpty(url)) {
            DialogUtils.showMsgDlg(mActivity, "提示","模块 \"" + skrMod.getName() + "\" 未提供下载地址。", null);
            return;
        }
        SkrModDownloader downloader = new SkrModDownloader(mActivity);
        downloader.downloadToCache(url, skrMod.getUuid() + "_" + updateInfo.getLatestVer() + ".zip", SkrModDownloader.AutoDelete.ON_BOTH,
                new SkrModDownloader.Callback() {
                    @Override
                    public void onSuccess(File file) { onAddSkrMod(file.getAbsolutePath()); }
                    @Override
                    public void onError(Exception e) {
                        DialogUtils.showMsgDlg(mActivity, "下载失败", e != null ? e.getMessage() : "未知错误", null);
                    }
                });
    }

    public void showSkrModMainPopupMenu(View v) {
        PopupMenu popupMenu = new PopupMenu(mActivity, v);
        popupMenu.getMenuInflater().inflate(R.menu.popup_skr_mod_main_menu, popupMenu.getMenu());
        popupMenu.setOnMenuItemClickListener(item -> {
            int itemId = item.getItemId();
            if (itemId == R.id.add_skr_mod) chooseFile();
            return true;
        });
        popupMenu.show();
    }

    private void chooseFile() {
        if(!GetSdcardPermissionsHelper.getPermissions(mActivity, mActivity, mActivity.getPackageName())) {
            DialogUtils.showNeedPermissionDialog(mActivity);
            return;
        }
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("application/zip");
        mActivity.startActivityForResult(intent, ActivityResultId.REQUEST_CODE_CHOOSE_FILE);
    }

    public void onChooseFileActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == ActivityResultId.REQUEST_CODE_CHOOSE_FILE && resultCode == Activity.RESULT_OK) {
            Uri uri = data.getData();
            String filePath = FileUtils.getRealPathFromURI(mActivity, uri);
            if (filePath == null) {
                Log.e("SkrModFragment", "Invalid file path");
                return;
            }
            onAddSkrMod(filePath);
        }
    }


}
