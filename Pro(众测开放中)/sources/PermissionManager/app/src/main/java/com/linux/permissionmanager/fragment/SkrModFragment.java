package com.linux.permissionmanager.fragment;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.PopupMenu;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.SimpleItemAnimator;

import com.linux.permissionmanager.R;
import com.linux.permissionmanager.adapter.SkrModAdapter;
import com.linux.permissionmanager.adapter.SkrModPrinter;
import com.linux.permissionmanager.bridge.NativeBridge;
import com.linux.permissionmanager.model.SkrModItem;
import com.linux.permissionmanager.model.SkrModUpdateInfo;
import com.linux.permissionmanager.update.SkrModUpdateManager;
import com.linux.permissionmanager.utils.DialogUtils;
import com.linux.permissionmanager.utils.DownloadDialogHelper;
import com.linux.permissionmanager.utils.FileUtils;

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

public class SkrModFragment extends Fragment {
    private Activity mActivity;
    private String mRootKey = "";

    private TextView mTextEmptyTips;
    private RecyclerView mSkrModRecyclerView;
    private SkrModAdapter mAdapter;
    private SkrModUpdateManager mUpdateManager;

    public SkrModFragment(Activity activity) {
        mActivity = activity;
    }
    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
                             @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_skr_mod, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        mTextEmptyTips = view.findViewById(R.id.empty_tips_tv);
        mSkrModRecyclerView = view.findViewById(R.id.skr_mod_recycler_view);
        mUpdateManager = new SkrModUpdateManager(mActivity);
        setupSkrModRecyclerView();
    }

    public void setRootKey(String rootKey) {
        mRootKey = rootKey;
    }

    public void setupSkrModRecyclerView() {
        String jsonAll = NativeBridge.getSkrootModuleList(mRootKey, false);
        List<SkrModItem> listAll = parseSkrModList(jsonAll);
        if(!listAll.isEmpty()) {
            String jsonRunning = NativeBridge.getSkrootModuleList(mRootKey, true);
            List<SkrModItem> listRunning = parseSkrModList(jsonRunning);

            Set<String> runningUuids = (listRunning == null) ?
                    Collections.emptySet() :
                    listRunning.stream()
                            .map(SkrModItem::getUuid)
                            .filter(Objects::nonNull)
                            .collect(Collectors.toSet());
            listAll.forEach(it -> it.setRunning(
                    it.getUuid() != null && runningUuids.contains(it.getUuid())
            ));
        }

        mAdapter = new SkrModAdapter(listAll, new SkrModAdapter.OnItemClickListener() {
            @Override
            public void onOpenWebUIBtnClick(View v, SkrModItem skrmod) {
                onOpenSkrModWebUI(skrmod);
            }
            @Override
            public void onNewVersionBtnClick(View v, SkrModItem skrmod) {
                onUpdateSkrMod(skrmod);
            }
            @Override
            public void onMoreBtnClick(View v, SkrModItem skrmod) {
                showSkrModItemPopupMenu(v, skrmod);
            }
        });
        mSkrModRecyclerView.setLayoutManager(new LinearLayoutManager(getContext()));
        mSkrModRecyclerView.setAdapter(mAdapter);
        mTextEmptyTips.setVisibility(listAll.size() == 0 ? View.VISIBLE : View.GONE);
        mSkrModRecyclerView.setVisibility(listAll.size() == 0 ? View.GONE : View.VISIBLE);
        RecyclerView.ItemAnimator animator = mSkrModRecyclerView.getItemAnimator();
        if (animator instanceof SimpleItemAnimator) {
            ((SimpleItemAnimator) animator).setSupportsChangeAnimations(false);
        }
        checkAllModulesUpdate(listAll);
    }

    private List<SkrModItem> parseSkrModList(String jsonStr) {
        List<SkrModItem> list = new ArrayList<>();
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

                SkrModItem e = new SkrModItem(name, desc, ver, uuid, author, update_json, min_sdk_ver, web_ui, false);
                list.add(e);
            }
        } catch (Exception e) {
            DialogUtils.showMsgDlg(mActivity, "发生错误", jsonStr, null);
            e.printStackTrace();
        }
        return list;
    }

    private void showSkrModItemPopupMenu(View v, SkrModItem skrMod) {
        PopupMenu popupMenu = new PopupMenu(requireContext(), v);
        Menu menu = popupMenu.getMenu();
        popupMenu.getMenuInflater().inflate(R.menu.popup_skr_mod_item_menu, menu);

        // 是否显示“更新”菜单
        MenuItem updateItem = menu.findItem(R.id.update);
        updateItem.setVisible(skrMod.getUpdateJson().length() > 0);

        // 是否显示“更新日志”菜单
        MenuItem changelogItem = menu.findItem(R.id.changelog);
        changelogItem.setVisible(updateItem.isVisible());
        changelogItem.setEnabled(skrMod.hasChangelog());

        popupMenu.setOnMenuItemClickListener(item -> {
            int itemId = item.getItemId();
            if (itemId == R.id.del) {
                onDeleteSkrMod(skrMod);
            } else if (itemId == R.id.update) {
                onUpdateSkrMod(skrMod);
            } else if (itemId == R.id.changelog) {
                onDownloadChangeLogSkrMod(skrMod);
            } else if (itemId == R.id.details) {
                onShowDetailsSkrMod(skrMod);
            }
            return true;
        });
        popupMenu.show();
    }

    public void onAddSkrMod(String zipFilePath) {
        String tip = NativeBridge.installSkrootModule(mRootKey, zipFilePath);
        if(tip.indexOf("OK") != -1) tip += "，重启后生效";
        if(tip.indexOf("ERR_MODULE_REQUIRE_MIN_SDK") != -1) tip += "，当前SKRoot环境版本太低，请先升级SKRoot";
        if(tip.indexOf("ERR_MODULE_SDK_TOO_OLD") != -1) tip += "，该模块SDK版本太低，已不支持安装";
        DialogUtils.showMsgDlg(mActivity, "执行结果", tip, null);
        setupSkrModRecyclerView();
    }

    private void onDeleteSkrMod(SkrModItem skrMod) {
        DialogUtils.showCustomDialog(
                mActivity,
                "确认",
                "确定要删除 " + skrMod.getName() + " 模块吗？",
                null,
                "确定", (dialog, which) -> {
                    dialog.dismiss();
                    String tip = NativeBridge.uninstallSkrootModule(mRootKey, skrMod.getUuid());
                    if(tip.indexOf("OK") != -1) tip += "，重启后生效";
                    DialogUtils.showMsgDlg(mActivity, "执行结果", tip, null);
                    setupSkrModRecyclerView();
                },
                "取消", (dialog, which) -> {
                    dialog.dismiss();
                }
        );
    }

    private void onShowDetailsSkrMod(SkrModItem skrMod) {
        String details = SkrModPrinter.buildModuleMeta(skrMod);
        DialogUtils.showLogDialog(mActivity, details);
    }

    private void onOpenSkrModWebUI(SkrModItem skrMod) {
        String tip = NativeBridge.openSkrootModuleWebUI(mRootKey, skrMod.getUuid());
        DialogUtils.showMsgDlg(mActivity, "执行结果", tip, null);
    }

    private void onUpdateSkrMod(SkrModItem skrMod) {
        mUpdateManager.requestModuleUpdate(
                skrMod,
                (item, info) -> {
                    if (info != null) {
                        mAdapter.updateModuleUpdateInfo(item.getUuid(), info);
                    }
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
                (item, e) -> {
                    DialogUtils.showMsgDlg(mActivity,"提示","检查模块 \"" + item.getName() + "\" 更新失败：" + e.getMessage(),null);
                }
        );
    }

    private void onDownloadChangeLogSkrMod(SkrModItem skrMod) {
        mUpdateManager.requestModuleChangelog(
                skrMod,
                (item, content) -> DialogUtils.showLogDialog(mActivity, content),
                (item, e) -> DialogUtils.showMsgDlg(mActivity,"提示",
                        "下载模块 \"" + item.getName() + "\" 的更新日志失败：" + e.getMessage(),
                        null
                )
        );
    }

    private void checkAllModulesUpdate(List<SkrModItem> listAll) {
        if (listAll == null || listAll.isEmpty()) return;
        mUpdateManager.checkAllModulesUpdate(
                listAll,
                (mod, info) -> {
                    if (info != null && mAdapter != null) {
                        mAdapter.updateModuleUpdateInfo(mod.getUuid(), info);
                    }
                },
                (mod, e) -> {
                    Log.w("SkrMod", "check update failed: " + mod.getName(), e);
                }
        );
    }

    private void onDownloadNewSkrMod(SkrModItem skrMod, SkrModUpdateInfo updateInfo) {
        String url = updateInfo.getDownloadUrl();
        if (TextUtils.isEmpty(url)) {
            DialogUtils.showMsgDlg(mActivity, "提示","模块 \"" + skrMod.getName() + "\" 未提供下载地址。", null);
            return;
        }

        File dir = new File(mActivity.getCacheDir(), "skrmods");
        if (!dir.exists() && !dir.mkdirs()) {
            DialogUtils.showMsgDlg(mActivity, "错误","创建缓存目录失败，无法下载更新。", null);
            return;
        }

        String fileName = null;
        try {
            Uri uri = Uri.parse(url);
            String lastSegment = uri.getLastPathSegment();
            if (lastSegment != null && !lastSegment.trim().isEmpty()) {
                fileName = lastSegment;
            }
        } catch (Exception ignored) {}

        if (fileName == null || fileName.trim().isEmpty()) {
            fileName = skrMod.getUuid() + "_" + updateInfo.getLatestVer() + ".zip";
        }

        final File destFile = new File(dir, fileName);
        DownloadDialogHelper.startDownloadWithDialog(mActivity, url, destFile,
                new DownloadDialogHelper.DownloadResultCallback() {
                    @Override
                    public void onSuccess(File file) {
                        try {
                            onAddSkrMod(destFile.getAbsolutePath());
                        } finally {
                            FileUtils.deleteFile(destFile);
                        }
                    }
                    @Override
                    public void onError(Exception e) {
                        try {
                            DialogUtils.showMsgDlg( mActivity,"下载失败",
                                    "下载模块 \"" + skrMod.getName() + "\" 失败："+ (e != null ? e.getMessage() : "未知错误"),
                                    null);
                        } finally {
                            FileUtils.deleteFile(destFile);
                        }
                    }
                }
        );
    }

}
