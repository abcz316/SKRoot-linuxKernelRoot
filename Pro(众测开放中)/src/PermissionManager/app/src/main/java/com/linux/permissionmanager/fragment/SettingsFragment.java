package com.linux.permissionmanager.fragment;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Paint;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.PopupMenu;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.Fragment;

import com.linux.permissionmanager.R;
import com.linux.permissionmanager.bridge.NativeBridge;
import com.linux.permissionmanager.model.AppUpdateInfo;
import com.linux.permissionmanager.update.AppUpdateManager;
import com.linux.permissionmanager.utils.DialogUtils;
import com.linux.permissionmanager.utils.UrlIntentUtils;

public class SettingsFragment extends Fragment {
    private Activity mActivity;
    private String mRootKey = "";

    private CheckBox mCkboxEnableBootFailProtect;
    private CheckBox mCkboxAdbForcedDisabled;
    private Button mBtnTestSkrootBasics;
    private Button mBtnTestSkrootDefaultModule;
    private Button mBtnReboot;
    private CheckBox mCkboxEnableSkrootLog;
    private Button mBtnShowSkrootLog;
    private Button mBtnClearSkrootLog;
    private TextView mTvAboutVer;
    private TextView mTvModuleDevGuidePdf;
    private TextView mTvLink;
    private TextView mTvTg;

    // Update component
    private LinearLayout mTvUpdateBlock;
    private TextView mTvUpdateFound;
    private TextView mTvUpdateChangelog;
    private TextView mTvUpdateDownload;
    private AppUpdateManager mUpdateManager;

    public SettingsFragment(Activity activity, String rootKey) {
        mActivity = activity;
        mRootKey = rootKey;
        mUpdateManager = new AppUpdateManager(mActivity);
        initUpdateBlock(false);
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
                             @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_settings, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        mCkboxEnableBootFailProtect = view.findViewById(R.id.enable_boot_fail_protect_ckbox);
        mCkboxAdbForcedDisabled = view.findViewById(R.id.adb_forced_disabled_ckbox);
        mBtnTestSkrootBasics = view.findViewById(R.id.test_skroot_basics_btn);
        mBtnTestSkrootDefaultModule = view.findViewById(R.id.test_skroot_default_module_btn);
        mBtnReboot = view.findViewById(R.id.reboot_btn);
        mCkboxEnableSkrootLog = view.findViewById(R.id.enable_skroot_log_ckbox);
        mBtnShowSkrootLog = view.findViewById(R.id.show_skroot_log_btn);
        mBtnClearSkrootLog = view.findViewById(R.id.clear_skroot_log_btn);
        mTvAboutVer = view.findViewById(R.id.about_ver_tv);
        mTvModuleDevGuidePdf = view.findViewById(R.id.module_dev_guide_pdf_tv);
        mTvLink = view.findViewById(R.id.link_tv);
        mTvTg = view.findViewById(R.id.tg_tv);

        // Update component
        mTvUpdateBlock = view.findViewById(R.id.core_update_block);
        mTvUpdateFound = view.findViewById(R.id.core_update_found_tv);
        mTvUpdateChangelog = view.findViewById(R.id.core_update_changelog_tv);
        mTvUpdateDownload = view.findViewById(R.id.core_update_download_tv);
        initSettingsControl();
    }

    private void initSettingsControl() {
        mCkboxEnableBootFailProtect.setOnCheckedChangeListener(null);
        mCkboxEnableBootFailProtect.setChecked(NativeBridge.isBootFailProtectEnabled(mRootKey));
        mCkboxEnableBootFailProtect.setOnCheckedChangeListener(
                (v, isChecked) -> {
                    String tip = NativeBridge.setBootFailProtectEnabled(mRootKey, isChecked);
                    DialogUtils.showMsgDlg(mActivity, "执行结果", tip, null);
                }
        );
        mCkboxAdbForcedDisabled.setOnCheckedChangeListener(null);
        mCkboxAdbForcedDisabled.setChecked(NativeBridge.isAdbForcedDisabled(mRootKey));
        mCkboxAdbForcedDisabled.setOnCheckedChangeListener(
                (v, isChecked) -> {
                    String tip = NativeBridge.setAdbForcedDisabled(mRootKey, isChecked);
                    DialogUtils.showMsgDlg(mActivity, "执行结果", tip, null);
                }
        );
        mBtnTestSkrootBasics.setOnClickListener((v) -> showSelectTestSkrootBasicsDlg());
        mBtnTestSkrootDefaultModule.setOnClickListener((v) -> showSelectTestDefaultModuleDlg());
        mBtnReboot.setOnClickListener((v) -> showRebootSelectDlg());

        mCkboxEnableSkrootLog.setOnCheckedChangeListener(null);
        mCkboxEnableSkrootLog.setChecked(NativeBridge.isSkrootLogEnabled(mRootKey));
        mCkboxEnableSkrootLog.setOnCheckedChangeListener(
                (v, isChecked) -> {
                    String tip = NativeBridge.setSkrootLogEnabled(mRootKey, isChecked);
                    DialogUtils.showMsgDlg(mActivity, "执行结果", tip, null);
                }
        );
        mBtnShowSkrootLog.setOnClickListener(v -> showSkrootLogDlg());
        mBtnClearSkrootLog.setOnClickListener(v -> clearSkrootLog());
        initAboutText();
        initLink();
        initUpdateBlock(true);
    }

    private void showSelectTestSkrootBasicsDlg() {
        final String[] items = {"1.通道检查", "2.内核起始地址检查", "3.写入内存测试", "4.读取跳板测试", "5.写入跳板测试", "6.物理地址计算测试"};
        AlertDialog.Builder builder = new AlertDialog.Builder(mActivity);
        builder.setTitle("请选择一个选项");
        builder.setSingleChoiceItems(items, -1, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                dialog.dismiss();
                String item = "";
                if(which == 0) item = "Channel";
                else if(which == 1) item = "KernelBase";
                else if(which == 2) item = "WriteTest";
                else if(which == 3) item = "ReadTrampoline";
                else if(which == 4) item = "WriteTrampoline";
                else if(which == 5) item = "PhysAddrCalc";
                String log = NativeBridge.testSkrootBasics(mRootKey, item);
                if(log.contains("ERR_MODULE_MUST_UNINSTALL")) log += "\n请先卸载 SKRoot 环境，再重试。";
                DialogUtils.showLogDialog(mActivity, log, true);
            }
        });
        builder.setNegativeButton("取消", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) { dialog.dismiss(); }
        });
        AlertDialog dialog = builder.create();
        dialog.show();
    }

    private void showSelectTestDefaultModuleDlg() {
        final String[] items = {"1.Root 权限模块 (打印)", "2.Root 权限模块 (执行)", "3.su 重定向模块 (打印)", "4.su 重定向模块 (执行)", "5.系统目录净化模块 (打印)"};
        DialogUtils.showSingleChoiceDialog(mActivity, null, items, -1,
                (dialog, which) -> {
                    String defName = "";
                    if(which == 0) defName = "RootBridgePrint";
                    else if(which == 1) defName = "RootBridgeExec";
                    else if(which == 2) defName = "SuRedirectPrint";
                    else if(which == 3) defName = "SuRedirectExec";
                    else if(which == 4) defName = "TombstonesPurgePrint";
                    String log = NativeBridge.testSkrootDefaultModule(mRootKey, defName);
                    if(log.contains("ERR_MODULE_MUST_UNINSTALL")) log += "\n请先卸载 SKRoot 环境，再重试。";
                    DialogUtils.showLogDialog(mActivity, log, true);
                }
        );


    }

    private enum RebootAction {
        NORMAL("普通重启", "setprop sys.powerctl reboot", false),
        SOFT("软重启", null, true),
        RECOVERY("重启到 Recovery", "setprop sys.powerctl reboot,recovery", false),
        BOOTLOADER("重启到 Fastboot", "setprop sys.powerctl reboot,bootloader", false),
        FASTBOOTD("重启到 FastbootD", "setprop sys.powerctl reboot,fastboot", false);
        final String title;
        final String cmd;
        final boolean softReboot;
        RebootAction(String title, String cmd, boolean softReboot) {
            this.title = title;
            this.cmd = cmd;
            this.softReboot = softReboot;
        }
        static RebootAction fromId(int id) {
            RebootAction[] actions = values();
            if (id < 0 || id >= actions.length) return null;
            return actions[id];
        }
    }

    private void showRebootSelectDlg() {
        final String[] items = {
                "1.普通重启",
                "2.软重启",
                "3.重启到 Recovery",
                "4.重启到 Fastboot",
                "5.重启到 FastbootD",
        };
        DialogUtils.showSingleChoiceDialog(mActivity, null, items, -1,
                (dialog, which) -> {
                    RebootAction action = RebootAction.fromId(which);
                    if (action == null) return;
                    showConfirmRebootDialog(action);
                }
        );
    }

    private void showConfirmRebootDialog(RebootAction action) {
        DialogUtils.showCustomDialog(mActivity,"确认", "确定要" + action.title + "吗？",null, "确定",
                (dialog, which) -> {
                    dialog.dismiss();
                    String tip = runRebootAction(action);
                    DialogUtils.showMsgDlg(mActivity, "执行结果", tip, null);
                },"取消", (dialog, which) -> dialog.dismiss()
        );
    }

    private String runRebootAction(RebootAction action) {
        if (action.softReboot) return NativeBridge.restartZygote64(mRootKey);
        return NativeBridge.runRootCmd(mRootKey, action.cmd);
    }

    private void showSkrootLogDlg() {
        String log = NativeBridge.readSkrootLog(mRootKey);
        DialogUtils.showLogDialog(mActivity, log, true);
    }

    private void clearSkrootLog() {
        String tip = NativeBridge.clearSkrootLog(mRootKey);
        DialogUtils.showMsgDlg(mActivity, "执行结果", tip, null);
    }

    private void initAboutText() {
        StringBuffer sb = new StringBuffer();
        sb.append("内置核心版本：");
        sb.append(NativeBridge.getSdkVersion());
        mTvAboutVer.setText(sb.toString());
    }

    static public void openModuleDevGuidePdf(Context ctx) {
        String url = "https://abcz316.github.io/SKRoot-linuxKernelRoot/skroot_pro_app/module_developer_help.pdf";
        UrlIntentUtils.openUrl(ctx, url);
    }

    private void initLink() {
        mTvLink.setText("github.com/abcz316/SKRoot-linuxKernelRoot");
        mTvTg.setText("t.me/skrootabc");
        mTvModuleDevGuidePdf.setOnClickListener(v -> openModuleDevGuidePdf(mActivity));
        mTvLink.setOnClickListener(v -> UrlIntentUtils.openUrl(mActivity, mTvLink.getText().toString()));
        mTvTg.setOnClickListener(v -> UrlIntentUtils.openUrl(mActivity, mTvTg.getText().toString()));
        makeUnderline(mTvModuleDevGuidePdf);
        makeUnderline(mTvLink);
        makeUnderline(mTvTg);
    }

    private void onDownloadChangeLogApp(AppUpdateInfo updateInfo) {
        mUpdateManager.requestAppChangelog(updateInfo,
                (content) -> DialogUtils.showLogDialog(mActivity, content, false),
                (e) -> DialogUtils.showMsgDlg(mActivity, "提示", "App 更新日志下载失败：" + e.getMessage(),null)
        );
    }

    private void showAppUpdateInfo(AppUpdateInfo info) {
        if (info == null || !info.isHasNewVersion()) return;
        mTvUpdateBlock.setVisibility(View.VISIBLE);
        mTvUpdateFound.setText("发现新版本：" + info.getLatestVer());
        mTvUpdateChangelog.setOnClickListener(v -> onDownloadChangeLogApp(info));
        mTvUpdateDownload.setOnClickListener(v -> UrlIntentUtils.openUrl(mActivity, info.getDownloadUrl()));
    }

    private void showAppUpdateDialog(AppUpdateInfo info) {
        if (info == null || !info.isHasNewVersion()) return;
        DialogUtils.showCustomDialog(mActivity, "提示", "发现新版本：" + info.getLatestVer(), null, "确定",
                (dialog, which) -> {
                    UrlIntentUtils.openUrl(mActivity, info.getDownloadUrl());
                    dialog.dismiss();
                },"取消", (dialog, which) -> dialog.dismiss()
        );
    }

    private void initUpdateBlock(boolean updateUI) {
        if (updateUI) {
            makeUnderline(mTvUpdateChangelog);
            makeUnderline(mTvUpdateDownload);
        }
        final boolean[] updateDialogShown = {false};
        AppUpdateInfo cacheInfo = mUpdateManager.getAppUpdateResponseCache();
        if (cacheInfo != null && cacheInfo.isHasNewVersion()) {
            if (updateUI) showAppUpdateInfo(cacheInfo);
            showAppUpdateDialog(cacheInfo);
            updateDialogShown[0] = true;
        }
        mUpdateManager.requestAppUpdate(
                (info) -> {
                    if (info == null || !info.isHasNewVersion()) return;
                    if (updateUI) showAppUpdateInfo(info);
                    if (!updateDialogShown[0]) {
                        updateDialogShown[0] = true;
                        showAppUpdateDialog(info);
                    }
                }, (e) -> {}
        );
    }

    private void makeUnderline(TextView tv) {
        tv.getPaint().setFlags(tv.getPaintFlags() | Paint.UNDERLINE_TEXT_FLAG);
    }
}
