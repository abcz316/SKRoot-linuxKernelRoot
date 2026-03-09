package com.linux.permissionmanager.fragment;

import android.app.Activity;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Paint;
import android.net.Uri;
import android.os.Bundle;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.UnderlineSpan;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.TextView;

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
    private Button mBtnTestSkrootBasics;
    private Button mBtnTestSkrootDefaultModule;
    private CheckBox mCkboxEnableSkrootLog;
    private Button mBtnShowSkrootLog;
    private TextView mTvAboutVer;
    private TextView mTvLink;

    // Update component
    private LinearLayout mTvUpdateBlock;
    private TextView mTvUpdateFound;
    private TextView mTvUpdateChangelog;
    private TextView mTvUpdateDownload;
    private AppUpdateManager mUpdateManager;

    public SettingsFragment(Activity activity, String rootKey) {
        mActivity = activity;
        mRootKey = rootKey;
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
        mBtnTestSkrootBasics = view.findViewById(R.id.test_skroot_basics_btn);
        mBtnTestSkrootDefaultModule = view.findViewById(R.id.test_skroot_default_module_btn);
        mCkboxEnableSkrootLog = view.findViewById(R.id.enable_skroot_log_ckbox);
        mBtnShowSkrootLog = view.findViewById(R.id.show_skroot_log_btn);
        mTvAboutVer = view.findViewById(R.id.about_ver_tv);
        mTvLink = view.findViewById(R.id.link_tv);

        // Update component
        mTvUpdateBlock = view.findViewById(R.id.core_update_block);
        mTvUpdateFound = view.findViewById(R.id.core_update_found_tv);
        mTvUpdateChangelog = view.findViewById(R.id.core_update_changelog_tv);
        mTvUpdateDownload = view.findViewById(R.id.core_update_download_tv);
        initSettingsControl();
    }

    private void initSettingsControl() {
        mCkboxEnableBootFailProtect.setChecked(NativeBridge.isBootFailProtectEnabled(mRootKey));
        mCkboxEnableBootFailProtect.setOnCheckedChangeListener(
                (v, isChecked) -> {
                    String tip = NativeBridge.setBootFailProtectEnabled(mRootKey, isChecked);
                    DialogUtils.showMsgDlg(mActivity, "执行结果", tip, null);
                }
        );
        mBtnTestSkrootBasics.setOnClickListener((v) -> showSelectTestSkrootBasicsDlg());
        mBtnTestSkrootDefaultModule.setOnClickListener((v) -> showSelectTestDefaultModuleDlg());

        mCkboxEnableSkrootLog.setChecked(NativeBridge.isSkrootLogEnabled(mRootKey));
        mCkboxEnableSkrootLog.setOnCheckedChangeListener(
                (v, isChecked) -> {
                    String tip = NativeBridge.setSkrootLogEnabled(mRootKey, isChecked);
                    DialogUtils.showMsgDlg(mActivity, "执行结果", tip, null);
                }
        );
        mBtnShowSkrootLog.setOnClickListener(v -> showSkrootLogDlg());
        mUpdateManager = new AppUpdateManager(mActivity);
        initAboutText();
        initLink();
        initUpdateBlock();
    }

    private void showSelectTestSkrootBasicsDlg() {
        final String[] items = {"1.通道检查", "2.内核起始地址检查", "3.写入内存测试", "4.读取跳板测试", "5.写入跳板测试"};
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
                String log = NativeBridge.testSkrootBasics(mRootKey, item);
                DialogUtils.showLogDialog(mActivity, log);
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
        final String[] items = {"1.ROOT 权限模块 (打印)", "2.ROOT 权限模块 (执行)", "3.SU 重定向模块 (打印)", "4.SU 重定向模块 (执行)"};
        AlertDialog.Builder builder = new AlertDialog.Builder(mActivity);
        builder.setTitle("选择一个选项");
        builder.setSingleChoiceItems(items, -1, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                dialog.dismiss();
                String defName = "";
                if(which == 0) defName = "RootBridgePrint";
                else if(which == 1) defName = "RootBridgeExec";
                else if(which == 2) defName = "SuRedirectPrint";
                else if(which == 3) defName = "SuRedirectExec";
                String log = NativeBridge.testSkrootDefaultModule(mRootKey, defName);
                DialogUtils.showLogDialog(mActivity, log);
            }
        });
        builder.setNegativeButton("取消", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) { dialog.dismiss(); }
        });
        AlertDialog dialog = builder.create();
        dialog.show();
    }

    private void showSkrootLogDlg() {
        String log = NativeBridge.readSkrootLog(mRootKey);
        DialogUtils.showLogDialog(mActivity, log);
    }

    private void initAboutText() {
        StringBuffer sb = new StringBuffer();
        sb.append("内置核心版本：");
        sb.append(NativeBridge.getSdkVersion());
        mTvAboutVer.setText(sb.toString());
    }

    private void initLink() {
        mTvLink.setText("https://github.com/abcz316/SKRoot-linuxKernelRoot");
        mTvLink.setOnClickListener(v -> {
            UrlIntentUtils.openUrl(mActivity, mTvLink.getText().toString());
        });
        makeUnderline(mTvLink);
    }

    private void onDownloadChangeLogApp(AppUpdateInfo updateInfo) {
        mUpdateManager.requestAppChangelog(
                updateInfo,
                (content) -> DialogUtils.showLogDialog(mActivity, content),
                (e) -> DialogUtils.showMsgDlg(mActivity, "提示", "App 更新日志下载失败：" + e.getMessage(),null)
        );
    }

    private void initUpdateBlock() {
        mUpdateManager.requestAppUpdate(
                (info) -> {
                    if (info == null || !info.isHasNewVersion()) return;
                    mTvUpdateBlock.setVisibility(View.VISIBLE);
                    mTvUpdateFound.setText("发现新版本：" + info.getLatestVer());
                    mTvUpdateChangelog.setOnClickListener(v -> onDownloadChangeLogApp(info));
                    mTvUpdateDownload.setOnClickListener(v -> UrlIntentUtils.openUrl(mActivity, info.getDownloadUrl()));
                    DialogUtils.showCustomDialog(
                            mActivity, "提示", "发现新版本：" + info.getLatestVer(),null,"确定",
                            (dialog, which) -> {
                                UrlIntentUtils.openUrl(mActivity, info.getDownloadUrl());
                                dialog.dismiss();
                            },
                            "取消",
                            (dialog, which) -> dialog.dismiss()
                    );
                },
                (e) -> {}
        );
        makeUnderline(mTvUpdateChangelog);
        makeUnderline(mTvUpdateDownload);
    }

    private void makeUnderline(TextView tv) {
        tv.getPaint().setFlags(tv.getPaintFlags() | Paint.UNDERLINE_TEXT_FLAG);
    }
}
