package com.linux.permissionmanager.fragment;

import static com.linux.permissionmanager.AppSettings.HOTLOAD_SHELL_PATH;
import static com.linux.permissionmanager.AppSettings.KEY_IS_HOTLOAD_MODE;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;

import com.linux.permissionmanager.AppSettings;
import com.linux.permissionmanager.R;
import com.linux.permissionmanager.bridge.NativeBridge;
import com.linux.permissionmanager.utils.ClipboardUtils;
import com.linux.permissionmanager.utils.DialogUtils;

import org.json.JSONObject;

public class HomeFragment extends Fragment implements View.OnClickListener {
    private Activity mActivity;
    private String mRootKey = "";
    private String lastInputCmd = "id";
    private String lastInputRootExecPath = "";

    private TextView tvSelinuxStatus;
    private TextView tvSeccompStatus;
    private TextView tvAdbStatus;
    private TextView tvOneplusBypassStatus;
    private EditText mConsoleEdit;
    public HomeFragment(Activity activity, String rootKey) {
        mActivity = activity;
        mRootKey = rootKey;
    }
    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
                             @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_home, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        lastInputCmd = AppSettings.getString("lastInputCmd", lastInputCmd);
        lastInputRootExecPath = AppSettings.getString("lastInputRootExecPath", lastInputRootExecPath);

        Button install_skroot_env_btn = view.findViewById(R.id.install_skroot_env_btn);
        Button uninstall_skroot_env_btn = view.findViewById(R.id.uninstall_skroot_env_btn);
        Button test_root_btn = view.findViewById(R.id.test_root_btn);
        Button run_root_cmd_btn = view.findViewById(R.id.run_root_cmd_btn);
        Button implant_app_btn_btn = view.findViewById(R.id.implant_app_btn);
        Button copy_info_btn = view.findViewById(R.id.copy_info_btn);
        Button clean_info_btn = view.findViewById(R.id.clean_info_btn);
        tvSelinuxStatus = view.findViewById(R.id.tv_selinux_status);
        tvSeccompStatus = view.findViewById(R.id.tv_seccomp_status);
        tvAdbStatus =view. findViewById(R.id.tv_adb_status);
        tvOneplusBypassStatus =view. findViewById(R.id.tv_oneplus_bypass_status);
        mConsoleEdit = view.findViewById(R.id.console_edit);

        install_skroot_env_btn.setOnClickListener(this);
        uninstall_skroot_env_btn.setOnClickListener(this);
        test_root_btn.setOnClickListener(this);
        run_root_cmd_btn.setOnClickListener(this);
        implant_app_btn_btn.setOnClickListener(this);
        copy_info_btn.setOnClickListener(this);
        clean_info_btn.setOnClickListener(this);
        showSkrootStatus();
        showSystemStatus();
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.install_skroot_env_btn:
                onClickInstallSkrootEnvBtn();
                break;
            case R.id.uninstall_skroot_env_btn:
                onClickUninstallSkrootEnvBtn();
                break;
            case R.id.test_root_btn:
                appendConsoleMsg(NativeBridge.testRoot(mRootKey));
                break;
            case R.id.run_root_cmd_btn:
                showInputRootCmdDlg();
                break;
            case R.id.implant_app_btn:
                break;
            case R.id.copy_info_btn:
                copyConsoleMsg();
                break;
            case R.id.clean_info_btn:
                cleanConsoleMsg();
                break;
            default:
                break;
        }
    }

    private boolean isSkrootChannelOK(String rootKey) { return NativeBridge.testSkrootBasics(rootKey, "Channel").contains("OK"); }

    private void showSkrootStatus() {
        String curState = NativeBridge.getSkrootEnvState(mRootKey);
        String installedVer = NativeBridge.getInstalledSkrootEnvVersion(mRootKey);
        String sdkVer = NativeBridge.getSdkVersion();
        boolean isHotload = AppSettings.getBoolean(KEY_IS_HOTLOAD_MODE, false);
        boolean isFault = false;
        if(curState.indexOf("NotInstalled") != -1) {
            appendConsoleMsg("SKRoot环境未安装！"); isFault = true;
        } else if(curState.indexOf("Fault") != -1) {
            appendConsoleMsg("SKRoot环境出现故障，核心版本：" + installedVer); isFault = true;
        } else if(curState.indexOf("Running") != -1) {
            if (sdkVer.equals(installedVer)) {  
                appendConsoleMsg("SKRoot环境运行中，核心版本：" + installedVer);
            } else {
                appendConsoleMsg("SKRoot环境运行中，核心版本：" + installedVer + "，版本太低，请升级！");
                appendConsoleMsg("升级方式：请重新安装 SKRoot 环境。");
            }
        }
        if(isHotload && isFault) {
            appendConsoleMsg(isSkrootChannelOK(mRootKey) ? "当前为热启动模式，请立即安装SKRoot环境。" : "当前为热启动模式，正在等待热启动补丁响应，请稍候…");
        }
    }
    private void showSystemStatus() {
        try {
            String json = NativeBridge.getSystemStatusJson();
            JSONObject obj = new JSONObject(json);
            int selinux = obj.optInt("selinux", -1);
            int seccomp = obj.optInt("seccomp", -1);
            boolean adb = obj.optBoolean("adb", false);
            // SELinux
            if (selinux == 0) setStatusText(tvSelinuxStatus, "SELinux: 宽容模式", false);
            else setStatusText(tvSelinuxStatus, "SELinux: 严格模式", true);
            // Seccomp
            // 0 = disabled, 1 = strict, 2 = filter
            if (seccomp == 2) setStatusText(tvSeccompStatus, "Seccomp: 过滤模式", true);
            else if (seccomp == 1) setStatusText(tvSeccompStatus, "Seccomp: 严格模式", false);
            else if (seccomp == 0) setStatusText(tvSeccompStatus, "Seccomp: 未开启", false);
            else setStatusText(tvSeccompStatus, "Seccomp: 未知", false);
            // ADB
            if (adb) setStatusText(tvAdbStatus, "Adb: 已开启", false);
            else setStatusText(tvAdbStatus, "Adb: 未开启", true);
            if (selinux != 0 && NativeBridge.oneplusBypassIsWorkNormal(mRootKey)) tvOneplusBypassStatus.setVisibility(View.VISIBLE);
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    private void setStatusText(TextView textView, String label, boolean ok) {
        if (ok) {
            textView.setText("✅ " + label);
            textView.setTextColor(ContextCompat.getColor(mActivity, R.color.green));
        } else {
            textView.setText("❌ " + label);
            textView.setTextColor(ContextCompat.getColor(mActivity, R.color.red));
        }
    }

    private void showInputRootCmdDlg() {
        Handler inputCallback = new Handler() {
            @Override
            public void handleMessage(@NonNull Message msg) {
                String text = (String)msg.obj;
                lastInputCmd = text;
                AppSettings.setString("lastInputCmd", lastInputCmd);
                appendConsoleMsg(text + "\n" + NativeBridge.runRootCmd(mRootKey, text));
                super.handleMessage(msg);
            }
        };
        DialogUtils.showInputDlg(mActivity, lastInputCmd, "请输入ROOT命令", null, inputCallback, null);
    }

    private void onClickInstallSkrootEnvBtn() {
        boolean isHotload = AppSettings.getBoolean(KEY_IS_HOTLOAD_MODE, false);
        String err = NativeBridge.installSkrootEnv(mRootKey, isHotload);
        appendConsoleMsg(err);
        if(isHotload && err.indexOf("OK") != -1) NativeBridge.runRootCmd(mRootKey, "rm -f " + HOTLOAD_SHELL_PATH);
    }

    private void onClickUninstallSkrootEnvBtn() {
        DialogUtils.showCustomDialog(mActivity,"确认","确定要卸载SKRoot环境吗？这会同时清空 su 授权列表和删除已安装的模块",null,
                "确定", (dialog, which) -> {
                    dialog.dismiss();
                    appendConsoleMsg(NativeBridge.uninstallSkrootEnv(mRootKey));
                },"取消", (dialog, which) -> dialog.dismiss()
        );
    }

    private void appendConsoleMsg(String msg) {
        StringBuffer txt = new StringBuffer();
        txt.append(mConsoleEdit.getText().toString());
        if (txt.length() != 0) txt.append("\n");
        txt.append(msg);
        txt.append("\n");
        mConsoleEdit.setText(txt.toString());
        mConsoleEdit.setSelection(txt.length());
    }

    private void copyConsoleMsg() {
        ClipboardUtils.copyText(mActivity, mConsoleEdit.getText().toString());
        Toast.makeText(mActivity, "复制成功", Toast.LENGTH_SHORT).show();
    }

    private void cleanConsoleMsg() {
        mConsoleEdit.setText("");
    }
}
