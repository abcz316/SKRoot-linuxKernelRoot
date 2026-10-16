package com.android.zygotepreloadtools;

import static com.android.zygotepreloadtools.MagicaRootHelper.executeMagicaRootScript;

import androidx.appcompat.app.AppCompatActivity;

import android.content.pm.ApplicationInfo;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;

import com.android.zygotepreloadtools.bridge.NativeBridge;
import com.android.zygotepreloadtools.utils.AppLaunchUtils;
import com.android.zygotepreloadtools.utils.AppUninstallUtils;
import com.android.zygotepreloadtools.utils.DialogUtils;

import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class MainActivity extends AppCompatActivity {
    private String mRootKey = "";
    private String mGoBackPackage = "";
    private String mGoBackActivity = "";
    private String mScriptSuccessTip = "加载完成！请返回SKRoot APP继续操作";
    private String mScriptErrorTip = "加载出错，请重试或保存日志反馈";
    private String mOneplusBypassResult = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        ApplicationInfo appInfo = getApplicationInfo();
        String script = readFileToString(new File(appInfo.nativeLibraryDir, "libsh.so").getAbsolutePath());
        String jsonConfig = readFileToString(new File(appInfo.nativeLibraryDir, "libconfigjson.so").getAbsolutePath());
        if (jsonConfig != null) {
            try {
                JSONObject configJson = new JSONObject(jsonConfig);
                mGoBackPackage = configJson.optString("goBackPackageName", "");
                mGoBackActivity = configJson.optString("goBackActivityName", "");
                mScriptSuccessTip = configJson.optString("scriptSuccessTip", mScriptSuccessTip);
                mScriptErrorTip = configJson.optString("scriptErrorTip", mScriptErrorTip);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
        mRootKey = extractConfigValue(script, "ROOT_KEY");
        TextView tvRootKey = findViewById(R.id.tv_root_key);
        tvRootKey.setText("密匙：" + mRootKey);

        if (!isSkrootChannelOK(mRootKey)) {
            executeHotloadScript(script);
        } else {
            DialogUtils.showCustomDialog(this, "提示", mScriptSuccessTip, null, "确定",
                            (dialog, which) -> {
                                dialog.dismiss();
                                AppLaunchUtils.launchApp(this, mGoBackPackage, mGoBackActivity);
                            }, null, null);
        }
        Button btnUninstall = findViewById(R.id.btn_uninstall);
        btnUninstall.setOnClickListener(v -> AppUninstallUtils.uninstallSelf(this));
    }

    private String extractConfigValue(String text, String key) {
        if (TextUtils.isEmpty(text)) return "";
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("(?m)^\\s*#.*?\\b" + java.util.regex.Pattern.quote(key) + "\\s*=\\s*(\\S+)");
        java.util.regex.Matcher matcher = pattern.matcher(text);
        return matcher.find() ? matcher.group(1).trim() : "";
    }

    private void executeHotloadScript(String script) {
        if (TextUtils.isEmpty(script)) return;
        DialogUtils.LogDialog logDlg = new DialogUtils.LogDialog(this, "正在加载热启动补丁，预计需要 1 分钟");
        logDlg.appendLine("[开始执行热启动补丁]");
		logDlg.appendLine("密匙：" + mRootKey);
        executeMagicaRootScript(this, script, () -> onHotloadCompletionResult(logDlg), logDlg::appendLine);
    }

    private boolean isSkrootChannelOK(String rootKey) { return NativeBridge.testSkrootBasics(rootKey, "Channel").contains("OK"); }

    private void oneplusBypassWriteStage1() {
        mOneplusBypassResult += NativeBridge.oneplusBypassWriteStage1();
    }

    private void onHotloadCompletionResult(DialogUtils.LogDialog logDlg) {
        runOnUiThread(() -> {
            oneplusBypassWriteStage1();
            if (!TextUtils.isEmpty(mOneplusBypassResult)) logDlg.appendLine("一加Oppo内部接口拦截日志（仅用于异常排查）：\n" + mOneplusBypassResult);
            new Handler(Looper.getMainLooper()).postDelayed(() -> {
                if (isSkrootChannelOK(mRootKey)) {
                    logDlg.dismiss();
                    DialogUtils.showCustomDialog(this, "提示", mScriptSuccessTip, null, "确定",
                            (dialog, which) -> {
                                dialog.dismiss();
                                AppLaunchUtils.launchApp(this, mGoBackPackage, mGoBackActivity);
                            }, null, null);
                } else {
                    DialogUtils.showMsgDlg(this, "提示", mScriptErrorTip, null);
                }
            }, 3000);
        });
    }

    private static String readFileToString(String path) {
        try (FileInputStream in = new FileInputStream(path)) {
            byte[] bytes = new byte[in.available()];
            in.read(bytes);
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}