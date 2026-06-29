package com.linux.permissionmanager;

import static com.linux.permissionmanager.AppSettings.HOTLOAD_SHELL_PATH;
import static com.linux.permissionmanager.AppSettings.KEY_IS_HOTLOAD_MODE;
import static com.linux.permissionmanager.helper.MagicaRootHelper.executeMagicaRootScript;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;

import com.google.android.material.tabs.TabLayout;
import com.linux.permissionmanager.bridge.NativeBridge;
import com.linux.permissionmanager.fragment.SuAuthFragment;
import com.linux.permissionmanager.fragment.HomeFragment;
import com.linux.permissionmanager.fragment.SettingsFragment;
import com.linux.permissionmanager.fragment.SkrModFragment;
import com.linux.permissionmanager.utils.DialogUtils;
import com.linux.permissionmanager.utils.FileUtils;
import com.linux.permissionmanager.utils.GetAppListPermissionHelper;
import com.linux.permissionmanager.utils.GetSdcardPermissionsHelper;
import com.linux.permissionmanager.utils.ShellUtils;

import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;

public class MainActivity extends AppCompatActivity {
    private String mRootKey = "";
    private String mHotloadCmd = "";
    private String mHotloadMethod = "SHELL";
    private String mHotloadResult = "";
    private String mOneplusBypassResult = "";
    private Dialog mLoadingDialog;

    private HomeFragment mHomeFragm;
    private SuAuthFragment mSuAuthFragm;
    private SkrModFragment mSkrModFragm;
    private SettingsFragment mSettingsFragm;

    private TabLayout mBottomTab;
    private MenuItem mMainMenu;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_LOCKED);
        setContentView(R.layout.activity_main);
        AppSettings.init(this);
        mRootKey = AppSettings.getString("rootKey", mRootKey);
        mHotloadCmd = AppSettings.getString("hotloadCmd", mHotloadCmd);
        mHotloadMethod = AppSettings.getString("hotloadMethod", mHotloadMethod);
        checkGetAppListPermission();
        showInputRootKeyDlg();
        setupFragment("");
    }

    private void showInputRootKeyDlg() {
        boolean isHotload = AppSettings.getBoolean(KEY_IS_HOTLOAD_MODE, false);
        if (isHotload) showHotloadModeInputDlg();
        else showBootModeInputDlg();
    }

    private void showModeSelectDlg(boolean currentIsHotload, @NonNull Runnable onSelectBoot, @NonNull Runnable onSelectHotload) {
        final String[] items = {"1.刷 Boot 模式", "2.热启动模式"};
        DialogUtils.showSingleChoiceDialog(this, "请选择模式", items, -1,
                (dialog, which) -> {
                    if(which == 0) {
                        if (!currentIsHotload) return;
                        AppSettings.setBoolean(KEY_IS_HOTLOAD_MODE, false);
                        onSelectBoot.run();
                    } else if(which == 1) {
                        if (currentIsHotload) return;
                        AppSettings.setBoolean(KEY_IS_HOTLOAD_MODE, true);
                        onSelectHotload.run();
                    }
                }
        );
    }

    private static class ModeRowHolder {
        LinearLayout root;
        TextView tvMode;
        TextView tvSwitch;
    }

    private ModeRowHolder createModeRow(Context context, String modeText) {
        View view = LayoutInflater.from(context).inflate(R.layout.view_mode_row, null, false);
        ModeRowHolder holder = new ModeRowHolder();
        holder.root = (LinearLayout) view;
        holder.tvMode = view.findViewById(R.id.tv_mode);
        holder.tvSwitch = view.findViewById(R.id.tv_switch);
        holder.tvMode.setText("当前模式：" + modeText);
        return holder;
    }

    private int resolveThemeColor(Context context, int attr, int fallbackColor) {
        TypedValue outValue = new TypedValue();
        if (!context.getTheme().resolveAttribute(attr, outValue, true)) return fallbackColor;
        if (outValue.resourceId != 0) return context.getResources().getColor(outValue.resourceId);
        return outValue.data;
    }
    private int withAlpha(int color, int alpha) { return (color & 0x00FFFFFF) | ((alpha & 0xFF) << 24); }

    private TextView createMiniActionButton(Context context, String text) {
        float density = context.getResources().getDisplayMetrics().density;
        int primaryColor = resolveThemeColor(context, androidx.appcompat.R.attr.colorPrimary, 0xFF6200EE);
        TextView tv = new TextView(context);
        tv.setText(text);
        tv.setTextSize(14);
        tv.setTextColor(primaryColor);
        tv.setGravity(Gravity.CENTER);
        tv.setSingleLine(true);
        tv.setPadding((int) (12 * density),(int) (5 * density),(int) (12 * density),(int) (5 * density));
        tv.setMinHeight((int) (34 * density));
        tv.setClickable(true);
        tv.setFocusable(true);
        android.graphics.drawable.GradientDrawable bg = new android.graphics.drawable.GradientDrawable();
        bg.setColor(0x00000000);
        bg.setCornerRadius(7 * density);
        bg.setStroke(Math.max(1, (int) (1 * density)), withAlpha(primaryColor, 0x66));
        tv.setBackground(bg);
        return tv;
    }

    private static void exportHotloadToSdcard(Activity activity, String text) {
        File outFile = new File(HOTLOAD_SHELL_PATH);
        FileUtils.writeTextAsync(activity, outFile, text, true, (ok, file, errMsg) -> {
            if (ok) DialogUtils.showMsgDlg(activity, "导出成功", "已存放在：" + file.getAbsolutePath(),null);
            else DialogUtils.showMsgDlg(activity,"导出失败", "无法导出到：" + file.getAbsolutePath() + "\n\n错误信息：" + (errMsg == null ? "unknown" : errMsg), null);
        });
    }

    private void showBootModeInputDlg() {
        int dp16 = (int) (16 * getResources().getDisplayMetrics().density);
        int dp4= (int) (4 * getResources().getDisplayMetrics().density);
        LinearLayout rootLayout = new LinearLayout(this);
        rootLayout.setOrientation(LinearLayout.VERTICAL);
        rootLayout.setPadding(dp16, dp16, dp16, dp4);
        TextView tipText = new TextView(this);
        tipText.setText("请输入 Root 权限的 Key");
        tipText.setTextSize(14);
        tipText.setPadding(0, dp4, 0, dp4);
        EditText inputTxt = new EditText(this);
        inputTxt.setText(mRootKey);
        inputTxt.setFocusable(true);
        inputTxt.setFocusableInTouchMode(true);
        inputTxt.setSelection(mRootKey.length());
        ModeRowHolder modeRow = createModeRow(this, "刷 Boot");
        rootLayout.addView(modeRow.root);
        rootLayout.addView(tipText);
        rootLayout.addView(inputTxt);
        final AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("Root 密钥配置")
                .setIcon(android.R.drawable.ic_dialog_info)
                .setView(rootLayout)
                .setNegativeButton("取消", null)
                .setPositiveButton("确定", (d, which) -> {
                    mRootKey = inputTxt.getText().toString().trim();
                    if(TextUtils.isEmpty(mRootKey)) return;
                    AppSettings.setString("rootKey", mRootKey);
                    AppSettings.setBoolean(KEY_IS_HOTLOAD_MODE, false);
                    setupFragment(mRootKey);
                    switchPage(0);
                }).create();
        modeRow.tvSwitch.setOnClickListener(v -> {
            dialog.dismiss();
            showModeSelectDlg(false, this::showBootModeInputDlg, this::showHotloadModeInputDlg);
        });
        dialog.show();
    }

    private String extractConfigValue(String text, String key) {
        if(TextUtils.isEmpty(text)) return "";
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("(?m)^\\s*#.*?\\b" + java.util.regex.Pattern.quote(key) + "\\s*=\\s*(\\S+)");
        java.util.regex.Matcher matcher = pattern.matcher(text);
        return matcher.find() ? matcher.group(1).trim() : "";
    }

    private void executeHotloadScript(String script, String method) {
        if(TextUtils.isEmpty(script)) return;
        DialogUtils.dismissDialog(mLoadingDialog);
        mLoadingDialog = DialogUtils.showLoadingDialog(this, "正在加载热启动补丁，预计需要 1 分钟…");
        if (TextUtils.equals(method, "MAGICA")) {
            executeMagicaRootScript(this, script, result -> {
                oneplusBypassWriteStage1(true);
                handleHotloadResult(mOneplusBypassResult + result);
            });
        } else new Thread(() ->handleHotloadResult(ShellUtils.executeScript(this, script))).start();
    }

    private boolean isSkrootChannelOK(String rootKey) { return NativeBridge.testSkrootBasics(rootKey, "Channel").contains("OK"); }

    private void handleHotloadResult(String result) {
        runOnUiThread(() -> {
            mHotloadResult = result;
            new Handler(Looper.getMainLooper()).postDelayed(() -> {
                DialogUtils.dismissDialog(mLoadingDialog);
                mLoadingDialog = null;
                if(isSkrootChannelOK(mRootKey)) {
                    DialogUtils.showMsgDlg(this, "提示","加载完成", null);
                    setupFragment(mRootKey);
                    switchPage(0);
                } else DialogUtils.showLogDialog(this, mHotloadResult, true);
            }, 3000);
        });
    }

    private void oneplusBypassWriteStage1(boolean showLog) {
        try {
            String json = NativeBridge.getSystemStatusJson();
            JSONObject obj = new JSONObject(json);
            int selinux = obj.optInt("selinux", -1);
            if (selinux != 0) return;
            mOneplusBypassResult += NativeBridge.oneplusBypassWriteStage1(mRootKey);
        } catch (Throwable e) {
            e.printStackTrace();
        }
        if(!TextUtils.isEmpty(mOneplusBypassResult)) {
            mOneplusBypassResult += "\n";
            if(showLog) DialogUtils.showLogDialog(this, "一加Oppo内部接口拦截日志（仅用于异常排查）：\n" + mOneplusBypassResult, true);
        }
    }

    private void showHotloadModeInputDlg() {
        int dp16 = (int) (16 * getResources().getDisplayMetrics().density);
        int dp6= (int) (6 * getResources().getDisplayMetrics().density);
        int dp4 = (int) (4 * getResources().getDisplayMetrics().density);
        LinearLayout rootLayout = new LinearLayout(this);
        rootLayout.setOrientation(LinearLayout.VERTICAL);
        rootLayout.setPadding(dp16, dp16, dp16, dp4);
        TextView tipText = new TextView(this);
        tipText.setText("可直接输入 Key，或将热启动补丁包放到 "+ HOTLOAD_SHELL_PATH +" 后点击“从1.h导入”");
        tipText.setTextSize(14);
        tipText.setPadding(0, dp4, 0, dp4);
        EditText inputTxt = new EditText(this);
        inputTxt.setText(mRootKey);
        inputTxt.setFocusable(true);
        inputTxt.setFocusableInTouchMode(true);
        inputTxt.setEnabled(TextUtils.isEmpty(mHotloadCmd));
        inputTxt.setSelection(mRootKey.length());
        LinearLayout actionRow = new LinearLayout(this);
        actionRow.setOrientation(LinearLayout.HORIZONTAL);
        actionRow.setPadding(0, dp16, 0, 0);
        TextView importBtn = createMiniActionButton(this, "从 1.h 导入");
        TextView exportBtn = createMiniActionButton(this, "导出");
        LinearLayout.LayoutParams importLp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT,LinearLayout.LayoutParams.WRAP_CONTENT);
        importLp.setMargins(0, 0, dp6, 0);
        LinearLayout.LayoutParams exportLp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        exportLp.setMargins(dp6, 0, 0, 0);
        actionRow.addView(importBtn, importLp);
        actionRow.addView(exportBtn, exportLp);
        ModeRowHolder modeRow = createModeRow(this, "热启动");
        rootLayout.addView(modeRow.root);
        rootLayout.addView(tipText);
        rootLayout.addView(inputTxt);
        rootLayout.addView(actionRow);
        final AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("Root 密钥配置")
                .setIcon(android.R.drawable.ic_dialog_info)
                .setView(rootLayout)
                .setNegativeButton("取消", null)
                .setPositiveButton("确定", (d, which) -> {
                    mRootKey = inputTxt.getText().toString().trim();
                    if(TextUtils.isEmpty(mRootKey)) return;
                    AppSettings.setString("rootKey", mRootKey);
                    AppSettings.setBoolean(KEY_IS_HOTLOAD_MODE, true);
                    setupFragment(mRootKey);
                    switchPage(0);
                    if (!TextUtils.isEmpty(mHotloadCmd)) {
                        if (!isSkrootChannelOK(mRootKey)) executeHotloadScript(mHotloadCmd, mHotloadMethod);
                        else oneplusBypassWriteStage1(true);
                    }
                }).create();
        modeRow.tvSwitch.setOnClickListener(v -> {
            dialog.dismiss();
            showModeSelectDlg(true, this::showBootModeInputDlg, this::showHotloadModeInputDlg);
        });

        importBtn.setOnClickListener(v -> {
            if(!GetSdcardPermissionsHelper.getPermissions(this, this, this.getPackageName())) {
                DialogUtils.showNeedPermissionDialog(this);
                return;
            }
            String scriptText = FileUtils.readTextFile(HOTLOAD_SHELL_PATH);
            if (TextUtils.isEmpty(scriptText)) {
                DialogUtils.showMsgDlg(this, "错误", "读取文件失败或文件不存在", null);
                return;
            }
            String rootKey = extractConfigValue(scriptText, "ROOT_KEY");
            String method = extractConfigValue(scriptText, "METHOD");
            if (TextUtils.isEmpty(rootKey)) return;
            mRootKey = rootKey;
            mHotloadMethod = TextUtils.isEmpty(method) ? "SHELL" : method;
            mHotloadCmd = scriptText;
            inputTxt.setText(mRootKey);
            inputTxt.setEnabled(false);
            AppSettings.setString("rootKey", mRootKey);
            AppSettings.setString("hotloadCmd", mHotloadCmd);
            AppSettings.setString("hotloadMethod", mHotloadMethod);
        });

        exportBtn.setOnClickListener(v -> {
            if(!GetSdcardPermissionsHelper.getPermissions(this, this, this.getPackageName())) {
                DialogUtils.showNeedPermissionDialog(this);
                return;
            }
            if (!TextUtils.isEmpty(mHotloadCmd)) exportHotloadToSdcard(this, mHotloadCmd);
        });
        dialog.show();
        if (!TextUtils.isEmpty(mHotloadCmd)) oneplusBypassWriteStage1(false);
    }
    
    private void checkGetAppListPermission() {
        if(GetAppListPermissionHelper.getPermissions(this)) return;
        DialogUtils.showCustomDialog(this,"权限申请","请授予读取APP列表权限，再重新打开",null,"确定",
                (dialog, which) -> {
                    dialog.dismiss();
                    finish();
                },null, null);
    }

    private void setupFragment(String rootKey) {
        mBottomTab = findViewById(R.id.bottom_tab);
        mBottomTab.removeAllTabs();
        mBottomTab.addTab(mBottomTab.newTab().setText("主页"), true);
        mBottomTab.addTab(mBottomTab.newTab().setText("授权"));
        mBottomTab.addTab(mBottomTab.newTab().setText("模块"));
        mBottomTab.addTab(mBottomTab.newTab().setText("设置"));
        mHomeFragm = new HomeFragment(MainActivity.this, rootKey);
        mSuAuthFragm = new SuAuthFragment(MainActivity.this, rootKey);
        mSkrModFragm = new SkrModFragment(MainActivity.this, rootKey);
        mSettingsFragm = new SettingsFragment(MainActivity.this, rootKey);
        switchPage(0);
        mBottomTab.addOnTabSelectedListener(new TabLayout.OnTabSelectedListener() {
            @Override public void onTabSelected(TabLayout.Tab tab) { switchPage(tab.getPosition()); }
            @Override public void onTabUnselected(TabLayout.Tab tab) {}
            @Override public void onTabReselected(TabLayout.Tab tab) {}
        });
    }

    private void switchPage(int index) {
        Fragment f;
        switch (index) {
            case 0: f = mHomeFragm; break;
            case 1: f = mSuAuthFragm; break;
            case 2: f = mSkrModFragm; break;
            default: f = mSettingsFragm; break;
        }
        if(f == null) return;
        getSupportFragmentManager()
                .beginTransaction()
                .replace(R.id.frame_layout, f)
                .commit();
        if(mMainMenu != null) mMainMenu.setVisible(index == 1 || index == 2);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_main, menu);
        mMainMenu = menu.findItem(R.id.action_add);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == R.id.action_add) {
            View anchor = findViewById(R.id.action_add);
            showMainPopupMenu(anchor);
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        onChooseFileActivityResult(requestCode, resultCode, data);
    }

    private void showMainPopupMenu(View v) {
        int index = mBottomTab.getSelectedTabPosition();
        if(index == 1) mSuAuthFragm.showSuAuthMainPopupMenu(v);
        if(index == 2)  mSkrModFragm.showSkrModMainPopupMenu(v);
    }

    private void onChooseFileActivityResult(int requestCode, int resultCode, Intent data) {
        mSkrModFragm.onChooseFileActivityResult(requestCode, resultCode, data);
    }

}