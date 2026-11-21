package com.linux.permissionmanager;

import static com.linux.permissionmanager.AppConfig.HOTLOAD_SHELL_PATH;

import android.app.Activity;
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
import com.linux.permissionmanager.hotload.HotloadLauncher;
import com.linux.permissionmanager.localadb.LocalAdbHelper;
import com.linux.permissionmanager.model.HotloadMethod;
import com.linux.permissionmanager.utils.DialogUtils;
import com.linux.permissionmanager.utils.FileUtils;
import com.linux.permissionmanager.utils.GetAppListPermissionHelper;
import com.linux.permissionmanager.utils.GetSdcardPermissionsHelper;

import org.json.JSONObject;

import java.io.File;

public class MainActivity extends AppCompatActivity {
    private String mRootKey = "";
    private boolean mIsHotloadMode = false;
    private String mHotloadCmd = "";
    private HotloadMethod mHotloadMethod = HotloadMethod.NONE;
    private String mOneplusBypassResult = "";
    private AlertDialog mHotloadKeyDlg;

    private HomeFragment mHomeFragm;
    private SuAuthFragment mSuAuthFragm;
    private SkrModFragment mSkrModFragm;
    private SettingsFragment mSettingsFragm;

    private TabLayout mBottomTab;
    private MenuItem mMainMenu;

    private final LocalAdbHelper mLocalAdb = new LocalAdbHelper(this);
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_LOCKED);
        setContentView(R.layout.activity_main);
        AppSettings.init(this);
        AppConfig.init(this);
        mRootKey = AppSettings.getString("rootKey", mRootKey);
        mIsHotloadMode = AppSettings.getBoolean("isHotloadMode", mIsHotloadMode);
        mHotloadCmd = AppSettings.getString("hotloadCmd", mHotloadCmd);
        mHotloadMethod = HotloadMethod.fromConfig(AppSettings.getString("hotloadMethod", ""));
        if(checkGetAppPermission()) showInputRootKeyDlg();
        setupFragment("");
    }

    private void showPermissionDeniedDialog(String message) {
        DialogUtils.showCustomDialog(this, "权限申请", message, null, "确定", (dialog, which) -> { dialog.dismiss(); finish(); }, null, null);
    }

    private boolean checkGetAppPermission() {
        if (!GetAppListPermissionHelper.getPermissions(this)) {
            showPermissionDeniedDialog("请授予读取APP列表权限，后重新打开");
            return false;
        }
        return true;
    }

    private void showInputRootKeyDlg() {
        if (mIsHotloadMode) showHotloadModeInputDlg();
        else showBootModeInputDlg();
    }

    private void showModeSelectDlg(boolean currentIsHotload, @NonNull Runnable onSelectBoot, @NonNull Runnable onSelectHotload) {
        final String[] items = {"1.刷Boot", "2.热启动(内核漏洞)"};
        final String footNote = "已支持内核漏洞：\n" + HotloadMethod.SUPPORTED_CVE_TEXT;
        DialogUtils.showSingleChoiceDialog(this, "请选择模式", items, -1, footNote,
                (dialog, which) -> {
                    if(which == 0) {
                        if (!currentIsHotload) return;
                        mIsHotloadMode = false;
                        onSelectBoot.run();
                    } else if(which == 1) {
                        if (currentIsHotload) return;
                        mIsHotloadMode = true;
                        onSelectHotload.run();
                    }
                    AppSettings.setBoolean("isHotloadMode", mIsHotloadMode);
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
                .setCancelable(false)
                .setNegativeButton("取消", null)
                .setPositiveButton("确定", (d, which) -> {
                    mRootKey = inputTxt.getText().toString().trim();
                    if(TextUtils.isEmpty(mRootKey)) return;
                    AppSettings.setString("rootKey", mRootKey);
                    setupFragment(mRootKey);
                    switchPage(0);
                }).create();
        modeRow.tvSwitch.setOnClickListener(v -> {
            dialog.dismiss();
            showModeSelectDlg(false, this::showBootModeInputDlg, this::showHotloadModeInputDlg);
        });
        dialog.show();
    }

    private void runHotloadScript(String script, HotloadMethod method) {
        if (TextUtils.isEmpty(script)) return;
        if (!HotloadLauncher.precheck(this, mRootKey, method, script, mLocalAdb)) return;
        HotloadLauncher.launch(this, method, script, this::onHotloadCompletionResult);
    }

    private boolean isSkrootChannelOK(String rootKey) { return NativeBridge.testSkrootBasics(rootKey, "Channel").contains("OK"); }

    private void onHotloadCompletionResult(DialogUtils.LogDialog logDlg) {
        runOnUiThread(() -> {
            oneplusBypassWriteStage1();
            if(!TextUtils.isEmpty(mOneplusBypassResult)) logDlg.appendLine("一加Oppo内部接口拦截日志（仅用于异常排查）：\n" + mOneplusBypassResult);
            new Handler(Looper.getMainLooper()).postDelayed(() -> {
                if(isSkrootChannelOK(mRootKey)) {
                    logDlg.dismiss();
                    dismissHotloadKeyDlg();
                    DialogUtils.showMsgDlg(this, "提示","加载完成", null);
                    setupFragment(mRootKey);
                    switchPage(0);
                } else {
                    // 失败不关「Root 密钥配置」窗口，关掉日志窗口就能直接再点「确定」重跑。
                    DialogUtils.showMsgDlg(this, "提示","加载出错，请重试或保存日志反馈", null);
                }
            }, 3000);
        });
    }

    private void dismissHotloadKeyDlg() {
        if (mHotloadKeyDlg != null && mHotloadKeyDlg.isShowing()) {
            mHotloadKeyDlg.dismiss();
        }
        mHotloadKeyDlg = null;
    }

    private void oneplusBypassWriteStage1() {
        try {
            String json = NativeBridge.getSystemStatusJson();
            JSONObject obj = new JSONObject(json);
            int selinux = obj.optInt("selinux", -1);
            if (selinux != 0) return;
            mOneplusBypassResult += NativeBridge.oneplusBypassWriteStage1(mRootKey);
        } catch (Throwable e) {
            e.printStackTrace();
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
        tipText.setTextSize(14);
        tipText.setPadding(0, dp4, 0, dp4);
        updateHotloadTipText(tipText, mHotloadMethod);

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
        ModeRowHolder modeRow = createModeRow(this, "热启动(内核漏洞)");
        rootLayout.addView(modeRow.root);
        rootLayout.addView(tipText);
        rootLayout.addView(inputTxt);
        rootLayout.addView(actionRow);
        final AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("Root 密钥配置")
                .setIcon(android.R.drawable.ic_dialog_info)
                .setView(rootLayout)
                .setCancelable(false)
                .setNegativeButton("取消", null)
                .setPositiveButton("确定", null)
                .create();
        dialog.setOnShowListener(d -> {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
                mRootKey = inputTxt.getText().toString().trim();
                if(TextUtils.isEmpty(mRootKey)) return;
                AppSettings.setString("rootKey", mRootKey);
                setupFragment(mRootKey);
                switchPage(0);
                if (TextUtils.isEmpty(mHotloadCmd)) {
                    dialog.dismiss();
                    return;
                }
                if (isSkrootChannelOK(mRootKey)) {
                    oneplusBypassWriteStage1();
                    dialog.dismiss();
                    return;
                }
                runHotloadScript(mHotloadCmd, mHotloadMethod);
            });
        });
        modeRow.tvSwitch.setOnClickListener(v -> {
            dialog.dismiss();
            showModeSelectDlg(true, this::showBootModeInputDlg, this::showHotloadModeInputDlg);
        });

        importBtn.setOnClickListener(v -> {            
           if(!GetSdcardPermissionsHelper.getPermissions(this, this, this.getPackageName())) {
               DialogUtils.showNeedPermissionDialog(this, "文件存储权限");
               return;
           }
           String scriptText = FileUtils.readTextFile(HOTLOAD_SHELL_PATH);
           if (TextUtils.isEmpty(scriptText)) {
               DialogUtils.showMsgDlg(this, "错误", "读取文件失败或文件不存在", null);
               return;
           }
           String rootKey = HotloadLauncher.getConfigValue(scriptText, "ROOT_KEY");
           String method = HotloadLauncher.getConfigValue(scriptText, "METHOD");
           if (TextUtils.isEmpty(rootKey)) return;
           mRootKey = rootKey;
           mHotloadMethod = HotloadMethod.fromConfig(method);
           mHotloadCmd = scriptText;
           updateHotloadTipText(tipText, mHotloadMethod);
           inputTxt.setText(mRootKey);
           inputTxt.setEnabled(false);
           AppSettings.setString("rootKey", mRootKey);
           AppSettings.setString("hotloadCmd", mHotloadCmd);
           AppSettings.setString("hotloadMethod", mHotloadMethod.getConfigValue());
        });

        exportBtn.setOnClickListener(v -> {
            if(!GetSdcardPermissionsHelper.getPermissions(this, this, this.getPackageName())) {
                DialogUtils.showNeedPermissionDialog(this, "文件存储权限");
                return;
            }
            if (!TextUtils.isEmpty(mHotloadCmd)) exportHotloadToSdcard(this, mHotloadCmd);
        });
        mHotloadKeyDlg = dialog;
        dialog.setOnDismissListener(d -> { if (mHotloadKeyDlg == dialog) mHotloadKeyDlg = null; });
        dialog.show();
        if (!TextUtils.isEmpty(mHotloadCmd)) oneplusBypassWriteStage1();
    }
    private void updateHotloadTipText(TextView tipText, HotloadMethod method) {
        String value = method.getConfigValue();
        if (TextUtils.isEmpty(value)) {
            tipText.setText("可直接输入 Key，或将热启动补丁包放到 " + HOTLOAD_SHELL_PATH + " 后点击“从1.h导入”");
        } else {
            tipText.setText("已选内核漏洞：" + value);
        }
    }
    private void setupFragment(String rootKey) {
        mBottomTab = findViewById(R.id.bottom_tab);
        mBottomTab.removeAllTabs();
        mBottomTab.addTab(mBottomTab.newTab().setText("主页"), true);
        mBottomTab.addTab(mBottomTab.newTab().setText("授权"));
        mBottomTab.addTab(mBottomTab.newTab().setText("模块"));
        mBottomTab.addTab(mBottomTab.newTab().setText("设置"));
        mHomeFragm = new HomeFragment(MainActivity.this, rootKey, mIsHotloadMode, mHotloadMethod);
        mSuAuthFragm = new SuAuthFragment(MainActivity.this, rootKey);
        mSkrModFragm = new SkrModFragment(MainActivity.this, rootKey, mIsHotloadMode);
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