package com.linux.permissionmanager;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.PopupMenu;
import android.widget.RadioGroup;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AppCompatDelegate;
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


public class MainActivity extends AppCompatActivity {
    private String mRootKey = "";

    private HomeFragment mHomeFragm;
    private SuAuthFragment mSuAuthFragm;
    private SkrModFragment mSkrModFragm;
    private SettingsFragment mSettingsFragm;

    private TabLayout mBottomTab;
    private MenuItem mMainMenu;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        AppSettings.init(this);
        mRootKey = AppSettings.getString("rootKey", mRootKey);
        checkGetAppListPermission();
        showInputRootKeyDlg();
        setupFragment();
    }

    private void showInputRootKeyDlg() {
        Handler inputCallback = new Handler() {
            @Override
            public void handleMessage(@NonNull Message msg) {
                String text = (String)msg.obj;
                mRootKey = text;
                AppSettings.setString("rootKey", mRootKey);
                setupFragment();
                switchPage(0);
                super.handleMessage(msg);
            }
        };
        DialogUtils.showInputDlg(this, mRootKey,"请输入ROOT权限的KEY", null, inputCallback, null);
    }

    private void checkGetAppListPermission() {
        if(GetAppListPermissionHelper.getPermissions(this)) return;
        DialogUtils.showCustomDialog(
                this,"权限申请","请授予读取APP列表权限，再重新打开",null,"确定",
                (dialog, which) -> {
                    dialog.dismiss();
                    finish();
                },null, null);
    }

    private void setupFragment() {
        mBottomTab = findViewById(R.id.bottom_tab);
        mBottomTab.removeAllTabs();
        mBottomTab.addTab(mBottomTab.newTab().setText("主页"), true);
        mBottomTab.addTab(mBottomTab.newTab().setText("授权"));
        mBottomTab.addTab(mBottomTab.newTab().setText("模块"));
        mBottomTab.addTab(mBottomTab.newTab().setText("设置"));

        // 默认页
        mHomeFragm = new HomeFragment(MainActivity.this, mRootKey);
        mSuAuthFragm = new SuAuthFragment(MainActivity.this, mRootKey);
        mSkrModFragm = new SkrModFragment(MainActivity.this, mRootKey);
        mSettingsFragm = new SettingsFragment(MainActivity.this, mRootKey);
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
        if(mMainMenu != null) {
            mMainMenu.setVisible(index == 1 || index == 2);
        }
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