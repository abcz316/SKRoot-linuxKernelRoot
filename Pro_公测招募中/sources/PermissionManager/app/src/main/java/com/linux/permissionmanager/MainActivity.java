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
    private RadioGroup mNavigateRadioGroup;
    private MenuItem mMainMenu;
    private HomeFragment mHomeFragm = null;
    private SuAuthFragment mSuAuthFragm = null;
    private SkrModFragment mSkrModFragm = null;
    private SettingsFragment mSettingsFragm = null;
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
                mHomeFragm.setRootKey(mRootKey);
                mSuAuthFragm.setRootKey(mRootKey);
                mSkrModFragm.setRootKey(mRootKey);
                mSettingsFragm.setRootKey(mRootKey);
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
        mNavigateRadioGroup = findViewById(R.id.rg_navigation);
        mHomeFragm = new HomeFragment(this);
        mSuAuthFragm = new SuAuthFragment(this);
        mSkrModFragm = new SkrModFragment(this);
        mSettingsFragm = new SettingsFragment(this);
        getSupportFragmentManager().beginTransaction()
                .replace(R.id.frame_layout, mHomeFragm)
                .commit();
        mNavigateRadioGroup.setOnCheckedChangeListener((group, checkedId) -> {
            Fragment selectedFragment = null;
            if (checkedId == R.id.rb_home) {
                selectedFragment = mHomeFragm;
            } else if (checkedId == R.id.rb_su_auth) {
                selectedFragment = mSuAuthFragm;
            } else if (checkedId == R.id.rb_skr_mod) {
                selectedFragment = mSkrModFragm;
            } else if (checkedId == R.id.rb_settings) {
                selectedFragment = mSettingsFragm;
            }
            mMainMenu.setVisible(checkedId == R.id.rb_su_auth || checkedId == R.id.rb_skr_mod);
            if (selectedFragment != null) {
                getSupportFragmentManager().beginTransaction()
                        .replace(R.id.frame_layout, selectedFragment)
                        .commitNow();
            }
        });
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
        int checkedId = mNavigateRadioGroup.getCheckedRadioButtonId();
        if(checkedId == R.id.rb_su_auth) showSuAuthMainPopupMenu(v);
        if(checkedId == R.id.rb_skr_mod)  showSkrModMainPopupMenu(v);
    }

    private void showSuAuthMainPopupMenu(View v) {
        PopupMenu popupMenu = new PopupMenu(this, v);
        popupMenu.getMenuInflater().inflate(R.menu.popup_su_auth_main_menu, popupMenu.getMenu());
        popupMenu.setOnMenuItemClickListener(item -> {
            int itemId = item.getItemId();
            if (itemId == R.id.add_su_auth) {
                mSuAuthFragm.onShowSelectAddSuAuthList();
            } else if (itemId == R.id.clear_su_auth) {
                mSuAuthFragm.onClearSuAuth();
            }
            return true;
        });

        popupMenu.show();
    }

    private void showSkrModMainPopupMenu(View v) {
        PopupMenu popupMenu = new PopupMenu(this, v);
        popupMenu.getMenuInflater().inflate(R.menu.popup_skr_mod_main_menu, popupMenu.getMenu());
        popupMenu.setOnMenuItemClickListener(item -> {
            int itemId = item.getItemId();
            if (itemId == R.id.add_skr_mod) chooseFile();
            return true;
        });
        popupMenu.show();
    }

    private void chooseFile() {
        if(!GetSdcardPermissionsHelper.getPermissions(this, this, this.getPackageName())) {
            DialogUtils.showNeedPermissionDialog(this);
            return;
        }
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("application/zip");
        startActivityForResult(intent, ActivityResultId.REQUEST_CODE_CHOOSE_FILE);
    }

    private void onChooseFileActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == ActivityResultId.REQUEST_CODE_CHOOSE_FILE && resultCode == Activity.RESULT_OK) {
            Uri uri = data.getData();
            String filePath = FileUtils.getRealPathFromURI(this, uri);
            if (filePath == null) {
                Log.e("SkrModFragment", "Invalid file path");
                return;
            }
            Log.d("SkrModFragment", "Add skr module file path: " + filePath);
            mSkrModFragm.onAddSkrMod(filePath);
        }
    }

}