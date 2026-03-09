package com.linux.permissionmanager.fragment;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.PopupMenu;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.viewpager2.widget.ViewPager2;

import com.google.android.material.tabs.TabLayout;
import com.google.android.material.tabs.TabLayoutMediator;
import com.linux.permissionmanager.ActivityResultId;
import com.linux.permissionmanager.R;
import com.linux.permissionmanager.page.SkrModInstalledPage;
import com.linux.permissionmanager.page.SkrModMarketPage;
import com.linux.permissionmanager.utils.DialogUtils;
import com.linux.permissionmanager.utils.GetSdcardPermissionsHelper;

public class SkrModFragment extends Fragment {
    private Activity mActivity;
    private String mRootKey = "";

    private TabLayout mTabLayout;
    private View mInstalled;
    private View mMarket;

    private SkrModInstalledPage mModInstalledPage;
    private SkrModMarketPage mModMarketPage;

    public SkrModFragment(Activity activity, String rootKey) {
        mActivity = activity;
        mRootKey = rootKey;
        mModInstalledPage = new SkrModInstalledPage(activity, rootKey);
        mModMarketPage = new SkrModMarketPage(activity, rootKey);
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
        mTabLayout = view.findViewById(R.id.tab_layout);
        mInstalled = view.findViewById(R.id.page_installed);
        mMarket = view.findViewById(R.id.page_market);
        mModInstalledPage.bindPage(mInstalled);
        mModMarketPage.bindPage(mMarket);
        initTabLayout();
    }

    private void initTabLayout() {
        mTabLayout.addTab(mTabLayout.newTab().setText("已安装"), true);
        mTabLayout.addTab(mTabLayout.newTab().setText("模块市场"));

        mTabLayout.addOnTabSelectedListener(new TabLayout.OnTabSelectedListener() {
            @Override public void onTabSelected(TabLayout.Tab t) {
                boolean showInstalled = t.getPosition() == 0;
                mInstalled.setVisibility(showInstalled ? View.VISIBLE : View.GONE);
                mMarket.setVisibility(showInstalled ? View.GONE : View.VISIBLE);

                if(showInstalled) mModInstalledPage.refreshPage();
                else mModMarketPage.refreshPage();
            }
            @Override public void onTabUnselected(TabLayout.Tab t) {}
            @Override public void onTabReselected(TabLayout.Tab t) {}
        });
    }

    public void showSkrModMainPopupMenu(View v) {
        mModInstalledPage.showSkrModMainPopupMenu(v);
    }

    public void onChooseFileActivityResult(int requestCode, int resultCode, Intent data) {
        mModInstalledPage.onChooseFileActivityResult(requestCode, resultCode, data);
    }
}
