package com.linux.permissionmanager.fragment;

import android.app.Activity;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.google.android.material.tabs.TabLayout;
import com.linux.permissionmanager.R;
import com.linux.permissionmanager.page.SuAuthListPage;
import com.linux.permissionmanager.page.SuProbeRecordsPage;

public class SuAuthFragment extends Fragment {
    private TabLayout mTabLayout;
    private View mSuAuthListView;
    private View mSuProbeRecordsView;

    private SuAuthListPage mSuAuthListPage;
    private SuProbeRecordsPage mSuProbeRecordsPage;

    public SuAuthFragment(Activity activity, String rootKey) {
        mSuAuthListPage = new SuAuthListPage(activity, rootKey);
        mSuProbeRecordsPage = new SuProbeRecordsPage(activity, rootKey);
        mSuAuthListPage.setOnSuProbeRecordsChanged(mSuProbeRecordsPage::refreshPage);
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_su_auth, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        mTabLayout = view.findViewById(R.id.tab_layout);
        mSuAuthListView = view.findViewById(R.id.page_su_auth_list);
        mSuProbeRecordsView = view.findViewById(R.id.page_su_probe_records);
        mSuAuthListPage.bindPage(mSuAuthListView);
        mSuProbeRecordsPage.bindPage(mSuProbeRecordsView);
        initTabLayout();
    }

    private void initTabLayout() {
        mTabLayout.addTab(mTabLayout.newTab().setText("授权列表"), true);
        mTabLayout.addTab(mTabLayout.newTab().setText("嗅探记录"));
        mTabLayout.addOnTabSelectedListener(new TabLayout.OnTabSelectedListener() {
            @Override public void onTabSelected(TabLayout.Tab t) {
                boolean showAuthList = t.getPosition() == 0;
                mSuAuthListView.setVisibility(showAuthList ? View.VISIBLE : View.GONE);
                mSuProbeRecordsView.setVisibility(showAuthList ? View.GONE : View.VISIBLE);
                if (showAuthList) mSuAuthListPage.refreshPage();
                else mSuProbeRecordsPage.refreshPage();
            }
            @Override public void onTabUnselected(TabLayout.Tab t) {}
            @Override public void onTabReselected(TabLayout.Tab t) {}
        });
    }

    public void showSuAuthMainPopupMenu(View v) {
        mSuAuthListPage.showSuAuthMainPopupMenu(v);
    }
}
