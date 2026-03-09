package com.linux.permissionmanager.adapter;

import android.graphics.Color;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.linux.permissionmanager.R;
import com.linux.permissionmanager.model.SkrModInstalledItem;
import com.linux.permissionmanager.model.SkrModMarketItem;
import com.linux.permissionmanager.model.SkrModRunState;
import com.linux.permissionmanager.model.SkrModUpdateInfo;

import java.util.ArrayList;
import java.util.List;

public class SkrModInstalledAdapter extends RecyclerView.Adapter<SkrModInstalledAdapter.ViewHolder> {
    private final int SkrModRunningColor = Color.parseColor("#16A34A");
    private final int SkrModNotRunningColor = Color.parseColor("#F59E0B");
    private final int SkrModAbnormalColor = Color.parseColor("#EF4444");

    private List<SkrModInstalledItem> skrmods;
    private OnItemClickListener listener;

    public interface OnItemClickListener {
        void onOpenWebUIBtnClick(View v, SkrModInstalledItem skrmod);
        void onNewVersionBtnClick(View v, SkrModInstalledItem skrmod);
        void onMoreBtnClick(View v, SkrModInstalledItem skrmod);
    }

    public SkrModInstalledAdapter(List<SkrModInstalledItem> skrmods, OnItemClickListener listener) {
        this.skrmods = skrmods;
        this.listener = listener;
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_skr_mod_installed, parent, false);
        return new ViewHolder(view);
    }

    private static void setTextOrGone(TextView tv, String s) {
        if (tv == null) return;
        boolean hidden = TextUtils.isEmpty(s) || TextUtils.isEmpty(s.trim());
        tv.setText(s);
        tv.setVisibility(hidden ? View.GONE : View.VISIBLE);
    }

    @Override
    public void onBindViewHolder(ViewHolder holder, int position) {
        SkrModInstalledItem skrmod = skrmods.get(position);
        holder.tvName.setText(skrmod.getName());

        setTextOrGone(holder.tvDesc, skrmod.getDesc());
        holder.tvVer.setText(skrmod.getVer());
        holder.tvAuthor.setText(skrmod.getAuthor());
        SkrModRunState state = skrmod.getRunState();
        holder.tvStatus.setText(
                state == SkrModRunState.RUNNING ? "运行中" :
                        state == SkrModRunState.ABNORMAL ? "运行异常" :
                                "未启动"
        );
        holder.tvStatus.setTextColor(
                state == SkrModRunState.RUNNING ? SkrModRunningColor :
                        state == SkrModRunState.ABNORMAL ? SkrModAbnormalColor :
                                SkrModNotRunningColor
        );
        holder.btnWebUI.setVisibility(skrmod.isWebUi() ? View.VISIBLE : View.GONE);
        holder.btnWebUI.setOnClickListener(v -> {
            if (listener != null) listener.onOpenWebUIBtnClick(v, skrmod);
        });

        holder.btnMore.setOnClickListener(v -> {
            if (listener != null) listener.onMoreBtnClick(v, skrmod);
        });

        boolean hasNewVer = skrmod.getUpdateInfo() != null && skrmod.getUpdateInfo().isHasNewVersion();
        holder.btnNewVersion.setVisibility(hasNewVer ? View.VISIBLE : View.GONE);
        holder.btnNewVersion.setOnClickListener(v -> {
            if (listener != null) listener.onNewVersionBtnClick(v, skrmod);
        });
    }

    public void updateModuleUpdateInfo(String uuid, SkrModUpdateInfo updateInfo) {
        if (uuid == null) return;
        for (int i = 0; i < skrmods.size(); i++) {
            SkrModInstalledItem item = skrmods.get(i);
            if (uuid.equals(item.getUuid())) {
                item.setUpdateInfo(updateInfo);
                notifyItemChanged(i);
                break;
            }
        }
    }

    @Override
    public int getItemCount() {
        return skrmods.size();
    }

    public static class ViewHolder extends RecyclerView.ViewHolder {
        public TextView tvName;
        public TextView tvDesc;
        public TextView tvVer;
        public TextView tvAuthor;
        public TextView tvStatus;
        public Button btnWebUI;
        public Button btnNewVersion;
        public Button btnMore;

        public ViewHolder(View itemView) {
            super(itemView);
            tvName = itemView.findViewById(R.id.name_tv);
            tvDesc = itemView.findViewById(R.id.desc_tv);
            tvVer = itemView.findViewById(R.id.ver_tv);
            tvAuthor = itemView.findViewById(R.id.author_tv);
            tvStatus = itemView.findViewById(R.id.status_tv);
            btnMore = itemView.findViewById(R.id.more_btn);
            btnWebUI = itemView.findViewById(R.id.web_ui_btn);
            btnNewVersion = itemView.findViewById(R.id.new_version_btn);
        }
    }

}
