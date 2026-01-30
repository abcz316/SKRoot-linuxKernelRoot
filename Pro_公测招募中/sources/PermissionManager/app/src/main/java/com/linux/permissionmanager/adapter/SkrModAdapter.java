package com.linux.permissionmanager.adapter;

import android.graphics.Color;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.RecyclerView;

import com.linux.permissionmanager.R;
import com.linux.permissionmanager.bridge.NativeBridge;
import com.linux.permissionmanager.model.SkrModItem;
import com.linux.permissionmanager.model.SkrModUpdateInfo;

import java.util.List;

public class SkrModAdapter extends RecyclerView.Adapter<SkrModAdapter.ViewHolder> {
    private final int SkrModRunningColor = Color.rgb(0x22,0xB1, 0x4C);
    private final int SkrModNotRunningColor = Color.rgb(0xED,0x1C, 0x24);

    private List<SkrModItem> skrmods;
    private OnItemClickListener listener;

    public interface OnItemClickListener {
        void onOpenWebUIBtnClick(View v, SkrModItem skrmod);
        void onNewVersionBtnClick(View v, SkrModItem skrmod);
        void onMoreBtnClick(View v, SkrModItem skrmod);
    }

    public SkrModAdapter(List<SkrModItem> skrmods, OnItemClickListener listener) {
        this.skrmods = skrmods;
        this.listener = listener;
    }


    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_skr_mod, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(ViewHolder holder, int position) {
        SkrModItem skrmod = skrmods.get(position);
        holder.tvName.setText(skrmod.getName());
        holder.tvDesc.setText(skrmod.getDesc());
        holder.tvVer.setText(skrmod.getVer());
        holder.tvAuthor.setText(skrmod.getAuthor());
        holder.tvStatus.setText(skrmod.isRunning() ? "运行中" : "未运行");
        holder.tvStatus.setTextColor(skrmod.isRunning() ? SkrModRunningColor : SkrModNotRunningColor);
        holder.btnWebUI.setVisibility(skrmod.isWebUi() ? View.VISIBLE : View.GONE);
        boolean hasNewVer = skrmod.getUpdateInfo() != null && skrmod.getUpdateInfo().isHasNewVersion();
        holder.btnNewVersion.setVisibility(hasNewVer ? View.VISIBLE : View.GONE);
        holder.btnWebUI.setOnClickListener(v -> {
            if (listener != null) {
                listener.onOpenWebUIBtnClick(v, skrmod);
            }
        });
        holder.btnMore.setOnClickListener(v -> {
            if (listener != null) {
                listener.onMoreBtnClick(v, skrmod);
            }
        });
        holder.btnNewVersion.setOnClickListener(v -> {
            if (listener != null) {
                listener.onNewVersionBtnClick(v, skrmod);
            }
        });
    }

    public void updateModuleUpdateInfo(String uuid, SkrModUpdateInfo updateInfo) {
        if (uuid == null) return;
        for (int i = 0; i < skrmods.size(); i++) {
            SkrModItem item = skrmods.get(i);
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
