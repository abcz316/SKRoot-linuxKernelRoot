package com.linux.permissionmanager.adapter;

import android.graphics.Color;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.linux.permissionmanager.R;
import com.linux.permissionmanager.model.SuProbeItem;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class SuProbeAdapter extends RecyclerView.Adapter<SuProbeAdapter.ViewHolder> {

    private List<SuProbeItem> suProbes;

    public SuProbeAdapter(List<SuProbeItem> suProbes) {
        this.suProbes = suProbes;
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_su_probe, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(ViewHolder holder, int position) {
        SuProbeItem suProbe = suProbes.get(position);
        if (suProbe.getIcon() != null) holder.tvAppIcon.setImageDrawable(suProbe.getIcon());
        holder.tvAppName.setText(suProbe.getAppName());
        holder.tvAppPackageName.setText(suProbe.getAppPackageName());

        // 嗅探次数
        holder.tvProbeCount.setText(suProbe.getProbeCount() + " 次");

        // 授权状态
        boolean isAuthorized = suProbe.isAuthorized();
        holder.tvSuAuthStatus.setText(isAuthorized ? "已授权" : "无授权");
        holder.tvSuAuthStatus.setBackgroundResource(isAuthorized ? R.drawable.bg_status_authorized : R.drawable.bg_status_unauthorized);
        holder.tvSuAuthStatus.setTextColor(Color.parseColor(isAuthorized ? "#2E7D32" : "#D32F2F"));

        // 最近1小时内的嗅探时间标红
        long diff = System.currentTimeMillis() - suProbe.getLastProbeTimeS() * 1000L;
        int timeColor = diff >= 0 && diff < 3600000L ? Color.RED : Color.parseColor("#666666");
        holder.tvLastProbeTime.setText(formatTime(suProbe.getLastProbeTimeS()));
        holder.tvLastProbeTime.setTextColor(timeColor);
        holder.tvLastProbeLabel.setTextColor(timeColor);
    }

    private String formatTime(long timeS) {
        if (timeS <= 0) return "—";
        return new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(new Date(timeS * 1000));
    }

    @Override
    public int getItemCount() {
        return suProbes.size();
    }

    public static class ViewHolder extends RecyclerView.ViewHolder {
        public ImageView tvAppIcon;
        public TextView tvAppName;
        public TextView tvAppPackageName;
        public TextView tvProbeCount;
        public TextView tvLastProbeLabel;
        public TextView tvLastProbeTime;
        public TextView tvSuAuthStatus;

        public ViewHolder(View itemView) {
            super(itemView);
            tvAppIcon = itemView.findViewById(R.id.app_icon_iv);
            tvAppName = itemView.findViewById(R.id.app_name_tv);
            tvAppPackageName = itemView.findViewById(R.id.app_package_name_tv);
            tvProbeCount = itemView.findViewById(R.id.probe_count_tv);
            tvLastProbeLabel  = itemView.findViewById(R.id.last_probe_label_tv);
            tvLastProbeTime = itemView.findViewById(R.id.last_probe_time_tv);
            tvSuAuthStatus = itemView.findViewById(R.id.su_auth_status_tv);
        }
    }
}
