package com.linux.permissionmanager.adapter;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.linux.permissionmanager.R;
import com.linux.permissionmanager.model.SkrModMarketItem;
import com.linux.permissionmanager.model.SuAuthItem;

import java.util.ArrayList;
import java.util.List;

public class SuAuthAdapter extends RecyclerView.Adapter<SuAuthAdapter.ViewHolder> {

    private List<SuAuthItem> suAuths;
    private OnItemClickListener listener;

    public interface OnItemClickListener {
        void onRemoveSuAuthBtnClick(View v, SuAuthItem suAuth);
    }

    public SuAuthAdapter(List<SuAuthItem> suAuths, OnItemClickListener listener) {
        this.suAuths = suAuths;
        this.listener = listener;
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_su_auth, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(ViewHolder holder, int position) {
        SuAuthItem suAuth = suAuths.get(position);
        if(suAuth.getIcon() != null) holder.tvAppIcon.setImageDrawable(suAuth.getIcon());
        holder.tvAppName.setText(suAuth.getAppName());
        holder.tvAppPackageName.setText(suAuth.getAppPackageName());
        holder.btnRemove.setOnClickListener(v -> {
            if (listener != null) {
                listener.onRemoveSuAuthBtnClick(v, suAuth);
            }
        });
    }

    @Override
    public int getItemCount() {
        return suAuths.size();
    }

    public static class ViewHolder extends RecyclerView.ViewHolder {
        public ImageView tvAppIcon;
        public TextView tvAppName;
        public TextView tvAppPackageName;
        public Button btnRemove;

        public ViewHolder(View itemView) {
            super(itemView);
            tvAppIcon = itemView.findViewById(R.id.app_icon_iv);
            tvAppName = itemView.findViewById(R.id.app_name_tv);
            tvAppPackageName = itemView.findViewById(R.id.app_package_name_tv);
            btnRemove = itemView.findViewById(R.id.remove_btn);

        }
    }
}
