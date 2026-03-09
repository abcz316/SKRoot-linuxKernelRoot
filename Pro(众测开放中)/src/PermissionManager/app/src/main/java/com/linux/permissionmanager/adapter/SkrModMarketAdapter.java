package com.linux.permissionmanager.adapter;

import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.linux.permissionmanager.R;
import com.linux.permissionmanager.model.SkrModMarketItem;
import com.linux.permissionmanager.model.SkrModUpdateInfo;

import java.util.ArrayList;
import java.util.List;

public class SkrModMarketAdapter extends RecyclerView.Adapter<SkrModMarketAdapter.ViewHolder> {
    private List<SkrModMarketItem> skrmods;
    private OnItemClickListener listener;

    public interface OnItemClickListener {
        void onActionsBtnClick(View v, SkrModMarketItem skrmod);
    }

    public SkrModMarketAdapter(List<SkrModMarketItem> skrmods, OnItemClickListener listener) {
        this.skrmods = skrmods;
        this.listener = listener;
    }

    public void setData(List<SkrModMarketItem> list) {
        this.skrmods = (list == null) ? new ArrayList<>() : list;
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_skr_mod_market, parent, false);
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
        SkrModMarketItem skrmod = skrmods.get(position);
        holder.tvName.setText(skrmod.getChnName());

        setTextOrGone(holder.tvDesc, skrmod.getDesc());
        holder.tvVer.setText(skrmod.getVer());
        holder.tvAuthor.setText(skrmod.getAuthor());
        holder.tvUpdateDate.setText(skrmod.getUpdateDate());
        holder.btnActions.setOnClickListener(v -> {
            if (listener != null) listener.onActionsBtnClick(v, skrmod);
        });
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
        public TextView tvUpdateDate;
        public Button btnActions;

        public ViewHolder(View itemView) {
            super(itemView);
            tvName = itemView.findViewById(R.id.name_tv);
            tvDesc = itemView.findViewById(R.id.desc_tv);
            tvVer = itemView.findViewById(R.id.ver_tv);
            tvAuthor = itemView.findViewById(R.id.author_tv);
            tvUpdateDate = itemView.findViewById(R.id.update_date_tv);
            btnActions = itemView.findViewById(R.id.actions_btn);
        }
    }

}
