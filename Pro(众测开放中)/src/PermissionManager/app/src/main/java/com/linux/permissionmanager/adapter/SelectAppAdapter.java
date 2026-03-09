package com.linux.permissionmanager.adapter;

import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;

import com.linux.permissionmanager.model.SelectAppItem;
import com.linux.permissionmanager.R;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class SelectAppAdapter extends RecyclerView.Adapter<SelectAppAdapter.ViewHolder> {

    public interface OnAppSelectedListener {
        void onAppSelected(@NonNull SelectAppItem item);
    }

    private final int itemLayoutId;
    private final List<SelectAppItem> items = new ArrayList<>();
    @NonNull private final OnAppSelectedListener listener;

    public SelectAppAdapter(int itemLayoutId, @NonNull List<SelectAppItem> initialItems, @NonNull OnAppSelectedListener listener) {
        this.itemLayoutId = itemLayoutId;
        this.listener = listener;
        setData(initialItems);
    }

    public void setData(@Nullable List<SelectAppItem> newList) {
        items.clear();
        if (newList != null) items.addAll(newList);
        notifyDataSetChanged();
    }

    @NonNull
    public List<SelectAppItem> getData() {
        return Collections.unmodifiableList(items);
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(parent.getContext()).inflate(itemLayoutId, parent, false);
        return new ViewHolder(v);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        SelectAppItem item = items.get(position);

        Drawable icon = item.getDrawable(holder.itemView.getContext());
        String showName = item.getShowName(holder.itemView.getContext());
        String packageName = item.getPackageName();

        holder.icon.setImageDrawable(icon);
        holder.name.setText(buildColoredTitle(showName, packageName));
        holder.pkg.setText(packageName);

        holder.itemView.setOnClickListener(v -> listener.onAppSelected(item));
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    private CharSequence buildColoredTitle(String showName, String packageName) {
        SpannableStringBuilder ssb = new SpannableStringBuilder();

        int startName = ssb.length();
        ssb.append(showName);
        ssb.setSpan(new ForegroundColorSpan(Color.parseColor("#88CC88")), startName, ssb.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        ssb.append("  ");
        int startPkg = ssb.length();
        ssb.append("(").append(packageName).append(")");
        ssb.setSpan(new ForegroundColorSpan(Color.parseColor("#88CCCC")), startPkg, ssb.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        return ssb;
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        final ImageView icon;
        final TextView name;
        final TextView pkg;

        ViewHolder(@NonNull View itemView) {
            super(itemView);
            icon = itemView.findViewById(R.id.select_app_icon);
            name = itemView.findViewById(R.id.select_app_text);
            pkg  = itemView.findViewById(R.id.select_package_name);
        }
    }
}
