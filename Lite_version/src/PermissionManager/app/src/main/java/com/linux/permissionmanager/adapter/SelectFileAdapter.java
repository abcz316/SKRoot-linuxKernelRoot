package com.linux.permissionmanager.adapter;

import android.graphics.Color;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.ColorInt;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;

import com.linux.permissionmanager.model.SelectFileItem;
import com.linux.permissionmanager.R;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
public class SelectFileAdapter extends RecyclerView.Adapter<SelectFileAdapter.ViewHolder> {

    public interface OnFileSelectedListener {
        void onFileSelected(@NonNull SelectFileItem item);
    }
    private final int itemLayoutId;
    private final List<SelectFileItem> items = new ArrayList<>();
    @NonNull private final OnFileSelectedListener listener;

    public SelectFileAdapter(int itemLayoutId, @NonNull List<SelectFileItem> initialItems, @NonNull OnFileSelectedListener listener) {
        this.itemLayoutId = itemLayoutId;
        this.listener = listener;
        setData(initialItems);
    }

    public void setData(@Nullable List<SelectFileItem> newList) {
        items.clear();
        if (newList != null) items.addAll(newList);
        notifyDataSetChanged();
    }

    @NonNull
    public List<SelectFileItem> getData() {
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
        SelectFileItem item = items.get(position);

        String fileName = item.getFileName();
        String fileDesc = item.getFileDesc();

        Color fileDescColor = item.getFileDescColor();
        @ColorInt int descColor = fileDescColor.toArgb();

        holder.name.setText(buildColoredText(fileName, 0xFF88CC88));
        holder.desc.setText(buildColoredText(fileDesc, descColor));

        holder.itemView.setOnClickListener(v -> listener.onFileSelected(item));
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    private CharSequence buildColoredText(String text, @ColorInt int color) {
        SpannableStringBuilder ssb = new SpannableStringBuilder(text);
        ssb.setSpan(new ForegroundColorSpan(color), 0, ssb.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        return ssb;
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        final TextView name;
        final TextView desc;

        ViewHolder(@NonNull View itemView) {
            super(itemView);
            name = itemView.findViewById(R.id.select_file_name);
            desc = itemView.findViewById(R.id.select_file_desc);
        }
    }
}