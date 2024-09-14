package com.linux.permissionmanager.Adapter;

import android.content.Context;
import android.graphics.Color;
import android.os.Handler;
import android.os.Message;
import android.text.Html;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.PopupWindow;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.linux.permissionmanager.Model.SelectFileRecyclerItem;
import com.linux.permissionmanager.R;

import java.util.ArrayList;
import java.util.List;
public class SelectFileRecyclerAdapter extends RecyclerView.Adapter<SelectFileRecyclerAdapter.ViewHolder> {
    public static class ViewHolder extends RecyclerView.ViewHolder {
        public View v;
        public TextView select_file_name;
        public TextView select_file_desc;
        public ViewHolder(View v) {
            super(v);
            this.v = v;
        }
    }
    private int resourceId;
    private List<SelectFileRecyclerItem> objects;
    private PopupWindow popupWindow;
    private Handler selectFileCallback;
    private Context ctx;
    public SelectFileRecyclerAdapter(Context ctx, int textViewResourceId, List<SelectFileRecyclerItem> objects, PopupWindow popupWindow, Handler selectFileCallback) {
        this.resourceId = textViewResourceId;
        this.objects = new ArrayList<>(objects);
        this. popupWindow = popupWindow;
        this. selectFileCallback = selectFileCallback;
        this. ctx = ctx;
    }

    public void updateList(List<SelectFileRecyclerItem> newList) {
        objects.clear();
        objects.addAll(newList);
        notifyDataSetChanged();
    }


    public List<SelectFileRecyclerItem> getList() {
        return objects;
    }


    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v =LayoutInflater.from(parent.getContext()).inflate(resourceId,parent,false);
        SelectFileRecyclerAdapter.ViewHolder holder = new SelectFileRecyclerAdapter.ViewHolder(v);

        holder.select_file_name=v.findViewById(R.id.select_file_name) ;
        holder.select_file_desc=v.findViewById(R.id.select_file_desc) ;
        return holder;
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        SelectFileRecyclerItem fileItem=objects.get(position);
        String fileName = fileItem.getFileName();
        String fileDesc = fileItem.getFileDesc();
        Color fileDescColor = fileItem.getFileDescColor();
        String hexColor = String.format("#%06X", (0xFFFFFF & fileDescColor.toArgb()));

        String  showText="<font color = \"#88CC88\">"+fileName +"</font> ";
        String  showDesc="<font color = \""+ hexColor +"\">"+fileDesc +"</font> ";
        holder.select_file_name.setText(Html.fromHtml(showText));
        holder.select_file_desc.setText(Html.fromHtml(showDesc));

        holder.v.setOnClickListener(new ClickRecyclerItemListener(fileItem));
    }

    @Override
    public int getItemCount() {
        return objects.size();
    }

    @Override
    public int getItemViewType(int position) {
        return position;
    }


    class ClickRecyclerItemListener implements View.OnClickListener {
        SelectFileRecyclerItem fileItem;
        public ClickRecyclerItemListener(SelectFileRecyclerItem fileItem){
            this.fileItem =fileItem;
        }
        @Override
        public void onClick(View v) {
            popupWindow.dismiss();
            Message msg = new Message();
            msg.obj = (SelectFileRecyclerItem)fileItem;
            selectFileCallback.sendMessage(msg);
        }
    }
}