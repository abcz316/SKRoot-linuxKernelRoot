package com.android.zygotepreloadtools;

import android.os.ParcelFileDescriptor;

import java.io.IOException;

public class RemoteProcessHolder extends IRemoteProcess.Stub {
    private final Process process;
    private ParcelFileDescriptor in;
    private ParcelFileDescriptor out;
    private ParcelFileDescriptor err;

    public RemoteProcessHolder(Process process) {
        this.process = process;
    }

    @Override
    public synchronized ParcelFileDescriptor getOutputStream() {
        if (out == null) {
            try {
                out = ParcelFileDescriptorUtil.pipeTo(process.getOutputStream());
            } catch (IOException e) {
                return null;
            }
        }
        return out;
    }

    @Override
    public synchronized ParcelFileDescriptor getInputStream() {
        if (in == null) {
            try {
                in = ParcelFileDescriptorUtil.pipeFrom(process.getInputStream());
            } catch (IOException e) {
                return null;
            }
        }
        return in;
    }

    @Override
    public synchronized ParcelFileDescriptor getErrorStream() {
        if (err == null) {
            try {
                err = ParcelFileDescriptorUtil.pipeFrom(process.getErrorStream());
            } catch (IOException e) {
                return null;
            }
        }
        return err;
    }

    @Override
    public int waitFor() {
        try {
            return process.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return -1;
        }
    }

    @Override
    public int exitValue() {
        try {
            return process.exitValue();
        } catch (IllegalThreadStateException e) {
            return -1;
        }
    }

    @Override
    public void destroy() {
        process.destroy();
    }

    @Override
    public boolean isAlive() {
        try {
            process.exitValue();
            return false;
        } catch (IllegalThreadStateException e) {
            return true;
        }
    }
}