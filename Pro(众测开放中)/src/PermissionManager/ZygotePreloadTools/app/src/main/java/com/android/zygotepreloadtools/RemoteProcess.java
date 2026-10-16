package com.android.zygotepreloadtools;

import android.os.ParcelFileDescriptor;
import android.os.RemoteException;

import java.io.InputStream;
import java.io.OutputStream;

public class RemoteProcess extends Process {
    private final IRemoteProcess remote;

    private OutputStream outputStream;
    private InputStream inputStream;
    private InputStream errorStream;

    public RemoteProcess(IRemoteProcess remote) {
        this.remote = remote;
    }

    @Override
    public OutputStream getOutputStream() {
        if (outputStream == null) {
            try {
                ParcelFileDescriptor pfd = remote.getOutputStream();
                if (pfd == null) throw new RuntimeException("remote output pfd is null");
                outputStream = new ParcelFileDescriptor.AutoCloseOutputStream(pfd);
            } catch (RemoteException e) {
                throw new RuntimeException(e);
            }
        }
        return outputStream;
    }

    @Override
    public InputStream getInputStream() {
        if (inputStream == null) {
            try {
                ParcelFileDescriptor pfd = remote.getInputStream();
                if (pfd == null) throw new RuntimeException("remote input pfd is null");
                inputStream = new ParcelFileDescriptor.AutoCloseInputStream(pfd);
            } catch (RemoteException e) {
                throw new RuntimeException(e);
            }
        }
        return inputStream;
    }

    @Override
    public InputStream getErrorStream() {
        if (errorStream == null) {
            try {
                ParcelFileDescriptor pfd = remote.getErrorStream();
                if (pfd == null) throw new RuntimeException("remote error pfd is null");
                errorStream = new ParcelFileDescriptor.AutoCloseInputStream(pfd);
            } catch (RemoteException e) {
                throw new RuntimeException(e);
            }
        }
        return errorStream;
    }

    @Override
    public int waitFor() throws InterruptedException {
        try {
            return remote.waitFor();
        } catch (RemoteException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int exitValue() {
        try {
            return remote.exitValue();
        } catch (RemoteException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void destroy() {
        try {
            remote.destroy();
        } catch (RemoteException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean isAlive() {
        try {
            return remote.isAlive();
        } catch (RemoteException e) {
            throw new RuntimeException(e);
        }
    }
}