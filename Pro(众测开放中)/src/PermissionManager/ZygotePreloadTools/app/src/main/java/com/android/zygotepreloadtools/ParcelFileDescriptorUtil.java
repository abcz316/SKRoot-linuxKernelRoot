package com.android.zygotepreloadtools;

import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class ParcelFileDescriptorUtil {
    private static final String TAG = "Magica";

    private ParcelFileDescriptorUtil() {}

    public static ParcelFileDescriptor pipeFrom(InputStream inputStream) throws IOException {
        ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createPipe();
        ParcelFileDescriptor readSide = pipe[0];
        ParcelFileDescriptor writeSide = pipe[1];

        OutputStream outputStream = new ParcelFileDescriptor.AutoCloseOutputStream(writeSide);
        new TransferThread(inputStream, outputStream).start();
        return readSide;
    }

    public static ParcelFileDescriptor pipeTo(OutputStream outputStream) throws IOException {
        ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createPipe();
        ParcelFileDescriptor readSide = pipe[0];
        ParcelFileDescriptor writeSide = pipe[1];

        InputStream inputStream = new ParcelFileDescriptor.AutoCloseInputStream(readSide);
        new TransferThread(inputStream, outputStream).start();
        return writeSide;
    }

    static class TransferThread extends Thread {
        private final InputStream mIn;
        private final OutputStream mOut;

        TransferThread(InputStream in, OutputStream out) {
            super("ParcelFileDescriptor Transfer Thread");
            this.mIn = in;
            this.mOut = out;
            setDaemon(true);
        }

        @Override
        public void run() {
            byte[] buf = new byte[8192];
            int len;
            try {
                while ((len = mIn.read(buf)) > 0) {
                    mOut.write(buf, 0, len);
                    mOut.flush();
                }
            } catch (IOException e) {
                Log.e(TAG, "TransferThread error", e);
            } finally {
                try {
                    mIn.close();
                } catch (IOException e) {
                    Log.e(TAG, "TransferThread close mIn error", e);
                }
                try {
                    mOut.close();
                } catch (IOException e) {
                    Log.e(TAG, "TransferThread close mOut error", e);
                }
            }
        }
    }
}