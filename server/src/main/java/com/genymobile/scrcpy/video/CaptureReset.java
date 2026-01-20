package com.genymobile.scrcpy.video;

import android.media.MediaCodec;
import android.os.Bundle;

import com.genymobile.scrcpy.util.Ln;

import java.util.concurrent.atomic.AtomicBoolean;

public class CaptureReset implements SurfaceCapture.CaptureListener {

    private final AtomicBoolean reset = new AtomicBoolean();

    // Current instance of MediaCodec to "interrupt" on reset
    private MediaCodec runningMediaCodec;

    public boolean consumeReset() {
        return reset.getAndSet(false);
    }

    public synchronized void reset() {
        reset.set(true);
        if (runningMediaCodec != null) {
            try {
                runningMediaCodec.signalEndOfInputStream();
            } catch (IllegalStateException e) {
                // ignore
            }
        }
    }

    /**
     * Request an immediate sync frame (IDR) from the encoder.
     * This is a lightweight operation that doesn't restart the encoder.
     * Uses MediaCodec.PARAMETER_KEY_REQUEST_SYNC_FRAME API.
     */
    public synchronized void requestSyncFrame() {
        if (runningMediaCodec != null) {
            Bundle params = new Bundle();
            params.putInt(MediaCodec.PARAMETER_KEY_REQUEST_SYNC_FRAME, 0);
            try {
                runningMediaCodec.setParameters(params);
                Ln.d("Sync frame requested");
            } catch (IllegalStateException e) {
                Ln.w("Failed to request sync frame: " + e.getMessage());
            }
        }
    }

    public synchronized void setRunningMediaCodec(MediaCodec runningMediaCodec) {
        this.runningMediaCodec = runningMediaCodec;
    }

    @Override
    public void onInvalidated() {
        reset();
    }
}
