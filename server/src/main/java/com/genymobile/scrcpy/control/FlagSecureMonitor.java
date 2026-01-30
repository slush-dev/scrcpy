package com.genymobile.scrcpy.control;

import com.genymobile.scrcpy.util.Ln;

import android.annotation.SuppressLint;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Checks FLAG_SECURE state on request from PhoneVault.
 *
 * PhoneVault sends TYPE_CHECK_FLAG_SECURE control message, this monitor
 * checks visible windows via WindowManagerService, and sends back
 * TYPE_FLAG_SECURE device message if state changed.
 */
public class FlagSecureMonitor {

    private static final int FLAG_SECURE = 0x2000;
    private static final long SUBPROCESS_TIMEOUT_MS = 1000;
    private static final Pattern HEX_PATTERN = Pattern.compile("0x([0-9a-fA-F]+)");

    // Binder access via reflection - may be null if reflection fails
    private static final Method GET_SERVICE_METHOD;
    static {
        Method method = null;
        try {
            method = Class.forName("android.os.ServiceManager")
                    .getDeclaredMethod("getService", String.class);
        } catch (Exception e) {
            Ln.w("Failed to get ServiceManager.getService method, will use subprocess fallback: " + e.getMessage());
        }
        GET_SERVICE_METHOD = method;
    }

    private final DeviceMessageSender sender;

    // State tracking - null means no previous state (first check will always notify)
    // Access must be synchronized on 'this'
    private Boolean lastSecure = null;

    // Cached binder for WindowManagerService
    private IBinder windowManagerBinder;

    public FlagSecureMonitor(DeviceMessageSender sender) {
        this.sender = sender;
        Ln.i("FlagSecureMonitor initialized");
    }

    /**
     * Performs FLAG_SECURE check and sends notification if state changed.
     * Called when PhoneVault sends TYPE_CHECK_FLAG_SECURE control message.
     * Thread-safe: synchronized to prevent race conditions on lastSecure.
     */
    public synchronized void check() {
        long start = System.currentTimeMillis();
        Boolean result = checkFlagSecure();
        long elapsed = System.currentTimeMillis() - start;

        if (result == null) {
            Ln.w("FLAG_SECURE check failed");
            return;
        }

        Ln.d("FLAG_SECURE check took " + elapsed + "ms, result=" + result);

        // Send notification if state changed or first check
        boolean isInitial = (lastSecure == null);
        if (isInitial || !result.equals(lastSecure)) {
            Ln.i("FLAG_SECURE " + (isInitial ? "initial" : "changed") + ": " + result);
            lastSecure = result;
            DeviceMessage msg = DeviceMessage.createFlagSecure(result);
            sender.send(msg);
        }
    }

    /**
     * Gets the WindowManagerService binder, caching it for reuse.
     */
    @SuppressLint("PrivateApi,DiscouragedPrivateApi")
    private IBinder getWindowManagerBinder() {
        if (GET_SERVICE_METHOD == null) {
            return null;
        }
        if (windowManagerBinder == null) {
            try {
                windowManagerBinder = (IBinder) GET_SERVICE_METHOD.invoke(null, "window");
            } catch (Exception e) {
                Ln.w("Failed to get WindowManager binder: " + e.getMessage());
            }
        }
        return windowManagerBinder;
    }

    /**
     * Checks if FLAG_SECURE is active on any visible window.
     * Uses direct Binder IPC to call WindowManagerService.dump() - no subprocess spawn.
     * Returns null if the check fails.
     */
    private Boolean checkFlagSecure() {
        IBinder binder = getWindowManagerBinder();
        if (binder == null) {
            Ln.d("Using subprocess fallback (no binder)");
            return checkFlagSecureFallback();
        }

        ParcelFileDescriptor[] pipe = null;
        try {
            // Create a pipe to capture dump output
            pipe = ParcelFileDescriptor.createPipe();
            ParcelFileDescriptor readEnd = pipe[0];
            ParcelFileDescriptor writeEnd = pipe[1];

            // Call dump with "visible" argument to get only visible windows (much less output)
            binder.dump(writeEnd.getFileDescriptor(), new String[]{"visible"});

            // Close write end so read doesn't block forever
            writeEnd.close();
            writeEnd = null;

            // Read the output and check for SECURE flag
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(new FileInputStream(readEnd.getFileDescriptor())))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("fl=") && hasFlagSecure(line)) {
                        readEnd.close();
                        return true;
                    }
                }
            }

            readEnd.close();
            return false;

        } catch (Exception e) {
            Ln.w("Direct binder dump failed: " + e.getMessage() + ", falling back to subprocess");
            windowManagerBinder = null;
            return checkFlagSecureFallback();
        } finally {
            if (pipe != null) {
                try {
                    if (pipe[0] != null) pipe[0].close();
                } catch (Exception ignored) {}
                try {
                    if (pipe[1] != null) pipe[1].close();
                } catch (Exception ignored) {}
            }
        }
    }

    /**
     * Fallback method using subprocess.
     */
    private Boolean checkFlagSecureFallback() {
        Process process = null;
        try {
            ProcessBuilder pb = new ProcessBuilder("dumpsys", "window", "visible");
            pb.redirectErrorStream(true);
            process = pb.start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("fl=") && hasFlagSecure(line)) {
                        process.destroyForcibly();
                        return true;
                    }
                }
            }
            boolean finished = process.waitFor(SUBPROCESS_TIMEOUT_MS, TimeUnit.MILLISECONDS);
            if (!finished) {
                Ln.w("FLAG_SECURE subprocess timed out after " + SUBPROCESS_TIMEOUT_MS + "ms");
                process.destroyForcibly();
                return null;
            }
            return false;
        } catch (Exception e) {
            Ln.w("Failed to check FLAG_SECURE (fallback): " + e.getMessage());
            if (process != null) {
                process.destroyForcibly();
            }
            return null;
        }
    }

    /**
     * Checks if a line contains the SECURE flag.
     */
    private boolean hasFlagSecure(String line) {
        // Check for SECURE text
        if (line.contains(" SECURE") || line.contains("|SECURE") ||
            line.contains("SECURE ") || line.contains("SECURE|")) {
            return true;
        }
        // Check hex flag 0x2000 using regex
        Matcher matcher = HEX_PATTERN.matcher(line);
        while (matcher.find()) {
            try {
                long flags = Long.parseLong(matcher.group(1), 16);
                if ((flags & FLAG_SECURE) != 0) {
                    return true;
                }
            } catch (NumberFormatException e) {
                // Ignore malformed hex values
            }
        }
        return false;
    }
}
