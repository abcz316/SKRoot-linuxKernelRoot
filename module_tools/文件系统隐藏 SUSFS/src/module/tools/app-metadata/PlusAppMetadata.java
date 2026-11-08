import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.res.AssetManager;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.os.Looper;
import android.os.Build;
import android.util.Base64;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Set;

/** Read-only, one-shot framework resource decoder. Input/output use anonymous pipes. */
public final class PlusAppMetadata {
    private static final int MAX_INPUT = 32768;
    private static final int MAX_PNG = 65536;
    private static final int SIZE = 96;
    private final PackageManager pm;
    private final Object rawPm;
    private final Configuration configuration;
    private final String locale;

    private PlusAppMetadata() throws Exception {
        Configuration config = new Configuration(Resources.getSystem().getConfiguration());
        try {
            Class<?> am = Class.forName("android.app.ActivityManager");
            Object service = am.getDeclaredMethod("getService").invoke(null);
            config = new Configuration((Configuration) service.getClass().getMethod("getConfiguration").invoke(service));
        } catch (Throwable ignored) { /* System resources remain a valid fallback. */ }
        configuration = config;
        locale = Build.VERSION.SDK_INT >= 24 ? config.getLocales().toLanguageTags() : config.locale.toLanguageTag();
        PackageManager manager = null;
        try {
            if (Looper.getMainLooper() == null) Looper.prepareMainLooper();
            Class<?> activityThread = Class.forName("android.app.ActivityThread");
            Object thread = activityThread.getDeclaredMethod("systemMain").invoke(null);
            Context context = (Context) activityThread.getDeclaredMethod("getSystemContext").invoke(thread);
            manager = context.createConfigurationContext(config).getPackageManager();
        } catch (Throwable ignored) { /* Some OEMs restrict system context initialization. */ }
        pm = manager;
        Class<?> sm = Class.forName("android.os.ServiceManager");
        Object binder = sm.getDeclaredMethod("getService", String.class).invoke(null, "package");
        Class<?> stub = Class.forName("android.content.pm.IPackageManager$Stub");
        rawPm = stub.getDeclaredMethod("asInterface", android.os.IBinder.class).invoke(null, binder);
    }

    private Object packageCall(String methodName, String name) throws Exception {
        for (Method method : rawPm.getClass().getMethods()) {
            Class<?>[] types = method.getParameterTypes();
            if (!method.getName().equals(methodName) || types.length != 3 || types[0] != String.class
                    || (types[1] != long.class && types[1] != int.class) || types[2] != int.class) continue;
            Object flags = types[1] == long.class ? Long.valueOf(PackageManager.GET_SHARED_LIBRARY_FILES) : Integer.valueOf(PackageManager.GET_SHARED_LIBRARY_FILES);
            // A conditional expression would unbox/widen Integer to Long. Keep the wrapper exact.
            if (types[1] == int.class) flags = Integer.valueOf(PackageManager.GET_SHARED_LIBRARY_FILES);
            return method.invoke(rawPm, name, flags, Integer.valueOf(0));
        }
        throw new IllegalStateException("package_manager_signature");
    }

    private PackageInfo info(String name) throws Exception {
        if (pm != null) {
            try { return pm.getPackageInfo(name, PackageManager.GET_SHARED_LIBRARY_FILES); }
            catch (PackageManager.NameNotFoundException absent) { return null; }
            catch (RuntimeException ignored) { /* Try user-0 Binder API below. */ }
        }
        return (PackageInfo) packageCall("getPackageInfo", name);
    }

    private Resources resources(ApplicationInfo info) throws Exception {
        if (pm != null) {
            try {
                Resources value = pm.getResourcesForApplication(info);
                return new Resources(value.getAssets(), value.getDisplayMetrics(), configuration);
            } catch (Exception ignored) { /* Explicit base + split resource fallback below. */ }
        }
        return explicitResources(info);
    }

    private Resources explicitResources(ApplicationInfo info) throws Exception {
        AssetManager assets = AssetManager.class.getDeclaredConstructor().newInstance();
        Method add = AssetManager.class.getDeclaredMethod("addAssetPath", String.class);
        if (info.sharedLibraryFiles != null) {
            Method library = AssetManager.class.getDeclaredMethod("addAssetPathAsSharedLibrary", String.class);
            for (String path : info.sharedLibraryFiles) library.invoke(assets, path);
        }
        if (((Integer) add.invoke(assets, info.sourceDir)) == 0) throw new IllegalStateException("base_resources");
        if (info.splitSourceDirs != null) for (String path : info.splitSourceDirs) {
            if (((Integer) add.invoke(assets, path)) == 0) throw new IllegalStateException("split_resources");
        }
        String[] overlays = arrayField(info, "resourceDirs");
        if (overlays.length != 0) {
            Method overlay = AssetManager.class.getDeclaredMethod("addOverlayPath", String.class);
            for (String path : overlays) overlay.invoke(assets, path);
        }
        return new Resources(assets, Resources.getSystem().getDisplayMetrics(), configuration);
    }

    private static String[] arrayField(ApplicationInfo app, String field) {
        try {
            Object value = ApplicationInfo.class.getField(field).get(app);
            return value instanceof String[] ? (String[]) value : new String[0];
        }
        catch (Throwable ignored) { return new String[0]; }
    }

    private static void fileStamp(StringBuilder stamp, String path) {
        if (path == null) return;
        File file = new File(path);
        stamp.append('|').append(path).append(':').append(file.length()).append(':').append(file.lastModified());
    }

    private String version(PackageInfo info) throws Exception {
        ApplicationInfo app = info.applicationInfo;
        StringBuilder stamp = new StringBuilder(locale).append('|').append(configuration.toString())
                .append('|').append(Build.VERSION.SDK_INT >= 28 ? info.getLongVersionCode() : info.versionCode).append('|').append(info.lastUpdateTime)
                .append('|').append(app.uid).append('|').append(app.labelRes).append('|').append(app.icon);
        fileStamp(stamp, app.sourceDir);
        if (app.splitSourceDirs != null) for (String path : app.splitSourceDirs) fileStamp(stamp, path);
        if (app.sharedLibraryFiles != null) for (String path : app.sharedLibraryFiles) fileStamp(stamp, path);
        for (String path : arrayField(app, "resourceDirs")) fileStamp(stamp, path);
        for (String path : arrayField(app, "overlayPaths")) fileStamp(stamp, path);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(stamp.toString().getBytes(StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder();
        for (byte value : digest) hex.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
        return hex.toString();
    }

    private JSONObject metadata(String name, boolean icons, JSONObject known) throws Exception {
        JSONObject out = new JSONObject().put("package", name).put("uid", -1).put("label", "")
                .put("iconPng", "").put("status", "unavailable").put("version", "");
        String phase = "package";
        try {
            PackageInfo info = info(name);
            if (info == null || info.applicationInfo == null) return out.put("status", "not_found");
            ApplicationInfo app = info.applicationInfo;
            String version = version(info);
            out.put("uid", app.uid).put("version", version);
            if (known != null && version.equals(known.optString(name))) return out.put("unchanged", true).put("status", "ok");
            phase = "resources";
            Resources resources = resources(app);
            CharSequence label = app.nonLocalizedLabel;
            if (label == null || label.length() == 0) label = app.labelRes == 0 ? name : resources.getText(app.labelRes);
            String text = label.toString().trim();
            if (text.isEmpty()) text = name;
            // Keep names bounded without separating UTF-16 surrogate pairs.
            if (text.codePointCount(0, text.length()) > 512) text = text.substring(0, text.offsetByCodePoints(0, 512));
            out.put("label", text);
            if (icons) {
                phase = "drawable";
                Drawable icon;
                if (app.icon != 0) {
                    try { icon = resources.getDrawableForDensity(app.icon, configuration.densityDpi, null); }
                    catch (Exception ignored) { icon = explicitResources(app).getDrawableForDensity(app.icon, configuration.densityDpi, null); }
                } else {
                    // OEM getDefaultActivityIcon() can call LauncherApps and reject app_process.
                    // This is the same framework default resource, resolved locally instead.
                    icon = Resources.getSystem().getDrawable(android.R.drawable.sym_def_app_icon, null);
                }
                phase = "bitmap";
                Bitmap bitmap = Bitmap.createBitmap(SIZE, SIZE, Bitmap.Config.ARGB_8888);
                try {
                    phase = "draw";
                    icon.setBounds(0, 0, SIZE, SIZE);
                    icon.draw(new Canvas(bitmap));
                    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                    if (!bitmap.compress(Bitmap.CompressFormat.PNG, 100, bytes) || bytes.size() > MAX_PNG) throw new IllegalStateException("icon_size");
                    out.put("iconPng", Base64.encodeToString(bytes.toByteArray(), Base64.NO_WRAP));
                } finally { bitmap.recycle(); }
            }
            out.put("status", "ok");
        } catch (Throwable error) {
            // Helper diagnostics are intentionally not copied into the public API.
            Throwable cause = error.getCause() == null ? error : error.getCause();
            out.put("diagnostic", phase + ":" + cause.getClass().getSimpleName());
        }
        return out;
    }

    public static void main(String[] args) {
        Thread watchdog = new Thread(() -> {
            try { Thread.sleep(4800); } catch (InterruptedException ignored) { return; }
            System.exit(3);
        }, "metadata-deadline");
        watchdog.setDaemon(true);
        watchdog.start();
        int exit = 0;
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[2048];
            int count;
            while ((count = System.in.read(buffer)) != -1) {
                if (bytes.size() + count > MAX_INPUT) throw new IllegalArgumentException("input_size");
                bytes.write(buffer, 0, count);
            }
            JSONObject request = new JSONObject(bytes.toString("UTF-8"));
            boolean icons = request.getBoolean("includeIcons");
            JSONArray packages = request.getJSONArray("packages");
            if (packages.length() > (icons ? 16 : 64)) throw new IllegalArgumentException("package_count");
            Set<String> unique = new HashSet<>();
            for (int i = 0; i < packages.length(); ++i) {
                String name = packages.getString(i);
                if (name.length() > 255 || !name.matches("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)*") || !unique.add(name)) throw new IllegalArgumentException("package_name");
            }
            PlusAppMetadata helper = new PlusAppMetadata();
            JSONArray result = new JSONArray();
            for (int i = 0; i < packages.length(); ++i) result.put(helper.metadata(packages.getString(i), icons, request.optJSONObject("known")));
            System.out.println(new JSONObject().put("apps", result).put("locale", helper.locale));
        } catch (Throwable ignored) { exit = 2; }
        System.exit(exit);
    }
}
