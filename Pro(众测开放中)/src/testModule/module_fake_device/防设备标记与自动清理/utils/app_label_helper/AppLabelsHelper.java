import android.content.pm.ApplicationInfo;
import android.content.res.AssetManager;
import android.content.res.Resources;
import android.os.IBinder;
import android.util.Base64;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public final class AppLabelsHelper {
    private static Object packageManager() throws Exception {
        Class<?> serviceManager = Class.forName("android.os.ServiceManager");
        IBinder binder = (IBinder) serviceManager.getDeclaredMethod("getService", String.class).invoke(null, "package");
        Class<?> stub = Class.forName("android.content.pm.IPackageManager$Stub");
        return stub.getDeclaredMethod("asInterface", IBinder.class).invoke(null, binder);
    }

    @SuppressWarnings("unchecked")
    private static List<ApplicationInfo> installedApplications(Object manager) throws Exception {
        Method selected = null;
        for (Method method : manager.getClass().getMethods()) {
            Class<?>[] types = method.getParameterTypes();
            if (method.getName().equals("getInstalledApplications") && types.length == 2 && (types[0] == long.class || types[0] == int.class) && types[1] == int.class) {
                selected = method;
                break;
            }
        }

        if (selected == null) {
            System.err.println("getInstalledApplications method not found");
            return Collections.emptyList();
        }

        System.err.println("selected: " + selected);

        Class<?>[] types = selected.getParameterTypes();
        Object[] call = new Object[types.length];
        for (int index = 0; index < types.length; ++index) {
            if (types[index] == long.class) call[index] = 0L;
            else if (types[index] == int.class) call[index] = 0;
            else call[index] = null;
        }

        Object slice = selected.invoke(manager, call);
        if (slice == null) {
            System.err.println("getInstalledApplications returned null");
            return Collections.emptyList();
        }

        List<ApplicationInfo> list = (List<ApplicationInfo>) slice.getClass()
                .getMethod("getList")
                .invoke(slice);

        System.err.println("apps: " + list.size());
        return list;
    }

    private static String localizedLabel(ApplicationInfo info, Resources systemResources) {
        if (info.nonLocalizedLabel != null && info.nonLocalizedLabel.length() != 0) return info.nonLocalizedLabel.toString();
        if (info.labelRes == 0 || info.sourceDir == null) return "";

        AssetManager assets = null;
        try {
            assets = AssetManager.class.getDeclaredConstructor().newInstance();
            Method addAssetPath = AssetManager.class.getDeclaredMethod("addAssetPath", String.class);
            addAssetPath.setAccessible(true);
            addAssetPath.invoke(assets, info.sourceDir);
            if (info.splitSourceDirs != null) {
                for (String split : info.splitSourceDirs) {
                    if (split != null) addAssetPath.invoke(assets, split);
                }
            }
            Resources resources = new Resources(assets, systemResources.getDisplayMetrics(), systemResources.getConfiguration());
            CharSequence value = resources.getText(info.labelRes);
            return value == null ? "" : value.toString();
        } catch (Throwable ignored) {
            return "";
        } finally {
            if (assets != null) {
                try {
                    assets.close();
                } catch (Throwable ignored) {
                    // Best-effort resource cleanup.
                }
            }
        }
    }

	public static void main(String[] args) throws Exception {
		Resources systemResources = Resources.getSystem();
		List<ApplicationInfo> applications = installedApplications(packageManager());
		Collections.sort(applications, Comparator.comparing(info -> info.packageName));

		System.out.print("[");
		boolean first = true;

		for (ApplicationInfo info : applications) {
			if (info.packageName == null) continue;
			String label = localizedLabel(info, systemResources).trim();
			if (label.isEmpty()) continue;
			String encoded = Base64.encodeToString(label.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
			if (!first) System.out.print(",");
			first = false;
			System.out.print("{\"packageName\":\"" + info.packageName + "\",\"labelBase64\":\"" + encoded + "\"}");
		}
		System.out.println("]");
	}
}
