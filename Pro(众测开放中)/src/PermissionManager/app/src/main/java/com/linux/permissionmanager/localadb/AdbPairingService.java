package com.linux.permissionmanager.localadb;

import android.app.Notification;
import android.app.Service;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Log;

import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class AdbPairingService extends Service {

    public static final String ACTION_START = "com.linux.permissionmanager.localadb.action.START";
    public static final String ACTION_SUBMIT_CODE = "com.linux.permissionmanager.localadb.action.SUBMIT_CODE";
    public static final String ACTION_STOP = "com.linux.permissionmanager.localadb.action.STOP";
    public static final String EXTRA_PAIRING_CODE = "extra_pairing_code";
    public static final String EXTRA_SESSION_ID = "extra_session_id";

    private static final long PENDING_CODE_TIMEOUT_MS = 45_000L;
    private static final long CONNECT_ENDPOINT_WAIT_MS = 12_000L;
    private static final long CONNECT_ENDPOINT_POLL_MS = 200L;
    // 超过阶段超时仍未出结果，就认为 adb 侧已卡死，直接硬复位。
    private static final long PAIRING_STAGE_TIMEOUT_MS = 55_000L;
    private static final long CONNECT_STAGE_TIMEOUT_MS = 60_000L;
    private static final long TICK_INTERVAL_MS = 1_000L;

    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    // 卡死的任务会永久占住线程，超时后整个执行队列换掉。
    private ExecutorService adbOperationExecutor = Executors.newSingleThreadExecutor();

    private AdbManager adbManager;
    private MdnsDiscovery discovery;
    private AdbPairingReceiver pairingReceiver;
    private volatile MdnsDiscovery.Endpoint pairingEndpoint;
    private volatile MdnsDiscovery.Endpoint connectEndpoint;
    private boolean pairingServiceSeen;

    private String state = "idle";
    private String stateMessage = "尚未启动";
    private String commandOutput = "";
    private String pendingPairingCode;
    private String sessionId = "";

    private boolean foregroundStarted;
    private boolean operationRunning;
    private boolean adbConnected;
    private boolean silentStop;
    private volatile boolean stopping;
    private volatile int operationGeneration;
    private Future<?> activeOperation;
    private volatile boolean destroyed;
    private static volatile boolean serviceRunning = false;
    private long busySinceMs;

    // 收到配对码但系统配对页面迟迟不出现时的兜底。
    private final Runnable pendingCodeTimeout = new Runnable() {
        @Override
        public void run() {
            if (pendingPairingCode == null || operationRunning || stopping) return;
            pendingPairingCode = null;
            publishState("pair_expired", "未等到系统就绪，配对码可能已失效。请重新打开「使用配对码配对设备」页面，获取新的配对码后重试。", commandOutput);
        }
    };

    // 配对/连接阶段的硬超时：adb 请求卡死时通知栏会一直停在「配对中」，且按钮消失。
    private final Runnable busyWatchdog = new Runnable() {
        @Override
        public void run() {
            if (destroyed || stopping) return;
            if (!operationRunning || !isBusyState()) return;
            operationGeneration++;
            if (activeOperation != null) activeOperation.cancel(true);
            activeOperation = null;
            ExecutorService stuck = adbOperationExecutor;
            adbOperationExecutor = Executors.newSingleThreadExecutor();
            stuck.shutdownNow();
            operationRunning = false;
            adbConnected = false;
            publishState("pair_timeout",
                    "等待 ADB 服务超时，已自动重置。\n请确认「使用配对码配对设备」页面仍然打开后重新输入配对码；"
                            + "若仍然失败，请把「无线调试」关掉再打开，并保持本APP后台不受限制。",
                    commandOutput);
            try {
                adbOperationExecutor.execute(() -> {
                    try {
                        // 卡死的 server 只 kill 不重建还是连不上，直接换成新的。
                        adbManager.resetServer();
                    } catch (Exception ignored) {
                    }
                });
            } catch (RuntimeException ignored) {
            }
        }
    };

    private final Runnable busyTicker = new Runnable() {
        @Override
        public void run() {
            if (destroyed || stopping || !isBusyState()) return;
            refreshNotification();
            mainHandler.postDelayed(this, TICK_INTERVAL_MS);
        }
    };

    /** 动态注册：组件不进 manifest，其他APP枚举不到；代价是必须跟着服务生命周期注册。 */
    private void registerPairingReceiver() {
        pairingReceiver = new AdbPairingReceiver();
        IntentFilter filter = new IntentFilter();
        filter.addAction(AdbPairingReceiver.ACTION_SUBMIT_PAIRING_CODE);
        filter.addAction(AdbPairingReceiver.ACTION_STOP_SESSION);
        registerReceiver(pairingReceiver, filter);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        AdbPairingNotification.createChannel(this);
        registerPairingReceiver();
        adbManager = new AdbManager(this);
        discovery = new MdnsDiscovery(this, new MdnsDiscovery.Listener() {
            @Override
            public void onEndpointsChanged(MdnsDiscovery.Endpoint pairing, MdnsDiscovery.Endpoint connect) {
                pairingEndpoint = pairing;
                connectEndpoint = connect;
                if (pairing != null) pairingServiceSeen = true;
                onDiscoveryChanged();
            }

            @Override
            public void onLog(String message) {
                Log.d("LocalAdb", "mDNS: " + message);
            }

            @Override
            public void onDiscoveryFailed() {
                if (!destroyed && !stopping) {
                    publishState("discovery_failed", "未检测到无线调试。请关闭后重新打开「无线调试」再试。", "");
                }
            }
        });
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? ACTION_START : intent.getAction();
        // startForegroundService 要求 5 秒内调用 startForeground，静默收尾后的新请求必须把实例拉起来。
        if (stopping && silentStop && (ACTION_START.equals(action) || ACTION_SUBMIT_CODE.equals(action))) {
            silentStop = false;
            stopping = false;
        }
        // 通知栏操作都经 startForegroundService 转发，每次都要有对应的 startForeground。
        ensureForeground();
        if (stopping) {
            if (silentStop) stopSelf();
            return START_NOT_STICKY;
        }

        if (ACTION_STOP.equals(action)) {
            stopSession();
            return START_NOT_STICKY;
        }

        if (ACTION_START.equals(action) || action == null) {
            String newSessionId = intent == null ? null : intent.getStringExtra(EXTRA_SESSION_ID);
            // 用户重复点「确定」时不要打断正在进行的配对。
            boolean busy = operationRunning || pendingPairingCode != null;
            if (!busy && newSessionId != null && !newSessionId.isEmpty() && !newSessionId.equals(sessionId)) {
                beginSession(newSessionId);
            }
            startDiscoveryIfNeeded();
            if (operationRunning) {
                refreshNotification();
            } else if (adbConnected) {
                publishState("success", "已连接，可返回APP继续操作。", commandOutput);
            } else {
                updateDiscoveryState();
            }
        } else if (ACTION_SUBMIT_CODE.equals(action)) {
            // 配对码来自通知栏 RemoteInput，由 AdbPairingReceiver 取出后经 EXTRA_PAIRING_CODE 转发到这里。
            startDiscoveryIfNeeded();
            String code = intent.getStringExtra(EXTRA_PAIRING_CODE);
            if (code == null || !code.matches("\\d{6}")) {
                pendingPairingCode = null;
                publishState("invalid_code", "请输入 6 位数字的配对码。", "");
            } else if (operationRunning) {
                publishState(state, "当前操作尚未完成，请稍后再输入配对码。", commandOutput);
            } else if (adbConnected) {
                publishState("success", "已连接，可直接返回APP继续操作。", commandOutput);
            } else {
                pendingPairingCode = code;
                mainHandler.removeCallbacks(pendingCodeTimeout);
                mainHandler.postDelayed(pendingCodeTimeout, PENDING_CODE_TIMEOUT_MS);
                publishState("pairing", "正在配对，请稍候…", "");
                tryBeginPairing();
                if (pendingPairingCode != null) {
                    publishState("waiting_services", "正在等待系统就绪，请保持「使用配对码配对设备」页面打开，关闭后配对码将失效。", "");
                }
            }
        }

        return START_STICKY;
    }

    private void beginSession(String newSessionId) {
        operationGeneration++;
        if (activeOperation != null) activeOperation.cancel(true);
        activeOperation = null;
        sessionId = newSessionId;
        pendingPairingCode = null;
        mainHandler.removeCallbacks(pendingCodeTimeout);
        mainHandler.removeCallbacks(busyWatchdog);
        mainHandler.removeCallbacks(busyTicker);
        pairingServiceSeen = false;
        busySinceMs = 0L;
        operationRunning = false;
        adbConnected = false;
        silentStop = false;
        commandOutput = "";
        state = "idle";
        stateMessage = "等待配对";
        // 新会话必须从干净的 adb server 开始，否则会沿用上一次失败留下的僵死 server。
        resetLocalServerAsync();
    }

    private void resetLocalServerAsync() {
        try {
            adbOperationExecutor.execute(() -> {
                try { adbManager.resetServer(); } catch (Exception ignored) {}
            });
        } catch (RuntimeException ignored) {
        }
    }

    public static boolean isServiceRunning() { return serviceRunning; }

    private void ensureForeground() {
        Notification notification = buildNotification();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(AdbPairingNotification.NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE);
        } else {
            startForeground(AdbPairingNotification.NOTIFICATION_ID, notification);
        }
        foregroundStarted = true;
        serviceRunning = true;
    }

    private void startDiscoveryIfNeeded() {
        if (discovery != null && !discovery.isStarted()) {
            discovery.start();
        }
    }

    private void onDiscoveryChanged() {
        if (destroyed) return;
        if (adbConnected && connectEndpoint == null && !operationRunning && !stopping) {
            dropConnection();
            return;
        }
        if (pendingPairingCode != null) {
            // 配对服务消失说明配对页面已关闭，手里的配对码作废。
            if (pairingEndpoint == null && pairingServiceSeen && !operationRunning) {
                pendingPairingCode = null;
                mainHandler.removeCallbacks(pendingCodeTimeout);
                publishState("pair_expired", "配对码已失效，可能是配对页面被关闭。请重新打开该页面，获取新的配对码后重试。", commandOutput);
                return;
            }
            tryBeginPairing();
            return;
        }
        if (operationRunning || adbConnected || stopping) {
            refreshNotification();
            return;
        }
        updateDiscoveryState();
    }

    private void dropConnection() {
        adbConnected = false;
        publishState("disconnected", "与无线调试的连接已断开，请重新连接。", "");
        if (pairingEndpoint == null) {
            stopSilently();
        }
    }

    /** 静默收尾：撤掉通知并结束自己，不动 adb 服务。 */
    private void stopSilently() {
        if (stopping) return;
        stopping = true;
        silentStop = true;
        serviceRunning = false;
        operationGeneration++;
        if (activeOperation != null) activeOperation.cancel(true);
        activeOperation = null;
        pendingPairingCode = null;
        mainHandler.removeCallbacks(pendingCodeTimeout);
        mainHandler.removeCallbacks(busyWatchdog);
        mainHandler.removeCallbacks(busyTicker);
        busySinceMs = 0L;
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    private void updateDiscoveryState() {
        // 失败提示要留住，不能被随后的 mDNS 事件刷成「正在查找」，否则用户看不到失败原因。
        if (isFailureHintState()) {
            refreshNotification();
            return;
        }
        if (pairingEndpoint != null) {
            publishState("ready", "点击「输入配对码」，填写手机上显示的 6 位数字。\n若点击后无反应，请将本APP的后台休眠设为不限制。", "");
        } else if (connectEndpoint != null) {
            publishState("discovering_pair", "请进入「开发者选项」→「无线调试」→「使用配对码配对设备」。\n若长时间停留在此步骤，请将本APP的后台休眠设为不限制。", "");
        } else {
            publishState("discovering", "正在查找无线调试，请到「开发者选项」→「无线调试」打开开关。\n若长时间停留在此步骤，请将本APP的后台休眠设为不限制。", "");
        }
    }

    private boolean isFailureHintState() {
        return "pair_failed".equals(state)
                || "pair_timeout".equals(state)
                || "connect_failed".equals(state)
                || "invalid_code".equals(state)
                || "discovery_failed".equals(state)
                || "error".equals(state);
    }

    private void tryBeginPairing() {
        if (pendingPairingCode == null || operationRunning || stopping) return;
        // 配对只需要 pairing 端口，connect 端口等配对成功后再找。
        if (pairingEndpoint == null) return;
        final int pairPort = pairingEndpoint.port;
        final String pairHost = preferredPairHost(pairingEndpoint);
        final String code = pendingPairingCode;
        pendingPairingCode = null;
        mainHandler.removeCallbacks(pendingCodeTimeout);
        operationRunning = true;
        final int generation = ++operationGeneration;
        adbConnected = false;
        commandOutput = "";
        publishState("pairing", "正在配对，请稍候…", "");

        activeOperation = adbOperationExecutor.submit(() -> {
            try {
                AdbManager.CommandResult pairResult = adbManager.pair(pairHost, pairPort, code);
                // 本地 server 刚被强杀重建，这时重试只会白白消耗一次配对机会，必须让用户拿新码。
                if (!pairResult.isSuccess() && !pairResult.serverReset && !"localhost".equals(pairHost) && looksLikeConnectionProblem(pairResult.output)) {
                    // 个别 ROM 的配对服务只监听回环地址，换 localhost 再试一次。
                    AdbManager.CommandResult retryResult = adbManager.pair("localhost", pairPort, code);
                    if (retryResult.isSuccess()) pairResult = retryResult;
                }
                Log.i("LocalAdb", "adb pair " + pairHost + ":" + pairPort + " exit=" + pairResult.exitCode + " reset=" + pairResult.serverReset + " output=" + pairResult.output.replace('\n', ' '));
                if (!pairResult.isSuccess()) {
                    postState(generation, "pair_failed", pairFailedMessage(pairResult), pairResult.output);
                    return;
                }

                postState(generation, "connecting", "配对成功，正在连接，请稍候…", pairResult.output);
                int connectPort = waitForConnectPort(generation);
                if (connectPort <= 0) {
                    postState(generation, "connect_failed", "配对成功，但未能建立连接。请确认「无线调试」仍处于开启状态后重试。", pairResult.output);
                    return;
                }

                AdbManager.CommandResult connectResult = adbManager.connect(connectPort);
                String connectText = connectResult.output.toLowerCase(Locale.ROOT);
                boolean connected = connectResult.isSuccess() && (connectText.contains("connected to") || connectText.contains("already connected"));
                if (!connected) {
                    postState(generation, "connect_failed", "配对成功，但连接未能建立。请检查「无线调试」状态后重试。", connectResult.output);
                    return;
                }

                postState(generation, "success", "配对完成。请返回APP，再次点击「确定」继续。", connectResult.output);
            } catch (Exception e) {
                postState(generation, "error", "操作失败，请重试。", "");
            }
        });
    }

    private static String preferredPairHost(MdnsDiscovery.Endpoint endpoint) {
        if (endpoint == null) return "localhost";
        String host = endpoint.hostAddress == null ? "" : endpoint.hostAddress.trim();
        if (host.isEmpty() || host.indexOf(':') >= 0 || host.startsWith("127.")) return "localhost";
        return host;
    }

    private static boolean looksLikeConnectionProblem(String output) {
        String text = output == null ? "" : output.toLowerCase(Locale.ROOT);
        return text.contains("unable to start pairing")
                || text.contains("failed to connect")
                || text.contains("connection refused")
                || text.contains("no route to host")
                || text.contains("timed out")
                || text.contains("timeout");
    }

    private static String pairFailedMessage(AdbManager.CommandResult result) {
        String output = result == null ? "" : result.output;
        String text = output == null ? "" : output.toLowerCase(Locale.ROOT);
        if (AdbManager.looksLikeServerStartFailure(output)) {
            return "配对失败：ADB 服务没有正常启动。\n"
                    + "请先重启本APP再试；仍然失败就把「无线调试」关掉再重新打开，重新进入「使用配对码配对设备」页面，用新码重试。";
        }
        if (text.contains("wrong pairing code") || text.contains("invalid pairing code")) {
            return "配对失败：配对码不正确或已经失效。\n"
                    + "请重新打开「使用配对码配对设备」页面，用页面上新显示的 6 位配对码再试一次。";
        }
        if (result != null && result.serverReset) {
            return "配对失败：本地 ADB 服务无响应，已自动重置。\n" + "请重新打开「使用配对码配对设备」页面（端口和配对码都会变），用新显示的 6 位配对码再试一次。";
        }
        if (text.contains("protocol fault") || text.contains("couldn't read status")) {
            return "配对失败：本地 ADB 服务没有正常响应。\n" + "请重新打开「使用配对码配对设备」页面，用新码重试；若连续失败，把「无线调试」关掉再打开。";
        }
        if (looksLikeConnectionProblem(output)) {
            return "配对失败：连不上系统的配对服务。\n"
                    + "请关闭再重新打开「无线调试」，重新进入配对页面后重试。";
        }
        String reason = firstMeaningfulLine(output);
        if (reason.isEmpty()) {
            return "配对失败。请确认配对码正确，并保持「使用配对码配对设备」页面打开后重试。";
        }
        return "配对失败：" + reason + "\n请确认配对码正确，且输入时「使用配对码配对设备」页面仍然打开。";
    }

    private static String firstMeaningfulLine(String output) {
        if (output == null) return "";
        for (String line : output.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;
            String lower = trimmed.toLowerCase(Locale.ROOT);
            // 过滤 “* daemon not running; starting now at tcp:5038” 这类启动噪音。
            if (trimmed.startsWith("*")) continue;
            if (lower.startsWith("enter pairing code")) continue;
            if (lower.startsWith("full server startup log")) continue;
            return trimmed.length() > 80 ? trimmed.substring(0, 80) + "…" : trimmed;
        }
        return "";
    }

    private String notificationDetail() {
        String output = commandOutput == null ? "" : commandOutput.trim();
        if (output.isEmpty()) return "";
        // server 启动失败的输出里带着整段 adb.<uid>.log 转储，只取最后一次启动的关键行。
        if (AdbManager.looksLikeServerStartFailure(output)) {
            String reason = AdbManager.describeServerStartFailure(this, output);
            String tail = AdbManager.serverFailureDetail(this, output, 800);
            if (!tail.isEmpty()) {
                return reason.isEmpty() ? tail : "原因：" + reason + "\n" + tail;
            }
            if (!reason.isEmpty()) return "原因：" + reason;
        }
        StringBuilder filtered = new StringBuilder();
        for (String line : output.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.startsWith("*")) continue;
            if (filtered.length() > 0) filtered.append('\n');
            filtered.append(trimmed);
        }
        String text = filtered.toString().trim();
        if (text.isEmpty()) return "";
        return text.length() > 600 ? text.substring(0, 600) + "…" : text;
    }

    /** 返回 0 表示等待超时或被取消。 */
    private int waitForConnectPort(int generation) throws InterruptedException {
        long deadline = System.currentTimeMillis() + CONNECT_ENDPOINT_WAIT_MS;
        while (!destroyed && !stopping && generation == operationGeneration) {
            MdnsDiscovery.Endpoint endpoint = connectEndpoint;
            if (endpoint != null) return endpoint.port;
            if (System.currentTimeMillis() >= deadline) return 0;
            Thread.sleep(CONNECT_ENDPOINT_POLL_MS);
        }
        return 0;
    }

    private void postState(int generation, String newState, String message, String output) {
        mainHandler.post(() -> {
            if (!destroyed && !stopping && generation == operationGeneration) {
                publishState(newState, message, output);
            }
        });
    }

    private void publishState(String newState, String message, String output) {
        String previousState = state;
        state = newState;
        stateMessage = message == null ? "" : message;
        if (output != null) commandOutput = output;

        if ("success".equals(state)) adbConnected = true;
        if ("connect_failed".equals(state) || "error".equals(state) || "stopped".equals(state)) adbConnected = false;
        if ("success".equals(state)) {
            if (connectEndpoint != null) LocalAdbHelper.onAdbConnected(connectEndpoint.port);
        } else if ("pair_failed".equals(state) || "pair_timeout".equals(state) || "connect_failed".equals(state) || "error".equals(state) || "stopped".equals(state) || "disconnected".equals(state)) {
            LocalAdbHelper.onAdbDisconnected();
        }

        boolean busy = isBusyState();
        // 不在进行中状态就必须复位 operationRunning，否则通知栏会永远停在「配对中」且按钮消失。
        if (!busy && !"stopping".equals(state)) operationRunning = false;

        mainHandler.removeCallbacks(busyWatchdog);
        mainHandler.removeCallbacks(busyTicker);
        if (busy) {
            // 同一阶段内重复刷新不能把看门狗往后推，否则超时会被无限延长。
            if (!newState.equals(previousState) || busySinceMs == 0L) {
                busySinceMs = System.currentTimeMillis();
            }
            long elapsed = System.currentTimeMillis() - busySinceMs;
            mainHandler.postDelayed(busyWatchdog, Math.max(TICK_INTERVAL_MS, busyStageTimeoutMs() - elapsed));
            mainHandler.postDelayed(busyTicker, TICK_INTERVAL_MS);
        } else {
            busySinceMs = 0L;
        }

        refreshNotification();
    }

    private long busyStageTimeoutMs() {
        if ("connecting".equals(state)) return CONNECT_STAGE_TIMEOUT_MS;
        return PAIRING_STAGE_TIMEOUT_MS;
    }

    private Notification buildNotification() {
        boolean busy = isBusyState();
        boolean canEnterPairingCode = pairingEndpoint != null && !operationRunning && !adbConnected && !stopping;
        String message = stateMessage;
        if (busy && busySinceMs > 0L) {
            long seconds = Math.max(0L, (System.currentTimeMillis() - busySinceMs) / 1000L);
            message = message + "(已等待" + seconds + "秒)";
        }
        return AdbPairingNotification.build(this, "ADB无线调试" + stateSuffix(), message, canEnterPairingCode, "success".equals(state), notificationDetail(), busy);
    }

    private boolean isBusyState() {
        return "pairing".equals(state) || "waiting_services".equals(state) || "connecting".equals(state);
    }

    private String stateSuffix() {
        if ("ready".equals(state)) return " · 待配对";
        if ("pairing".equals(state) || "waiting_services".equals(state)) return " · 配对中";
        if ("connecting".equals(state)) return " · 连接中";
        return "";
    }

    private void refreshNotification() {
        if (!foregroundStarted) return;
        // 静默收尾已撤掉通知，期间冒出的 mDNS 事件不能再把它挂回去。
        if (silentStop) return;
        android.app.NotificationManager manager = (android.app.NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (manager != null) manager.notify(AdbPairingNotification.NOTIFICATION_ID, buildNotification());
    }

    private void stopSession() {
        if (stopping) return;
        stopping = true;
        operationGeneration++;
        if (activeOperation != null) activeOperation.cancel(true);
        activeOperation = null;
        pendingPairingCode = null;
        mainHandler.removeCallbacks(pendingCodeTimeout);
        mainHandler.removeCallbacks(busyWatchdog);
        mainHandler.removeCallbacks(busyTicker);
        busySinceMs = 0L;
        operationRunning = true;
        publishState("stopping", "正在停止，请稍候…", commandOutput);

        adbOperationExecutor.execute(() -> {
            try {
                adbManager.killServer();
            } catch (Exception ignored) {}
            mainHandler.post(() -> {
                if (destroyed) return;
                if (discovery != null) discovery.stop();
                adbConnected = false;
                publishState("stopped", "已停止。", commandOutput);
                stopForeground(STOP_FOREGROUND_REMOVE);
                stopSelf();
            });
        });
    }

    @Override
    public void onDestroy() {
        destroyed = true;
        serviceRunning = false;
        operationGeneration++;
        mainHandler.removeCallbacks(pendingCodeTimeout);
        mainHandler.removeCallbacks(busyWatchdog);
        mainHandler.removeCallbacks(busyTicker);
        if (activeOperation != null) activeOperation.cancel(true);
        if (discovery != null) discovery.stop();
        if (pairingReceiver != null) {
            try {
                unregisterReceiver(pairingReceiver);
            } catch (IllegalArgumentException ignored) {
                // 注册失败时反注册会抛异常，忽略即可。
            }
            pairingReceiver = null;
        }
        // 别把 adb server 留成孤儿进程：下次启动会直接复用它，坏掉后只能靠清缓存恢复。
        if (adbManager != null) {
            try {
                adbOperationExecutor.execute(() -> {
                    try { adbManager.killServer(); } catch (Exception ignored) {}
                });
            } catch (RuntimeException ignored) {}
        }
        // 用 shutdown 而不是 shutdownNow：已经排队的 kill-server 要能跑完。
        adbOperationExecutor.shutdown();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }
}
