package com.linux.permissionmanager.localadb;

import android.content.Context;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.net.wifi.WifiManager;
import android.os.Handler;
import android.os.Looper;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayDeque;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public final class MdnsDiscovery {
    public static final String PAIRING_SERVICE_TYPE = "_adb-tls-pairing._tcp";
    public static final String CONNECT_SERVICE_TYPE = "_adb-tls-connect._tcp";

    public interface Listener {
        void onEndpointsChanged(Endpoint pairing, Endpoint connect);
        void onLog(String message);
        default void onDiscoveryFailed() { }
    }

    public static final class Endpoint {
        public final String serviceName;
        public final String hostAddress;
        public final int port;
        public final String serviceType;

        Endpoint(String serviceName, String hostAddress, int port, String serviceType) {
            this.serviceName = serviceName;
            this.hostAddress = hostAddress;
            this.port = port;
            this.serviceType = serviceType;
        }

        @Override
        public String toString() {
            return hostAddress + ":" + port + " (" + serviceName + ")";
        }
    }

    private static final class ResolveRequest {
        final NsdServiceInfo serviceInfo;
        final String serviceType;
        final String key;

        ResolveRequest(NsdServiceInfo serviceInfo, String serviceType) {
            this.serviceInfo = serviceInfo;
            this.serviceType = serviceType;
            this.key = serviceType + "|" + serviceInfo.getServiceName();
        }
    }

    private final NsdManager nsdManager;
    private final WifiManager wifiManager;
    private final Listener listener;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    private final ArrayDeque<ResolveRequest> resolveQueue = new ArrayDeque<>();
    private final Set<String> pendingResolveKeys = new HashSet<>();
    private final Map<String, Endpoint> endpoints = new HashMap<>();

    private NsdManager.DiscoveryListener pairingDiscoveryListener;
    private NsdManager.DiscoveryListener connectDiscoveryListener;
    private WifiManager.MulticastLock multicastLock;

    private boolean started;
    private boolean resolving;
    private int generation;
    private String resolvingKey;
    private String resolvingServiceType;

    // 部分 ROM 上 resolveService 的回调可能都不来，会永久占住解析队列，用看门狗强制放行。
    private static final long RESOLVE_TIMEOUT_MS = 3_000L;
    private final Runnable resolveWatchdog = new Runnable() {
        @Override
        public void run() {
            synchronized (MdnsDiscovery.this) {
                if (!started || !resolving) return;
                resolving = false;
                if (resolvingKey != null) pendingResolveKeys.remove(resolvingKey);
                resolvingKey = null;
                String serviceType = resolvingServiceType;
                resolvingServiceType = null;
                log("服务解析超时，跳过并继续下一个");
                // 解析超时说明手里的端口不可信，丢掉它，避免下次拿过期端口去配对。
                if (serviceType != null) dropEndpoint(serviceType, "解析超时");
                resolveNext();
            }
        }
    };

    public MdnsDiscovery(Context context, Listener listener) {
        Context appContext = context.getApplicationContext();
        this.nsdManager = (NsdManager) appContext.getSystemService(Context.NSD_SERVICE);
        this.wifiManager = (WifiManager) appContext.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        this.listener = listener;
    }

    public synchronized void start() {
        if (started) {
            log("mDNS 发现已经在运行");
            return;
        }
        if (nsdManager == null) {
            log("当前设备没有可用的 NsdManager");
            return;
        }
        started = true;
        generation++;
        acquireMulticastLock();
        log("开始发现本机 ADB 无线调试服务……");
        startDiscovery(PAIRING_SERVICE_TYPE, true);
        startDiscovery(CONNECT_SERVICE_TYPE, false);
        failDiscoveryIfIncomplete();
    }

    public synchronized void stop() {
        generation++;
        mainHandler.removeCallbacks(resolveWatchdog);
        if (!started) {
            releaseMulticastLock();
            return;
        }
        started = false;
        stopDiscovery(pairingDiscoveryListener);
        stopDiscovery(connectDiscoveryListener);
        pairingDiscoveryListener = null;
        connectDiscoveryListener = null;
        resolveQueue.clear();
        pendingResolveKeys.clear();
        resolving = false;
        resolvingKey = null;
        resolvingServiceType = null;
        endpoints.clear();
        notifyEndpoints();
        releaseMulticastLock();
        log("已停止 mDNS 发现");
    }

    public synchronized boolean isStarted() {
        return started;
    }

    private void startDiscovery(final String serviceType, final boolean pairing) {
        final int listenerGeneration = generation;
        NsdManager.DiscoveryListener discoveryListener = new NsdManager.DiscoveryListener() {
            @Override
            public void onDiscoveryStarted(String type) {
                if (listenerGeneration != generation || !started) return;
                log("正在监听 " + serviceType);
            }

            @Override
            public void onServiceFound(NsdServiceInfo serviceInfo) {
                synchronized (MdnsDiscovery.this) {
                    if (listenerGeneration != generation || !started) return;
                    String name = serviceInfo.getServiceName();
                    if (name == null) return;
                    ResolveRequest request = new ResolveRequest(serviceInfo, serviceType);
                    if (pendingResolveKeys.add(request.key)) {
                        resolveQueue.add(request);
                        resolveNext();
                    }
                }
            }

            @Override
            public void onServiceLost(NsdServiceInfo serviceInfo) {
                synchronized (MdnsDiscovery.this) {
                    if (listenerGeneration != generation || !started) return;
                    String name = serviceInfo.getServiceName();
                    if (name == null) return;
                    String key = serviceType + "|" + name;
                    pendingResolveKeys.remove(key);
                    resolveQueue.removeIf(request -> request.key.equals(key));

                    Endpoint current = endpoints.get(serviceType);
                    if (current != null && current.serviceName.equals(name)) {
                        endpoints.remove(serviceType);
                        log("服务已消失：" + serviceType);
                        notifyEndpoints();
                    }
                }
            }

            @Override
            public void onDiscoveryStopped(String type) {
                if (listenerGeneration != generation) return;
                log("停止监听 " + serviceType);
            }

            @Override
            public void onStartDiscoveryFailed(String type, int errorCode) {
                synchronized (MdnsDiscovery.this) {
                    if (listenerGeneration != generation || !started) return;
                    log("启动发现失败：" + serviceType + "，错误码=" + errorCode);
                    stopDiscovery(this);
                    if (pairing) pairingDiscoveryListener = null;
                    else connectDiscoveryListener = null;
                    failDiscoveryIfIncomplete();
                }
            }

            @Override
            public void onStopDiscoveryFailed(String type, int errorCode) {
                if (listenerGeneration != generation) return;
                log("停止发现失败：" + serviceType + "，错误码=" + errorCode);
            }
        };

        if (pairing) {
            pairingDiscoveryListener = discoveryListener;
        } else {
            connectDiscoveryListener = discoveryListener;
        }

        try {
            nsdManager.discoverServices(serviceType, NsdManager.PROTOCOL_DNS_SD, discoveryListener);
        } catch (RuntimeException e) {
            log("启动服务发现异常：" + serviceType + "，" + e.getMessage());
            if (pairing) pairingDiscoveryListener = null;
            else connectDiscoveryListener = null;
        }
    }

    private synchronized void failDiscoveryIfIncomplete() {
        if (!started) return;
        if (connectDiscoveryListener != null && pairingDiscoveryListener != null) return;
        stop();
        log("mDNS 必需的服务监听启动失败，可在重新操作时重试");
        mainHandler.post(listener::onDiscoveryFailed);
    }

    private synchronized void resolveNext() {
        if (!started || resolving || resolveQueue.isEmpty()) return;
        final ResolveRequest request = resolveQueue.poll();
        if (request == null) return;
        resolving = true;
        resolvingKey = request.key;
        resolvingServiceType = request.serviceType;
        mainHandler.removeCallbacks(resolveWatchdog);
        mainHandler.postDelayed(resolveWatchdog, RESOLVE_TIMEOUT_MS);
        final int resolveGeneration = generation;
        try {
            nsdManager.resolveService(request.serviceInfo, new NsdManager.ResolveListener() {
                @Override
                public void onResolveFailed(NsdServiceInfo serviceInfo, int errorCode) {
                    synchronized (MdnsDiscovery.this) {
                        mainHandler.removeCallbacks(resolveWatchdog);
                        resolving = false;
                        resolvingKey = null;
                        resolvingServiceType = null;
                        pendingResolveKeys.remove(request.key);
                        if (!started || resolveGeneration != generation) return;
                        log("解析服务失败：" + request.serviceInfo.getServiceName() + "，错误码=" + errorCode);
                        dropEndpoint(request.serviceType, "解析失败");
                        resolveNext();
                    }
                }

                @Override
                public void onServiceResolved(NsdServiceInfo serviceInfo) {
                    synchronized (MdnsDiscovery.this) {
                        mainHandler.removeCallbacks(resolveWatchdog);
                        resolving = false;
                        resolvingKey = null;
                        resolvingServiceType = null;
                        if (!started || resolveGeneration != generation) return;
                        // 要移出待解析集合，否则同名服务再次广播时不会重新解析，端口变了还用旧值。
                        if (pendingResolveKeys.remove(request.key)) {
                            InetAddress host = serviceInfo.getHost();
                            int port = serviceInfo.getPort();
                            if (host == null || port <= 0) {
                                log("服务解析结果无效：" + serviceInfo.getServiceName());
                            } else if (!isLocalAddress(host)) {
                                log("忽略非本机服务：" + host.getHostAddress() + ":" + port);
                            } else {
                                Endpoint endpoint = new Endpoint(serviceInfo.getServiceName(), host.getHostAddress(), port, request.serviceType);
                                endpoints.put(request.serviceType, endpoint);
                                log("发现本机服务：" + request.serviceType + " -> " + host.getHostAddress() + ":" + port);
                                notifyEndpoints();
                            }
                        }
                        resolveNext();
                    }
                }
            });
        } catch (RuntimeException e) {
            mainHandler.removeCallbacks(resolveWatchdog);
            resolving = false;
            resolvingKey = null;
            resolvingServiceType = null;
            pendingResolveKeys.remove(request.key);
            log("请求解析服务异常：" + e.getMessage());
            dropEndpoint(request.serviceType, "解析异常");
            resolveNext();
        }
    }

    private boolean isLocalAddress(InetAddress candidate) {
        if (candidate.isLoopbackAddress()) return true;
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            if (interfaces == null) return false;
            while (interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                try {
                    if (!networkInterface.isUp()) continue;
                } catch (Exception ignored) {
                    continue;
                }
                Enumeration<InetAddress> addresses = networkInterface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress localAddress = addresses.nextElement();
                    if (localAddress.equals(candidate)) return true;
                    if (java.util.Arrays.equals(localAddress.getAddress(), candidate.getAddress())) return true;
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    private synchronized void notifyEndpoints() {
        final Endpoint pairing = endpoints.get(PAIRING_SERVICE_TYPE);
        final Endpoint connect = endpoints.get(CONNECT_SERVICE_TYPE);
        final int callbackGeneration = generation;
        mainHandler.post(() -> {
            synchronized (MdnsDiscovery.this) {
                if (callbackGeneration != generation) return;
            }
            listener.onEndpointsChanged(pairing, connect);
        });
    }

    /** 解析失败/超时时旧端口已经不可信，必须丢掉，否则会一直拿过期端口去配对。 */
    private synchronized void dropEndpoint(String serviceType, String reason) {
        Endpoint stale = endpoints.remove(serviceType);
        if (stale == null) return;
        log("丢弃过期服务地址：" + stale + "（" + reason + "）");
        notifyEndpoints();
    }

    private void log(final String message) {
        mainHandler.post(() -> listener.onLog(message));
    }

    private void stopDiscovery(NsdManager.DiscoveryListener discoveryListener) {
        if (discoveryListener == null || nsdManager == null) return;
        try {
            nsdManager.stopServiceDiscovery(discoveryListener);
        } catch (RuntimeException ignored) {}
    }

    private void acquireMulticastLock() {
        if (wifiManager == null || multicastLock != null) return;
        try {
            multicastLock = wifiManager.createMulticastLock("LocalAdb:mDNS");
            multicastLock.setReferenceCounted(false);
            multicastLock.acquire();
        } catch (RuntimeException e) {
            log("获取 MulticastLock 失败：" + e.getMessage());
            multicastLock = null;
        }
    }

    private void releaseMulticastLock() {
        if (multicastLock == null) return;
        try {
            if (multicastLock.isHeld()) multicastLock.release();
        } catch (RuntimeException ignored) {}
        multicastLock = null;
    }
}
