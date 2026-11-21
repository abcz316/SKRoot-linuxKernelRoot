package com.linux.permissionmanager.localadb;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class AdbManager {

    // 卡死的 adb server 连 kill-server 都不响应，只能换一个空闲端口绕开。
    private static final int PREFERRED_SERVER_PORT = 5038;
    private static volatile int serverPort = PREFERRED_SERVER_PORT;

    private static final long DEFAULT_TIMEOUT_SECONDS = 25L;
    private static final long SHELL_TIMEOUT_SECONDS = 60L;
    private static final int SERVER_PROBE_TIMEOUT_MS = 1_500;
    private static final long KILL_SERVER_TIMEOUT_SECONDS = 3L;
    private static final long RESTART_SERVER_TIMEOUT_SECONDS = 8L;
    private static final long PAIR_TIMEOUT_SECONDS = 12L;
    // 旧 server 收到 kill 后还要一点时间才释放端口，等不及就会连到正在退出的进程。
    private static final long SERVER_GONE_WAIT_MS = 3_000L;
    private static final String TMP_DIR_NAME = "adb-tmp";

    private static final int PROBE_NO_SERVER = 0;
    private static final int PROBE_HEALTHY = 1;
    private static final int PROBE_UNUSABLE = 2;

    private static final String PROBE_SERVICE = "host:version";
    private static final String SERVER_LOG_HINT = "Full server startup log: ";
    private static final String SERVER_START_MARKER = "--- adb starting";
    private static final Pattern ADB_LOG_PREFIX = Pattern.compile(
            "^\\d{2}-\\d{2} +\\d{2}:\\d{2}:\\d{2}\\.\\d+ +\\d+ +\\d+ +[A-Z] +adb *: *\\S* *"
    );

    public interface LineCallback {
        void onLine(String line);
    }

    private final Context context;
    private final File adbExecutable;
    private final File adbHome;
    private final File androidUserHome;
    private final File tmpDir;

    public AdbManager(Context context) {
        this.context = context.getApplicationContext();
        this.adbExecutable = new File(
                this.context.getApplicationInfo().nativeLibraryDir,
                "libadb.so"
        );
        this.adbHome = new File(this.context.getFilesDir(), "adb-home");
        this.androidUserHome = new File(adbHome, ".android");
        this.androidUserHome.mkdirs();
        // adb server 的日志/临时文件不能放在 cacheDir：系统清缓存会把目录整个删掉。
        this.tmpDir = adbTmpDir(this.context);
    }

    private static File adbTmpDir(Context context) {
        File dir = new File(context.getFilesDir(), TMP_DIR_NAME);
        if (!dir.isDirectory()) dir.mkdirs();
        return dir;
    }

    public boolean isAvailable() {
        if (!adbExecutable.isFile()) {
            return false;
        }
        if (!adbExecutable.canExecute()) {
            //noinspection ResultOfMethodCallIgnored
            adbExecutable.setExecutable(true, false);
        }
        return adbExecutable.canExecute();
    }

    /** @param host 部分 ROM 的配对服务只监听 wlan 地址，传空则改用 localhost。 */
    public CommandResult pair(String host, int pairingPort, String pairingCode) throws Exception {
        if (pairingPort <= 0) {
            throw new IllegalArgumentException("配对信息异常，请重试。");
        }
        if (pairingCode == null || !pairingCode.matches("\\d{6}")) {
            throw new IllegalArgumentException("配对码是 6 位数字。");
        }
        String address = host == null ? "" : host.trim();
        if (address.isEmpty()) {
            address = "localhost";
        } else if (address.indexOf(':') >= 0) {
            address = "[" + address + "]";
        }
        CommandResult serverResult = startServer();
        if (!serverResult.isSuccess()) {
            return serverResult;
        }
        CommandResult result = runAdb(
                Arrays.asList("pair", address + ":" + pairingPort, pairingCode),
                null,
                PAIR_TIMEOUT_SECONDS
        );
        if (!result.isSuccess() && isLocalServerFailure(result)) {
            // 本地 server 已经不可用了，不重建的话后面每次配对都会撞同一条坏连接。
            boolean reset = resetServer();
            return new CommandResult(result.exitCode, result.output, result.timedOut, reset);
        }
        return result;
    }

    public CommandResult connect(int connectPort) throws Exception {
        if (connectPort <= 0) {
            throw new IllegalArgumentException("连接信息异常，请重试。");
        }

        CommandResult startResult = startServer();
        if (!startResult.isSuccess()) {
            return startResult;
        }

        CommandResult result = runAdb(
                Arrays.asList("connect", "localhost:" + connectPort),
                null,
                DEFAULT_TIMEOUT_SECONDS
        );
        if (!result.isSuccess() && isLocalServerFailure(result)) {
            boolean reset = resetServer();
            return new CommandResult(result.exitCode, result.output, result.timedOut, reset);
        }
        return result;
    }

    /** 探活走一次 adb 握手（host:version），能区分端口空着、被占用、server 卡死三种情况。 */
    private CommandResult startServer() throws Exception {
        int port = serverPort;
        int probe = probeServer(port, SERVER_PROBE_TIMEOUT_MS);
        if (probe == PROBE_HEALTHY) return new CommandResult(0, "");
        if (probe == PROBE_UNUSABLE) port = rotateServerPort(port);

        CommandResult first = runAdb(Arrays.asList("start-server"), null, RESTART_SERVER_TIMEOUT_SECONDS);
        if (isServerReady(port)) return first;

        int retryPort = rotateServerPort(port);
        CommandResult retry = runAdb(Arrays.asList("start-server"), null, RESTART_SERVER_TIMEOUT_SECONDS);
        if (isServerReady(retryPort)) return retry;
        return new CommandResult(-1, joinOutput(first.output, retry.output));
    }

    private static boolean isServerReady(int port) {
        return probeServer(port, SERVER_PROBE_TIMEOUT_MS) == PROBE_HEALTHY;
    }

    private static String joinOutput(String first, String second) {
        String head = first == null ? "" : first.trim();
        String tail = second == null ? "" : second.trim();
        if (head.isEmpty()) return tail;
        if (tail.isEmpty()) return head;
        return head + "\n" + tail;
    }

    /**
     * 彻底换掉本地 adb server：kill → 等旧进程真正释放端口 → 换新端口 → 重启 → 探活。
     * 僵死的 server 往往 kill 不掉或者退得很慢，原地重启只会连到正在退出的旧进程，
     * 表现就是 “protocol fault (couldn't read status length): Success”。
     */
    public boolean resetServer() {
        try {
            runAdb(Arrays.asList("kill-server"), null, KILL_SERVER_TIMEOUT_SECONDS);
        } catch (Exception ignored) {
        }
        int oldPort = serverPort;
        waitForServerGone(oldPort, SERVER_GONE_WAIT_MS);
        int newPort = rotateServerPort(oldPort);
        try {
            runAdb(Arrays.asList("start-server"), null, RESTART_SERVER_TIMEOUT_SECONDS);
        } catch (Exception ignored) {
        }
        return isServerReady(newPort);
    }

    private static void waitForServerGone(int port, long timeoutMs) {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (probeServer(port, 300) == PROBE_NO_SERVER) return;
            try {
                Thread.sleep(150L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    /** 只匹配“本地 adb server 这一侧”出问题的输出；远端配对/连接被拒不算。 */
    public static boolean isLocalServerFailure(CommandResult result) {
        if (result == null) return false;
        if (result.timedOut) return true;
        String text = result.output == null ? "" : result.output.toLowerCase(Locale.ROOT);
        return text.contains("protocol fault")
                || text.contains("couldn't read status")
                || text.contains("cannot connect to daemon")
                || text.contains("failed to start daemon")
                || text.contains("server didn't ack")
                || text.contains("connection reset")
                || text.contains("broken pipe");
    }

    public static boolean looksLikeServerStartFailure(String output) {
        if (output == null) return false;
        String text = output.toLowerCase(Locale.ROOT);
        return text.contains("server didn't ack") || text.contains("cannot connect to daemon") || text.contains("failed to start daemon");
    }

    public CommandResult killServer() throws Exception {
        CommandResult result = runAdb(Arrays.asList("kill-server"), null, KILL_SERVER_TIMEOUT_SECONDS);
        int port = serverPort;
        if (probeServer(port, SERVER_PROBE_TIMEOUT_MS) == PROBE_UNUSABLE) {
            rotateServerPort(port);
        }
        return result;
    }

    public CommandResult executeScriptAsShell(int connectPort, String script, LineCallback lineCallback) throws Exception {
        if (connectPort <= 0) throw new IllegalArgumentException("连接信息异常，请重试。");
        if (script == null || script.trim().isEmpty()) throw new IllegalArgumentException("脚本内容为空");

        CommandResult connectResult = connect(connectPort);
        String connectText = connectResult.output.toLowerCase(Locale.ROOT);
        boolean connected = connectResult.isSuccess() && (connectText.contains("connected to") || connectText.contains("already connected"));
        if (!connected) {
            emitLines(lineCallback, connectResult.output);
            return connectResult;
        }

        String scriptInput = script.endsWith("\n") ? script : script + "\n";
        return runAdb(Arrays.asList("-s", "localhost:" + connectPort, "shell", "sh", "-s"), scriptInput, SHELL_TIMEOUT_SECONDS, lineCallback);
    }

    private CommandResult runAdb(List<String> adbArguments, String standardInput, long timeoutSeconds) throws Exception {
        return runAdb(adbArguments, standardInput, timeoutSeconds, null);
    }

    private CommandResult runAdb(List<String> adbArguments, String standardInput, long timeoutSeconds, LineCallback lineCallback) throws Exception {
        if (!isAvailable()) throw new IllegalStateException("缺少运行组件，请重新安装本APP。");
        int port = serverPort;
        List<String> command = new ArrayList<>();
        command.add(adbExecutable.getAbsolutePath());
        command.add("-P");
        command.add(String.valueOf(port));
        command.addAll(adbArguments);
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.directory(context.getFilesDir());
        processBuilder.redirectErrorStream(true);
        Map<String, String> environment = processBuilder.environment();
        environment.put("HOME", adbHome.getAbsolutePath());
        environment.put("ANDROID_USER_HOME", androidUserHome.getAbsolutePath());
        environment.put("TMPDIR", tmpDir.getAbsolutePath());
        environment.put("ADB_MDNS_AUTO_CONNECT", "0");
        // server 侧 mDNS 与配对无关（地址由 APP 的 NsdManager 解析），关掉可减少 server 启动失败点。
        environment.put("ADB_MDNS", "0");

        Process process = processBuilder.start();
        FutureTask<String> outputTask = new FutureTask<>(() -> readOutput(process.getInputStream(), lineCallback));
        Thread outputThread = new Thread(outputTask, "LocalAdb-OutputReader");
        outputThread.setDaemon(true);
        outputThread.start();

        FutureTask<Void> inputTask = new FutureTask<>(() -> {
            try (OutputStream input = process.getOutputStream()) {
                if (standardInput != null) {
                    input.write(standardInput.getBytes(StandardCharsets.UTF_8));
                    input.flush();
                }
            }
            return null;
        });
        Thread inputThread = new Thread(inputTask, "LocalAdb-InputWriter");
        inputThread.setDaemon(true);
        inputThread.start();

        try {
            boolean finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!finished) {
                process.destroy();
                if (!process.waitFor(1, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                }
                inputTask.cancel(true);
                String timeoutOutput = getOutputBestEffort(outputTask);
                return new CommandResult(-1, timeoutOutput + "\n操作超时，请重试。", true);
            }

            int exitCode = process.exitValue();
            String output = getOutput(outputTask);
            try {
                inputTask.get(3, TimeUnit.SECONDS);
            } catch (Exception e) {
                return new CommandResult(exitCode == 0 ? -1 : exitCode, output + "\n配对码发送失败，请重试。");
            }
            return new CommandResult(exitCode, output);
        } catch (Exception e) {
            inputTask.cancel(true);
            process.destroyForcibly();
            throw e;
        }
    }

    private static int probeServer(int port, int timeoutMs) {
        if (port <= 0) return PROBE_NO_SERVER;
        boolean reachable = false;
        for (InetAddress address : loopbackAddresses()) {
            int result = probeAddress(address, port, timeoutMs);
            if (result == PROBE_HEALTHY) return PROBE_HEALTHY;
            if (result == PROBE_UNUSABLE) reachable = true;
        }
        return reachable ? PROBE_UNUSABLE : PROBE_NO_SERVER;
    }

    private static int probeAddress(InetAddress address, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            try {
                socket.connect(new InetSocketAddress(address, port), timeoutMs);
            } catch (ConnectException e) {
                return PROBE_NO_SERVER;
            }
            socket.setSoTimeout(timeoutMs);
            try {
                OutputStream output = socket.getOutputStream();
                String request = String.format(Locale.ROOT, "%04x%s", PROBE_SERVICE.length(), PROBE_SERVICE);
                output.write(request.getBytes(StandardCharsets.UTF_8));
                output.flush();
                InputStream input = socket.getInputStream();
                if (!"OKAY".equals(readAscii(input, 4))) return PROBE_UNUSABLE;
                Integer.parseInt(readAscii(input, 4), 16);
                return PROBE_HEALTHY;
            } catch (Exception e) {
                return PROBE_UNUSABLE;
            }
        } catch (Exception e) {
            return PROBE_NO_SERVER;
        }
    }

    private static List<InetAddress> loopbackAddresses() {
        List<InetAddress> addresses = new ArrayList<>();
        try {
            addresses.add(InetAddress.getByAddress(new byte[]{127, 0, 0, 1}));
        } catch (Exception ignored) {
        }
        try {
            for (InetAddress address : InetAddress.getAllByName("localhost")) {
                if (!address.isLoopbackAddress()) continue;
                if (addresses.contains(address)) continue;
                addresses.add(address);
            }
        } catch (Exception ignored) {
        }
        return addresses;
    }

    private static String readAscii(InputStream input, int count) throws IOException {
        byte[] buffer = new byte[count];
        int read = 0;
        while (read < count) {
            int current = input.read(buffer, read, count - read);
            if (current <= 0) throw new IOException("连接已被对端关闭");
            read += current;
        }
        return new String(buffer, StandardCharsets.UTF_8);
    }

    private static synchronized int rotateServerPort(int unusablePort) {
        for (int i = 0; i < 8; i++) {
            int candidate = findFreePort();
            if (candidate > 0 && candidate != unusablePort) {
                serverPort = candidate;
                return candidate;
            }
        }
        serverPort = unusablePort == PREFERRED_SERVER_PORT ? PREFERRED_SERVER_PORT + 1 : PREFERRED_SERVER_PORT;
        return serverPort;
    }

    private static int findFreePort() {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByAddress(new byte[]{127, 0, 0, 1}))) {
            return socket.getLocalPort();
        } catch (Exception e) {
            return -1;
        }
    }

    // 日志以追加方式写到 $TMPDIR/adb.<uid>.log，要取最后一次 “--- adb starting ---” 之后的内容。
    public static String describeServerStartFailure(Context context, String output) {
        String detail = serverFailureDetail(context, output, 300);
        if (detail.isEmpty()) return "";
        String text = detail.toLowerCase(Locale.ROOT);
        if (text.contains("smartsocket") || text.contains("already in use") || text.contains("cannot bind")) {
            return "本地端口被占用";
        }
        if (text.contains("permission denied")) return "启动被系统拒绝";
        if (text.contains("no space")) return "存储空间不足";
        String first = detail.split("\n")[0].trim();
        return first.length() > 40 ? first.substring(0, 40) + "…" : first;
    }

    public static String serverFailureDetail(Context context, String output, int maxChars) {
        String block = readLastServerLogBlock(resolveServerLogFile(context, output));
        if (block.isEmpty()) return "";

        List<String> errors = new ArrayList<>();
        List<String> others = new ArrayList<>();
        for (String rawLine : block.split("\n")) {
            String line = stripAdbLogPrefix(rawLine);
            if (line.isEmpty() || isServerLogNoise(line)) continue;
            if (isServerLogError(line)) errors.add(line);
            else others.add(line);
        }

        List<String> picked = errors;
        if (picked.isEmpty()) {
            picked = others.size() <= 3 ? others : others.subList(others.size() - 3, others.size());
        }
        StringBuilder detail = new StringBuilder();
        for (String line : picked) {
            if (detail.length() > 0) detail.append('\n');
            detail.append(line);
            if (detail.length() >= maxChars) break;
        }
        String text = detail.toString();
        return text.length() > maxChars ? text.substring(0, maxChars) + "…" : text;
    }

    private static File resolveServerLogFile(Context context, String output) {
        if (output != null) {
            int index = output.indexOf(SERVER_LOG_HINT);
            if (index >= 0) {
                int start = index + SERVER_LOG_HINT.length();
                int end = output.indexOf('\n', start);
                String path = (end < 0 ? output.substring(start) : output.substring(start, end)).trim();
                if (!path.isEmpty()) {
                    File file = new File(path);
                    if (file.isFile()) return file;
                }
            }
        }
        File fallback = new File(adbTmpDir(context), "adb." + android.os.Process.myUid() + ".log");
        return fallback.isFile() ? fallback : null;
    }

    private static String readLastServerLogBlock(File file) {
        if (file == null) return "";
        try (RandomAccessFile reader = new RandomAccessFile(file, "r")) {
            long size = reader.length();
            int length = (int) Math.min(size, 16 * 1024);
            if (length <= 0) return "";
            byte[] buffer = new byte[length];
            reader.seek(size - length);
            reader.readFully(buffer);
            String text = new String(buffer, StandardCharsets.UTF_8);
            if (size > length) {
                int firstLineBreak = text.indexOf('\n');
                text = firstLineBreak < 0 ? "" : text.substring(firstLineBreak + 1);
            }
            int marker = text.lastIndexOf(SERVER_START_MARKER);
            if (marker >= 0) {
                int lineEnd = text.indexOf('\n', marker);
                text = lineEnd < 0 ? "" : text.substring(lineEnd + 1);
            }
            return text;
        } catch (Exception e) {
            return "";
        }
    }

    private static String stripAdbLogPrefix(String line) {
        Matcher matcher = ADB_LOG_PREFIX.matcher(line);
        String text = matcher.find() ? line.substring(matcher.end()) : line;
        return text.trim();
    }

    private static boolean isServerLogNoise(String line) {
        String lower = line.toLowerCase(Locale.ROOT);
        return lower.startsWith("android debug bridge version")
                || lower.startsWith("version ")
                || lower.startsWith("installed as ")
                || lower.startsWith("running on ")
                || lower.startsWith(SERVER_START_MARKER);
    }

    private static boolean isServerLogError(String line) {
        String lower = line.toLowerCase(Locale.ROOT);
        return lower.contains("error") || lower.contains("fatal") || lower.contains("fail")
                || lower.contains("cannot") || lower.contains("could not") || lower.contains("denied")
                || lower.contains("already in use") || lower.contains("unable")
                || lower.contains("exception") || lower.contains("abort") || lower.contains("killed");
    }

    private String getOutput(FutureTask<String> outputTask) throws Exception {
        return outputTask.get(3, TimeUnit.SECONDS);
    }

    private String getOutputBestEffort(FutureTask<String> outputTask) {
        try {
            return getOutput(outputTask);
        } catch (Exception e) {
            return "读取结果失败。";
        }
    }

    private static void emitLines(LineCallback lineCallback, String output) {
        if (lineCallback == null || output == null || output.isEmpty()) return;
        for (String line : output.split("\n")) {
            lineCallback.onLine(line);
        }
    }

    private String readOutput(InputStream inputStream, LineCallback lineCallback) throws Exception {
        if (lineCallback == null) return readOutput(inputStream);
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (output.length() < 256 * 1024) {
                    output.append(line).append('\n');
                }
                lineCallback.onLine(line);
            }
        }
        return output.toString().trim();
    }

    private String readOutput(InputStream inputStream) throws Exception {
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            char[] buffer = new char[2048];
            int count;
            while ((count = reader.read(buffer)) != -1) {
                if (output.length() < 256 * 1024) {
                    int allowed = Math.min(count, 256 * 1024 - output.length());
                    output.append(buffer, 0, allowed);
                }
            }
        }
        return output.toString().trim();
    }

    public static final class CommandResult {
        public final int exitCode;
        public final String output;
        /** 本地超时收尾时 adb 侧可能仍有未完成的请求。 */
        public final boolean timedOut;
        /** 本次失败后已强制重建本地 adb server，用户需要重新取配对码。 */
        public final boolean serverReset;

        CommandResult(int exitCode, String output) {
            this(exitCode, output, false, false);
        }

        CommandResult(int exitCode, String output, boolean timedOut) {
            this(exitCode, output, timedOut, false);
        }

        CommandResult(int exitCode, String output, boolean timedOut, boolean serverReset) {
            this.exitCode = exitCode;
            this.output = output == null ? "" : output;
            this.timedOut = timedOut;
            this.serverReset = serverReset;
        }
        public boolean isSuccess() {
            return exitCode == 0;
        }
    }
}
