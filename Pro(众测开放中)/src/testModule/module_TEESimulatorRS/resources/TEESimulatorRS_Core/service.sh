MODDIR=${0%/*}
MODDIR=${MODDIR%/}
cd "$MODDIR"

CONFIG_DIR=/data/adb/tricky_store

echo "=== TEESimulator service.sh start ==="
echo "MODDIR=$MODDIR"

# 确保配置目录存在
mkdir -p "$CONFIG_DIR"
echo "config dir ready"

# 初始化配置文件（仅首次）
if [ ! -f "$CONFIG_DIR/keybox.xml" ]; then
    cp "$MODDIR/keybox.xml" "$CONFIG_DIR/keybox.xml"
    echo "keybox.xml copied"
fi

if [ ! -f "$CONFIG_DIR/target.txt" ]; then
    cp "$MODDIR/target.txt" "$CONFIG_DIR/target.txt"
    echo "target.txt copied"
fi

if [ ! -f "$CONFIG_DIR/security_patch.txt" ]; then
    printf '%s\n' \
        '# TEESimulator default: mirror live device props.' \
        '# system=prop reads ro.build.version.security_patch at cert-gen time;' \
        '# boot and vendor are auto-forced to prop too.' \
        '# Override with explicit YYYY-MM-DD dates if you want active spoofing.' \
        'system=prop' > "$CONFIG_DIR/security_patch.txt"

    chmod 644 "$CONFIG_DIR/security_patch.txt"
    echo "security_patch.txt created"
fi

if [ ! -f "$CONFIG_DIR/hbk" ]; then
    head -c 32 /dev/random > "$CONFIG_DIR/hbk"
    echo "hbk generated"
fi

# 启动 daemon（后台）
echo "starting supervisor..."
nohup "$MODDIR/supervisor" "$MODDIR/daemon" "$MODDIR" > /dev/null 2>&1 &
SUPERVISOR_PID=$!
echo "supervisor pid: $SUPERVISOR_PID"

sleep 2

DAEMON_PID=$(pidof TEESimulator 2>/dev/null || echo "not found")
echo "daemon(TEESimulator) pid: $DAEMON_PID"

# Clear logd size persist properties once boot completes
(
    until [ "$(getprop sys.boot_completed)" = "1" ]; do
        sleep 1
    done

    setprop persist.logd.size ""
    setprop persist.logd.size.crash ""
    setprop persist.logd.size.system ""
    setprop persist.logd.size.main ""
) &

echo "service.sh done"
