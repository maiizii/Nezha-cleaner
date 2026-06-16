#!/bin/bash
# ============================================================
# 哪吒探针漏洞 - 后门检测与清理脚本 v3
#
# 攻击载荷 (已知 4 层):
#   1. 哪吒后门 Agent (C2: 207.58.173.192)
#   2. SSH 后门公钥 (gary@gary)
#   3. memfd 内存马 (伪装 kworker, 连 24.x)
#   4. SystemLoger 守护服务 (负责复活)
#
# 用法:
#   只扫描:            bash nezha-agent-cleaner.sh
#   dry-run:           bash nezha-agent-cleaner.sh --dry-run
#   交互清理:          bash nezha-agent-cleaner.sh --clean
#   非交互清理:        bash nezha-agent-cleaner.sh --clean --yes
# ============================================================

set -u

# ---- 颜色 ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ---- 参数解析 ----
MODE_SCAN=true
MODE_CLEAN=false
MODE_DRY_RUN=false
MODE_YES=false
for arg in "$@"; do
    case "$arg" in
        --clean)   MODE_CLEAN=true; MODE_SCAN=false ;;
        --dry-run) MODE_DRY_RUN=true ;;
        --yes|-y)  MODE_YES=true ;;
        --help|-h)
            echo "用法: $0 [--clean] [--dry-run] [--yes]"
            echo "  无参数      仅扫描 (默认)"
            echo "  --clean     扫描并清理 (需确认)"
            echo "  --dry-run   仅显示将执行的清理动作"
            echo "  --yes       跳过交互确认 (配合 --clean)"
            exit 0 ;;
        *) echo "未知参数: $arg"; exit 1 ;;
    esac
done

# ---- 常量 ----
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="/root/nezha-cleaner-${TIMESTAMP}.log"
BACKUP_DIR="/root/incident-backup-${TIMESTAMP}"
ATTACK_IP="207.58.173.192"
BAD_KEY_COMMENT="gary@gary"

# ---- 计数器 ----
COUNT_MALICIOUS=0
COUNT_SUSPICIOUS=0
COUNT_CLEANED=0
COUNT_REPORT_ONLY=0

# ---- 临时收集 ----
CLEANUP_ACTIONS=()

# ---- 工具函数 ----
log()       { echo -e "$1" | tee -a "$LOG_FILE"; }
log_raw()   { echo "$1" | tee -a "$LOG_FILE"; }
section()   { log "\n${CYAN}========== $1 ==========${NC}"; }
warn()      { log "${RED}[!!!] $1${NC}"; }
suspect()   { log "${YELLOW}[!!]  $1${NC}"; }
info()      { log "${GREEN}[ok]  $1${NC}"; }
hit()       { log "${RED}[hit] $1${NC}"; }

cmd_exists() { command -v "$1" >/dev/null 2>&1; }

backup_file() {
    local src="$1"
    if [[ -f "$src" ]]; then
        local dest="${BACKUP_DIR}${src}"
        mkdir -p "$(dirname "$dest")"
        cp -a "$src" "$dest" 2>/dev/null || true
    fi
}

backup_dir() {
    local src="$1"
    if [[ -d "$src" ]]; then
        local dest="${BACKUP_DIR}${src}"
        mkdir -p "$dest"
        cp -a "$src"/. "$dest"/ 2>/dev/null || true
    fi
}

add_cleanup_action() {
    local level="$1" desc="$2" cmd="$3"
    CLEANUP_ACTIONS+=("LEVEL:${level}|DESC:${desc}|CMD:${cmd}")
}

confirm_cleanup() {
    if [[ "$MODE_YES" == true ]]; then return 0; fi
    log "\n${YELLOW}以上清理操作即将执行，输入 YES 确认:${NC}"
    read -r answer
    [[ "$answer" == "YES" ]]
}

run_cmd() {
    local desc="$1"; shift
    if [[ "$MODE_DRY_RUN" == true ]]; then
        log "${YELLOW}[dry-run] 将执行: $*${NC}"
        return 0
    fi
    log "${GREEN}[clean] $desc${NC}"
    "$@"
}

# ============================================================
# 扫描 1: 网络连接
# ============================================================
scan_network_connections() {
    section "网络连接扫描"
    local found=0

    # ss
    if cmd_exists ss; then
        local suspicious
        suspicious=$(ss -tunap 2>/dev/null | grep -iE "$ATTACK_IP|nezha|nazhe|SystemLoger|systemloger|kworker|memfd" || true)
        if [[ -n "$suspicious" ]]; then
            log "${RED}[!!!] 可疑网络连接:${NC}"
            log_raw "$suspicious"
            found=1
        fi

        # 24.x 段连接提示 (排除常见合法 IP 段)
        local net24
        net24=$(ss -tunap 2>/dev/null | grep -oE "[0-9]+:[0-9]+\.[0-9]+\.[0-9]+:[0-9]+" | awk -F: '{print $3}' | grep -E "^24\." | sort -u || true)
        # 只输出包含 24.x 的完整行
        net24=""
        while IFS= read -r line; do
            local dst
            dst=$(echo "$line" | grep -oE "24\.[0-9]+\.[0-9]+\.[0-9]+" | head -1)
            if [[ -n "$dst" ]]; then
                # 排除 24.0.0.0/8 中的常见合法子网 (如 24.x 为 ISP 分配段，仅当明确可疑时提示)
                net24="${net24}${line}\n"
            fi
        done < <(ss -tunap 2>/dev/null | grep "24\.[0-9]" || true)
        net24=$(echo -e "$net24" | sed '/^$/d')
        if [[ -n "$net24" ]]; then
            log "${YELLOW}[!!]  24.x 段连接 (仅提示，非自动清理):${NC}"
            log_raw "$net24"
        fi
    fi

    # lsof
    if cmd_exists lsof; then
        local lsof_out
        lsof_out=$(lsof -i -P -n 2>/dev/null | grep -iE "$ATTACK_IP|nezha|nazhe|SystemLoger|systemloger|memfd" || true)
        if [[ -n "$lsof_out" ]]; then
            log "${RED}[!!!] lsof 可疑连接:${NC}"
            log_raw "$lsof_out"
            found=1
        fi
    fi

    if [[ $found -eq 0 ]]; then
        info "未发现可疑网络连接"
    fi
}

# ============================================================
# 扫描 2: 哪吒后门 Agent
# ============================================================
scan_nezha_backdoor() {
    section "哪吒 Agent 扫描"
    local found=0

    # 检查 systemd unit 文件
    local unit_dirs="/etc/systemd/system /lib/systemd/system /usr/lib/systemd/system"
    # 已知合法 agent 服务 (不告警)
    local LEGIT_AGENTS="1panel-agent|unified-monitoring-agent|oracle-cloud-agent|lxd-agent|snapd|cloud-init|containerd|docker"
    for udir in $unit_dirs; do
        [[ -d "$udir" ]] || continue
        while IFS= read -r unit_file; do
            local base
            base=$(basename "$unit_file")
            # 名称匹配 (排除已知合法服务)
            if echo "$base" | grep -qiE "nezha|nazhe|dashboard"; then
                local content
                content=$(cat "$unit_file" 2>/dev/null || true)
                local severity="suspicious"
                local reason="名称匹配"
                # 强命中: 内容包含恶意 IP 或恶意路径
                if echo "$content" | grep -qF "$ATTACK_IP" 2>/dev/null; then
                    severity="malicious"
                    reason="包含攻击IP $ATTACK_IP"
                elif echo "$content" | grep -qiE "nezha|nazhe" 2>/dev/null; then
                    severity="malicious"
                    reason="名称+内容均匹配哪吒"
                fi
                log "${RED}[${severity^^}] $unit_file ($reason)${NC}"
                log_raw "  内容: $(head -5 "$unit_file")"
                found=1
                if [[ "$severity" == "malicious" ]]; then
                    COUNT_MALICIOUS=$((COUNT_MALICIOUS + 1))
                    add_cleanup_action 1 "systemd: $base" "systemctl stop '$base'; systemctl disable '$base'; systemctl mask '$base'; rm -f '$unit_file'"
                else
                    COUNT_SUSPICIOUS=$((COUNT_SUSPICIOUS + 1))
                    add_cleanup_action 2 "systemd: $base (需确认)" "systemctl stop '$base'; systemctl disable '$base'; systemctl mask '$base'; rm -f '$unit_file'"
                fi
            elif echo "$base" | grep -qiE "agent"; then
                # agent 名称但不包含 nezha/nazhe，检查是否包含恶意特征
                if ! echo "$base" | grep -qiE "$LEGIT_AGENTS"; then
                    local content
                    content=$(cat "$unit_file" 2>/dev/null || true)
                    if echo "$content" | grep -qF "$ATTACK_IP" 2>/dev/null || \
                       echo "$content" | grep -qiE "nezha|nazhe|memfd|/dev/shm"; then
                        log "${RED}[SUSPICIOUS] $unit_file (agent 名称 + 可疑内容)${NC}"
                        log_raw "  内容: $(head -5 "$unit_file")"
                        found=1
                        COUNT_SUSPICIOUS=$((COUNT_SUSPICIOUS + 1))
                    fi
                fi
            fi
        done < <(find "$udir" -maxdepth 1 -name "*.service" -type f 2>/dev/null || true)
    done

    # 检查进程
    while IFS= read -r line; do
        log "${RED}[!!!] 哪吒进程: $line${NC}"
        found=1
        COUNT_SUSPICIOUS=$((COUNT_SUSPICIOUS + 1))
    done < <(ps auxww 2>/dev/null | grep -iE "nezha|nazhe" | grep -v grep | grep -v "nezha-agent-cleaner" || true)

    # 检查常见路径
    for p in /opt/nezha /opt/nazhe /etc/nezha /usr/local/bin/nezha-agent /usr/bin/nezha-agent; do
        if [[ -e "$p" ]]; then
            log "${RED}[!!!] 发现: $p${NC}"
            found=1
            COUNT_SUSPICIOUS=$((COUNT_SUSPICIOUS + 1))
        fi
    done
    for p in /tmp/nezha* /var/tmp/nezha* /dev/shm/nezha*; do
        # shellcheck disable=SC2086
        for f in $p; do
            if [[ -e "$f" ]] && [[ "$f" != "/tmp/nezha-cleaner"* ]] && [[ "$f" != "/tmp/nezha-agent-cleaner"* ]]; then
                log "${RED}[!!!] 发现: $f${NC}"
                found=1
                COUNT_SUSPICIOUS=$((COUNT_SUSPICIOUS + 1))
            fi
        done
    done

    # 检查到攻击IP的连接
    if cmd_exists ss; then
        local conn
        conn=$(ss -tnp 2>/dev/null | grep "$ATTACK_IP" || true)
        if [[ -n "$conn" ]]; then
            log "${RED}[!!!] 到攻击IP $ATTACK_IP 的活跃连接:${NC}"
            log_raw "$conn"
            found=1
            COUNT_MALICIOUS=$((COUNT_MALICIOUS + 1))
        fi
    fi

    [[ $found -eq 0 ]] && info "未发现哪吒后门 Agent"
}

# ============================================================
# 扫描 3: SSH 后门公钥
# ============================================================
scan_ssh_backdoor_keys() {
    section "SSH 后门公钥扫描"
    local found=0
    local ssh_key_files=()

    # 收集所有 authorized_keys 文件
    while IFS= read -r f; do
        [[ -f "$f" ]] && ssh_key_files+=("$f")
    done < <(find /root/.ssh /home/*/.ssh -name "authorized_keys*" -type f 2>/dev/null || true)

    if [[ ${#ssh_key_files[@]} -eq 0 ]]; then
        info "未发现 authorized_keys 文件"
        return
    fi

    for akf in "${ssh_key_files[@]}"; do
        local line_num=0
        while IFS= read -r line; do
            line_num=$((line_num + 1))
            [[ -z "$line" ]] && continue
            [[ "$line" == \#* ]] && continue

            local key_type key_comment fingerprint match_gary
            key_type=$(echo "$line" | awk '{print $1}')
            key_comment=$(echo "$line" | awk '{print $NF}')
            match_gary=false
            [[ "$line" == *"$BAD_KEY_COMMENT"* ]] && match_gary=true

            # 尝试获取 fingerprint
            fingerprint=""
            if cmd_exists ssh-keygen; then
                fingerprint=$(echo "$line" | ssh-keygen -l -f - 2>/dev/null | awk '{print $2}' || true)
            fi

            local status="normal"
            if [[ "$match_gary" == true ]]; then
                status="MALICIOUS"
                warn "$akf:$line_num $key_type $key_comment (匹配 $BAD_KEY_COMMENT) fp=$fingerprint"
                COUNT_MALICIOUS=$((COUNT_MALICIOUS + 1))
                found=1
                add_cleanup_action 1 "删除 $akf:$line_num gary@gary 公钥" \
                    "sed -i '${line_num}d' '$akf'"
            else
                # 输出所有 key 供审计
                log "${YELLOW}[audit] $akf:$line_num $key_type $key_comment fp=$fingerprint${NC}"
            fi
        done < "$akf"
    done

    [[ $found -eq 0 ]] && info "未发现 gary@gary 后门公钥 (已列出所有 key 供审计)"
}

# ============================================================
# 扫描 4: memfd 内存马
# ============================================================
scan_memfd_malware() {
    section "memfd 内存马 / 伪装 kworker 扫描"
    local found=0

    for pid_dir in /proc/[0-9]*; do
        local pid
        pid=$(basename "$pid_dir")
        [[ -d "$pid_dir" ]] || continue

        local exe="" cmdline="" comm="" ppid="" user=""
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null || true)
        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)
        comm=$(cat "/proc/$pid/comm" 2>/dev/null || true)
        ppid=$(awk '/^PPid:/{print $2}' "/proc/$pid/status" 2>/dev/null || true)
        user=$(awk '/^Uid:/{print $2}' "/proc/$pid/status" 2>/dev/null || true)

        [[ -z "$exe" ]] && continue

        local hit_reason=""
        local severity="suspicious"

        # 规则 1: exe 包含 memfd
        if echo "$exe" | grep -qi "memfd"; then
            hit_reason="exe 包含 memfd"
            severity="malicious"
        # 规则 2: exe 位于 /dev/shm
        elif echo "$exe" | grep -q "^/dev/shm/"; then
            hit_reason="exe 位于 /dev/shm"
            severity="malicious"
        # 规则 3: exe 位于 /tmp 或 /var/tmp 且 deleted
        elif echo "$exe" | grep -qE "^/(tmp|var/tmp)/" && echo "$exe" | grep -q "deleted"; then
            hit_reason="exe 位于 /tmp 或 /var/tmp 且已删除"
            severity="malicious"
        # 规则 4: exe 包含 deleted (排除已知正常进程)
        elif echo "$exe" | grep -q "deleted"; then
            if ! echo "$comm $cmdline" | grep -qiE "agetty|systemd-|sshd|sftp-server|unattended|python|rsyslog|cloud-init|sd-pam|dbus"; then
                hit_reason="exe 已删除 (非常见系统进程)"
                severity="suspicious"
            fi
        # 规则 5: 伪装 kworker (PPID != 2)
        elif echo "$comm" | grep -q "kworker"; then
            if [[ "$ppid" != "2" ]] && [[ -n "$cmdline" ]]; then
                hit_reason="伪装 kworker: PPID=$ppid (期望2), 有cmdline"
                severity="malicious"
            elif [[ -n "$cmdline" ]]; then
                hit_reason="kworker 有 cmdline (可疑)"
                severity="suspicious"
            fi
        fi

        # 规则 6: 伪装 kworker 且有外连
        if [[ -n "$hit_reason" ]] && cmd_exists ss; then
            local net
            net=$(ss -tnp 2>/dev/null | grep "pid=$pid" || true)
            if [[ -n "$net" ]]; then
                hit_reason="$hit_reason, 有外连"
                severity="malicious"
            fi
        fi

        if [[ -n "$hit_reason" ]]; then
            log "${RED}[${severity^^}] PID=$pid PPID=$ppid USER=$user COMM=$comm${NC}"
            log "${RED}  EXE=$exe${NC}"
            [[ -n "$cmdline" ]] && log "${RED}  CMD=$cmdline${NC}"
            log "${RED}  原因: $hit_reason${NC}"
            found=1

            if [[ "$severity" == "malicious" ]]; then
                COUNT_MALICIOUS=$((COUNT_MALICIOUS + 1))
                add_cleanup_action 1 "kill PID $pid ($comm)" "kill -TERM '$pid'; sleep 2; kill -KILL '$pid'"
            else
                COUNT_SUSPICIOUS=$((COUNT_SUSPICIOUS + 1))
                add_cleanup_action 2 "kill PID $pid ($comm, 需确认)" "kill -TERM '$pid'; sleep 2; kill -KILL '$pid'"
            fi
        fi
    done

    [[ $found -eq 0 ]] && info "未发现 memfd 内存马或伪装 kworker"
}

# ============================================================
# 扫描 5: SystemLoger 持久化
# ============================================================
scan_systemloger_persistence() {
    section "SystemLoger 持久化扫描"
    local found=0

    local malicious_patterns="SystemLoger|systemloger|system-loger|SystemLogger|systemlog\.service|logger\.service|loger"
    local content_patterns="$ATTACK_IP|memfd|kworker|/dev/shm|/tmp/|/var/tmp|bash\s+-c|/dev/tcp"
    # 已知合法服务排除列表
    local LEGIT_SERVICES="rsyslog|syslog-ng|systemd-journald|cloud-init|systemd-networkd|systemd-resolved|sshd|cron|docker|containerd|snapd|1panel|unified-monitoring|oracle-cloud|lxd|modemmanager|polkit|multipathd|open-iscsi|open-vm-tools|apparmor|iscsid|rpcbind|redis|grub|udisks2|netfilter|blk-availability|e2scrub|sysstat|dmesg|pollinate|snapd|ubuntu-advantage|unattended-upgrades|networkd-dispatcher|apport|cron|rsyslog|ssh|sshd|sub2api|easytier"

    # systemd services
    local unit_dirs="/etc/systemd/system /lib/systemd/system /usr/lib/systemd/system"
    for udir in $unit_dirs; do
        [[ -d "$udir" ]] || continue
        while IFS= read -r unit_file; do
            local base
            base=$(basename "$unit_file")
            [[ "$base" == *".service" ]] || continue

            local content
            content=$(cat "$unit_file" 2>/dev/null || true)

            local hit=false severity="" reason=""

            # 名称匹配 (排除真正的 rsyslog/syslog 和已知合法服务)
            if echo "$base" | grep -qiE "$malicious_patterns"; then
                if ! echo "$base" | grep -qiE "$LEGIT_SERVICES"; then
                    hit=true
                    reason="名称匹配: $base"
                fi
            fi

            # 内容匹配 (排除已知合法服务)
            if [[ "$hit" == false ]] && echo "$content" | grep -qiE "$content_patterns"; then
                # 排除已知合法服务
                if ! echo "$base" | grep -qiE "$LEGIT_SERVICES"; then
                    hit=true
                    reason="内容匹配可疑模式"
                fi
            fi

            if [[ "$hit" == true ]]; then
                # 判断严重级别
                if echo "$content" | grep -qF "$ATTACK_IP" || \
                   (echo "$content" | grep -qiE "memfd|/dev/shm" && echo "$content" | grep -qiE "24\.[0-9]"); then
                    severity="malicious"
                    COUNT_MALICIOUS=$((COUNT_MALICIOUS + 1))
                else
                    severity="suspicious"
                    COUNT_SUSPICIOUS=$((COUNT_SUSPICIOUS + 1))
                fi

                log "${RED}[${severity^^}] $unit_file ($reason)${NC}"
                log_raw "  内容片段: $(head -8 "$unit_file")"
                found=1
                add_cleanup_action "$([[ $severity == malicious ]] && echo 1 || echo 2)" \
                    "systemd: $base" \
                    "systemctl stop '$base' 2>/dev/null; systemctl disable '$base' 2>/dev/null; systemctl mask '$base' 2>/dev/null; rm -f '$unit_file'"
            fi
        done < <(find "$udir" -maxdepth 1 -name "*.service" -type f 2>/dev/null || true)
    done

    # timers
    while IFS= read -r timer_file; do
        local content
        content=$(cat "$timer_file" 2>/dev/null || true)
        if echo "$content" | grep -qiE "$malicious_patterns|$ATTACK_IP|memfd"; then
            log "${RED}[!!!] 可疑 timer: $timer_file${NC}"
            found=1
            COUNT_SUSPICIOUS=$((COUNT_SUSPICIOUS + 1))
            local base
            base=$(basename "$timer_file")
            add_cleanup_action 2 "timer: $base" \
                "systemctl stop '$base' 2>/dev/null; systemctl disable '$base' 2>/dev/null; rm -f '$timer_file'"
        fi
    done < <(find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -name "*.timer" -type f 2>/dev/null || true)

    # cron
    local cron_dirs="/etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs"
    for cdir in $cron_dirs; do
        [[ -d "$cdir" ]] || continue
        while IFS= read -r cron_file; do
            [[ -f "$cron_file" ]] || continue
            local content
            content=$(cat "$cron_file" 2>/dev/null || true)
            if echo "$content" | grep -qiE "$ATTACK_IP|nezha|nazhe|memfd|/dev/shm|bash\s+-c|/dev/tcp|$malicious_patterns"; then
                log "${RED}[!!!] 可疑 cron: $cron_file${NC}"
                log_raw "$content"
                found=1
                COUNT_SUSPICIOUS=$((COUNT_SUSPICIOUS + 1))
            fi
        done < <(find "$cdir" -maxdepth 1 -type f 2>/dev/null || true)
    done
    # /etc/crontab
    if [[ -f /etc/crontab ]]; then
        if grep -qiE "$ATTACK_IP|nezha|nazhe|memfd|/dev/shm|$malicious_patterns" /etc/crontab 2>/dev/null; then
            log "${RED}[!!!] 可疑 /etc/crontab${NC}"
            found=1
            COUNT_SUSPICIOUS=$((COUNT_SUSPICIOUS + 1))
        fi
    fi

    # 启动脚本
    for f in /etc/rc.local /etc/profile /etc/profile.d/*.sh /root/.bashrc; do
        # shellcheck disable=SC2086
        for ff in $f; do
            [[ -f "$ff" ]] || continue
            if grep -qiE "$ATTACK_IP|nezha|nazhe|memfd|/dev/shm|$malicious_patterns" "$ff" 2>/dev/null; then
                log "${RED}[!!!] 可疑启动/profile 脚本: $ff${NC}"
                found=1
                COUNT_SUSPICIOUS=$((COUNT_SUSPICIOUS + 1))
            fi
        done
    done
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        if grep -qiE "$ATTACK_IP|nezha|nazhe|memfd|/dev/shm|$malicious_patterns" "$f" 2>/dev/null; then
            log "${RED}[!!!] 可疑 bashrc: $f${NC}"
            found=1
            COUNT_SUSPICIOUS=$((COUNT_SUSPICIOUS + 1))
        fi
    done < <(find /home -maxdepth 2 -name ".bashrc" -type f 2>/dev/null || true)

    # /etc/ld.so.preload
    if [[ -f /etc/ld.so.preload ]]; then
        local preload_content
        preload_content=$(cat /etc/ld.so.preload 2>/dev/null || true)
        log "${RED}[!!!] /etc/ld.so.preload 存在 (高危):${NC}"
        log_raw "$preload_content"
        found=1
        COUNT_REPORT_ONLY=$((COUNT_REPORT_ONLY + 1))
        if echo "$preload_content" | grep -qiE "/tmp|/dev/shm|nezha|$ATTACK_IP"; then
            log "${RED}  >>> 内容指向恶意路径，强烈建议清理${NC}"
        fi
    fi

    # sshd_config
    for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        # shellcheck disable=SC2086
        for ff in $f; do
            [[ -f "$ff" ]] || continue
            if grep -qiE "$ATTACK_IP|nezha|nazhe|memfd|/dev/shm" "$ff" 2>/dev/null; then
                log "${RED}[!!!] 可疑 sshd 配置: $ff${NC}"
                found=1
                COUNT_SUSPICIOUS=$((COUNT_SUSPICIOUS + 1))
            fi
        done
    done

    # udev / tmpfiles.d / logrotate.d
    for d in /etc/udev/rules.d /etc/tmpfiles.d /etc/logrotate.d; do
        [[ -d "$d" ]] || continue
        while IFS= read -r f; do
            if grep -qiE "$ATTACK_IP|nezha|nazhe|memfd|/dev/shm|$malicious_patterns" "$f" 2>/dev/null; then
                log "${RED}[!!!] 可疑 $d 中的文件: $f${NC}"
                found=1
                COUNT_SUSPICIOUS=$((COUNT_SUSPICIOUS + 1))
            fi
        done < <(find "$d" -type f 2>/dev/null || true)
    done

    [[ $found -eq 0 ]] && info "未发现 SystemLoger 持久化"
}

# ============================================================
# 扫描 6: 用户和 sudoers
# ============================================================
scan_users_and_sudoers() {
    section "用户和 sudoers 审计"

    # UID=0 非 root 用户
    while IFS=: read -r uname _ uid _ _ _ _; do
        if [[ "$uid" == "0" ]] && [[ "$uname" != "root" ]]; then
            warn "UID=0 非 root 用户: $uname"
            COUNT_SUSPICIOUS=$((COUNT_SUSPICIOUS + 1))
        fi
    done < /etc/passwd

    # gary 用户
    if grep -q "^gary:" /etc/passwd 2>/dev/null; then
        warn "发现 gary 用户"
        COUNT_SUSPICIOUS=$((COUNT_SUSPICIOUS + 1))
    fi

    # sudoers
    for f in /etc/sudoers /etc/sudoers.d/*; do
        [[ -f "$f" ]] || continue
        # 排除已知合法文件
        if echo "$f" | grep -qiE "cloud-init|90-cloud-init"; then
            continue
        fi
        if grep -qiE "gary|nezha|nazhe|ALL.*NOPASSWD" "$f" 2>/dev/null; then
            warn "可疑 sudoers: $f"
            grep -n "gary\|nezha\|nazhe\|NOPASSWD" "$f" 2>/dev/null | while IFS= read -r line; do
                log "${RED}  $line${NC}"
            done
            COUNT_REPORT_ONLY=$((COUNT_REPORT_ONLY + 1))
        fi
    done

    # 最近登录
    log "${CYAN}最近登录记录:${NC}"
    last -a 2>/dev/null | head -20 | while IFS= read -r line; do
        log_raw "  $line"
    done

    # 当前在线用户
    if cmd_exists w; then
        log "${CYAN}当前在线:${NC}"
        w 2>/dev/null | while IFS= read -r line; do
            log_raw "  $line"
        done
    fi
}

# ============================================================
# 扫描 7: Docker 持久化
# ============================================================
scan_docker_persistence() {
    section "Docker 持久化扫描"

    if ! cmd_exists docker; then
        info "docker 未安装，跳过"
        return
    fi

    # 检查所有容器
    local containers
    containers=$(docker ps -a --format '{{.ID}} {{.Names}} {{.Image}} {{.Status}}' 2>/dev/null || true)
    if [[ -n "$containers" ]]; then
        log "${CYAN}所有 Docker 容器:${NC}"
        log_raw "$containers"

        # inspect 每个容器
        while IFS= read -r container_line; do
            local cid
            cid=$(echo "$container_line" | awk '{print $1}')
            [[ -z "$cid" ]] && continue
            local inspect_out
            inspect_out=$(docker inspect "$cid" 2>/dev/null || true)
            if echo "$inspect_out" | grep -qiE "$ATTACK_IP|nezha|nazhe|systemlog|memfd|/dev/shm|kworker|24\.[0-9]"; then
                warn "可疑容器 $cid: $(echo "$container_line" | awk '{print $2}')"
                log_raw "  $inspect_out" | head -20
                COUNT_SUSPICIOUS=$((COUNT_SUSPICIOUS + 1))
            fi
        done <<< "$containers"
    fi

    # 检查镜像
    local images
    images=$(docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' 2>/dev/null || true)
    if [[ -n "$images" ]] && echo "$images" | grep -qiE "nezha|nazhe|systemlog|kworker"; then
        warn "可疑 Docker 镜像:"
        log_raw "$images"
        COUNT_SUSPICIOUS=$((COUNT_SUSPICIOUS + 1))
    fi
}

# ============================================================
# 清理执行
# ============================================================
execute_cleanup() {
    section "执行清理"

    if [[ ${#CLEANUP_ACTIONS[@]} -eq 0 ]]; then
        info "无需清理的操作"
        return
    fi

    # 分类输出
    log "\n${BOLD}将执行的清理操作:${NC}"
    log "${RED}--- Level 1: 明确恶意 (将自动清理) ---${NC}"
    local has_l1=false
    for action in "${CLEANUP_ACTIONS[@]}"; do
        local level desc cmd
        level=$(echo "$action" | sed 's/LEVEL:\([^|]*\).*/\1/')
        desc=$(echo "$action" | sed 's/.*DESC:\([^|]*\).*/\1/')
        if [[ "$level" == "1" ]]; then
            log "  [L1] $desc"
            has_l1=true
        fi
    done
    [[ "$has_l1" == false ]] && log "  (无)"

    log "${YELLOW}--- Level 2: 高度可疑 (需确认) ---${NC}"
    local has_l2=false
    for action in "${CLEANUP_ACTIONS[@]}"; do
        local level desc
        level=$(echo "$action" | sed 's/LEVEL:\([^|]*\).*/\1/')
        desc=$(echo "$action" | sed 's/.*DESC:\([^|]*\).*/\1/')
        if [[ "$level" == "2" ]]; then
            log "  [L2] $desc"
            has_l2=true
        fi
    done
    [[ "$has_l2" == false ]] && log "  (无)"

    # 确认
    if [[ "$MODE_YES" != true ]]; then
        log "\n${YELLOW}输入 YES 确认执行以上清理操作:${NC}"
        read -r answer
        if [[ "$answer" != "YES" ]]; then
            log "${YELLOW}已取消清理${NC}"
            return
        fi
    fi

    # 备份
    mkdir -p "$BACKUP_DIR"
    log "\n${CYAN}备份到: $BACKUP_DIR${NC}"
    backup_dir /etc/systemd/system
    [[ -d /lib/systemd/system ]] && backup_dir /lib/systemd/system
    [[ -d /usr/lib/systemd/system ]] && backup_dir /usr/lib/systemd/system
    backup_dir /etc/cron.d
    [[ -d /etc/cron.hourly ]] && backup_dir /etc/cron.hourly
    [[ -d /etc/cron.daily ]] && backup_dir /etc/cron.daily
    [[ -d /etc/cron.weekly ]] && backup_dir /etc/cron.weekly
    [[ -d /etc/cron.monthly ]] && backup_dir /etc/cron.monthly
    [[ -d /var/spool/cron ]] && backup_dir /var/spool/cron
    [[ -d /var/spool/cron/crontabs ]] && backup_dir /var/spool/cron/crontabs
    [[ -f /etc/crontab ]] && backup_file /etc/crontab
    backup_dir /root/.ssh
    while IFS= read -r d; do
        [[ -d "$d/.ssh" ]] && backup_dir "$d/.ssh"
    done < <(find /home -maxdepth 1 -type d 2>/dev/null || true)
    backup_dir /etc/ssh
    [[ -f /etc/profile ]] && backup_file /etc/profile
    [[ -d /etc/profile.d ]] && backup_dir /etc/profile.d
    [[ -f /etc/rc.local ]] && backup_file /etc/rc.local
    [[ -f /root/.bashrc ]] && backup_file /root/.bashrc
    while IFS= read -r f; do
        backup_file "$f"
    done < <(find /home -maxdepth 2 -name ".bashrc" -type f 2>/dev/null || true)

    # 执行状态快照
    ps auxww > "${BACKUP_DIR}/ps-auxww.txt" 2>/dev/null || true
    ss -tunap > "${BACKUP_DIR}/ss-tunap.txt" 2>/dev/null || true
    if cmd_exists lsof; then
        lsof -i -P -n > "${BACKUP_DIR}/lsof-i.txt" 2>/dev/null || true
    fi
    systemctl list-units > "${BACKUP_DIR}/systemctl-units.txt" 2>/dev/null || true
    systemctl list-unit-files > "${BACKUP_DIR}/systemctl-unit-files.txt" 2>/dev/null || true

    # 执行清理
    for action in "${CLEANUP_ACTIONS[@]}"; do
        local level desc cmd
        level=$(echo "$action" | sed 's/LEVEL:\([^|]*\).*/\1/')
        desc=$(echo "$action" | sed 's/.*DESC:\([^|]*\).*/\1/')
        cmd=$(echo "$action" | sed 's/.*CMD://')

        if [[ "$level" == "2" ]] && [[ "$MODE_YES" != true ]]; then
            log "${YELLOW}[跳过 L2] $desc (需手动确认)${NC}"
            continue
        fi

        log "${GREEN}[清理] $desc${NC}"
        if [[ "$MODE_DRY_RUN" == true ]]; then
            log "${YELLOW}  命令: $cmd${NC}"
        else
            eval "$cmd" 2>/dev/null || true
            COUNT_CLEANED=$((COUNT_CLEANED + 1))
        fi
    done

    # 重新加载 systemd
    if [[ "$MODE_DRY_RUN" != true ]]; then
        systemctl daemon-reload 2>/dev/null || true
    fi
}

# ============================================================
# 总结
# ============================================================
print_summary() {
    section "扫描总结"
    log "${RED}明确恶意 (Level 1): $COUNT_MALICIOUS${NC}"
    log "${YELLOW}高度可疑 (Level 2): $COUNT_SUSPICIOUS${NC}"
    log "${CYAN}仅报告   (Level 3): $COUNT_REPORT_ONLY${NC}"
    if [[ "$MODE_CLEAN" == true ]]; then
        log "${GREEN}已清理操作数: $COUNT_CLEANED${NC}"
    fi

    if [[ $COUNT_MALICIOUS -gt 0 ]] || [[ $COUNT_SUSPICIOUS -gt 0 ]]; then
        log "\n${BOLD}${RED}安全建议:${NC}"
        log "  1. 建议重装系统或重建云实例"
        log "  2. 轮换所有 SSH 密钥对"
        log "  3. 更改所有用户密码"
        log "  4. 检查云平台密钥对，删除可疑公钥"
        log "  5. 检查防火墙规则，封禁 $ATTACK_IP"
        log "  6. 考虑使用 fail2ban 加固 SSH"
    fi

    log "\n日志文件: $LOG_FILE"
    [[ "$MODE_CLEAN" == true ]] && log "备份目录: $BACKUP_DIR"
}

# ============================================================
# 主函数
# ============================================================
main() {
    log "${BOLD}哪吒探针漏洞 - 后门检测与清理脚本 v3${NC}"
    log "时间: $(date)"
    log "主机: $(hostname)"
    log "模式: $(if [[ "$MODE_CLEAN" == true ]]; then echo "扫描+清理"; elif [[ "$MODE_DRY_RUN" == true ]]; then echo "dry-run"; else echo "仅扫描"; fi)"

    # 扫描
    scan_network_connections
    scan_nezha_backdoor
    scan_ssh_backdoor_keys
    scan_memfd_malware
    scan_systemloger_persistence
    scan_users_and_sudoers
    scan_docker_persistence

    # 清理
    if [[ "$MODE_CLEAN" == true ]] || [[ "$MODE_DRY_RUN" == true ]]; then
        execute_cleanup
    fi

    print_summary
}

main "$@"
