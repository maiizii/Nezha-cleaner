#!/bin/bash
# ============================================================
# 哪吒探针漏洞 - 后门检测与清理脚本 v2
# 攻击载荷 (已知):
#   1. 哪吒后门 Agent (/opt/nezha, 连 207.58.173.192)
#   2. gary@gary SSH 后门公钥 (ed25519)
#   3. memfd 内存马 (伪装 kworker, 连 24.x)
#   4. systemlog.service 伪装守护 (负责复活, 连 24.x)
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

LOG_FILE="/root/nezha-scan-$(hostname)-$(date +%Y%m%d_%H%M%S).log"
CLEANUP=false

if [[ "${1:-}" == "--clean" ]]; then
    CLEANUP=true
fi

log() { echo -e "$1" | tee -a "$LOG_FILE"; }
section() { log "\n${CYAN}========== $1 ==========${NC}"; }

ATTACK_IP="207.58.173.192"
# gary@gary ed25519 后门公钥 (完整内容, 用于精确匹配)
BAD_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMMDxNliLAR1lLp5koxMHQtdCN0cNrV9HQbtzaDfNu8J gary@gary"

# ============================================================
# 1. 检测哪吒 Agent 服务 (多实例 = 被入侵)
# ============================================================
section "1. 检测哪吒 Agent 服务"

found_agent=0

# 方法1: 检查所有已注册的 nezha/nazhe 服务 (包括停止的)
nezha_services=$(systemctl list-unit-files --type=service 2>/dev/null | grep -iE "nezha|nazhe" || true)
if [[ -n "$nezha_services" ]]; then
    log "${RED}[!] 发现哪吒相关服务:${NC}"
    echo "$nezha_services" | while IFS= read -r line; do
        log "${RED}    $line${NC}"
    done
    found_agent=1
    if [[ "$CLEANUP" == true ]]; then
        log "${YELLOW}[*] 清理所有哪吒服务...${NC}"
        echo "$nezha_services" | awk '{print $1}' | while IFS= read -r svc; do
            systemctl stop "$svc" 2>/dev/null || true
            systemctl disable "$svc" 2>/dev/null || true
            rm -f "/etc/systemd/system/$svc" "/usr/lib/systemd/system/$svc"
            log "${GREEN}[✓] 已清除 $svc${NC}"
        done
        systemctl daemon-reload 2>/dev/null || true
    fi
fi

# 方法2: 检查正在运行的 nezha 进程
nezha_procs=$(ps aux 2>/dev/null | grep -iE "nezha|nazhe" | grep -v grep | grep -v "nezha-backdoor-cleanup" || true)
if [[ -n "$nezha_procs" ]]; then
    log "${RED}[!] 发现哪吒相关进程:${NC}"
    echo "$nezha_procs" | while IFS= read -r line; do
        log "${RED}    $line${NC}"
    done
    found_agent=1
    if [[ "$CLEANUP" == true ]]; then
        pkill -f "nezha" 2>/dev/null || true
        pkill -f "nazhe" 2>/dev/null || true
        log "${YELLOW}[*] 已终止哪吒进程${NC}"
    fi
fi

# 方法3: 检查 /opt/nezha 安装目录
for d in /opt/nezha /opt/nazhe /var/lib/nezha /var/lib/nazhe; do
    if [[ -d "$d" ]]; then
        log "${RED}[!] 发现哪吒安装目录: $d${NC}"
        ls -la "$d/" | head -10 | tee -a "$LOG_FILE"
        found_agent=1
        if [[ "$CLEANUP" == true ]]; then
            rm -rf "$d"
            log "${GREEN}[✓] 已删除 $d${NC}"
        fi
    fi
done

# 方法4: 检查到攻击IP的连接
while IFS= read -r line; do
    log "${RED}[!] 到攻击IP的连接: $line${NC}"
    found_agent=1
done < <(ss -tnp 2>/dev/null | grep "$ATTACK_IP" || true)

if [[ $found_agent -eq 0 ]]; then
    log "${GREEN}[✓] 未发现哪吒 Agent${NC}"
fi

# ============================================================
# 2. 检测伪装 systemlog.service (负责复活的守护服务)
# ============================================================
section "2. 检测伪装 systemlog.service"

found_fake=0

# 检查 /etc/systemd/system/ 下的 systemlog.service (非 rsyslog)
if [[ -f /etc/systemd/system/systemlog.service ]]; then
    # 验证是否是伪装的 (真正的 syslog 是 rsyslog 的符号链接)
    if [[ ! -L /etc/systemd/system/systemlog.service ]]; then
        log "${RED}[!] 发现伪装的 systemlog.service 文件${NC}"
        log "${RED}    内容:${NC}"
        cat /etc/systemd/system/systemlog.service | tee -a "$LOG_FILE"
        found_fake=1
        if [[ "$CLEANUP" == true ]]; then
            log "${YELLOW}[*] 清除伪装 systemlog.service...${NC}"
            systemctl stop systemlog.service 2>/dev/null || true
            systemctl disable systemlog.service 2>/dev/null || true
            rm -f /etc/systemd/system/systemlog.service
            systemctl daemon-reload 2>/dev/null || true
            log "${GREEN}[✓] systemlog.service 已清除${NC}"
        fi
    fi
fi

# 检查 systemctl 中注册的 systemlog 服务 (排除真正的 rsyslog)
while IFS= read -r line; do
    svc_name=$(echo "$line" | awk '{print $1}')
    # 排除 rsyslog 和 syslog.socket
    if echo "$svc_name" | grep -qiE "rsyslog|syslog\.socket"; then
        continue
    fi
    if echo "$line" | grep -qiE "systemlog"; then
        log "${RED}[!] 发现可疑服务: $line${NC}"
        found_fake=1
        if [[ "$CLEANUP" == true ]]; then
            systemctl stop "$svc_name" 2>/dev/null || true
            systemctl disable "$svc_name" 2>/dev/null || true
            rm -f "/etc/systemd/system/$svc_name" "/usr/lib/systemd/system/$svc_name"
            log "${GREEN}[✓] 已清除 $svc_name${NC}"
        fi
    fi
done < <(systemctl list-unit-files --type=service 2>/dev/null | grep -i "systemlog" || true)

if [[ $found_fake -eq 0 ]]; then
    log "${GREEN}[✓] 未发现伪装 systemlog.service${NC}"
fi

# ============================================================
# 3. 检测 gary@gary SSH 后门公钥
# ============================================================
section "3. 检测 gary@gary SSH 后门公钥"

found_keys=0

while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    # 精确匹配 gary@gary 公钥
    if grep -qF "gary@gary" "$f" 2>/dev/null; then
        log "${RED}[!] 发现后门公钥: $f${NC}"
        grep -n "gary@gary" "$f" | while read -r line; do
            log "${RED}    $line${NC}"
        done
        found_keys=1
        if [[ "$CLEANUP" == true ]]; then
            log "${YELLOW}[*] 清理 $f 中的 gary@gary 公钥...${NC}"
            grep -vF "gary@gary" "$f" > "${f}.clean" 2>/dev/null || true
            install -m 600 -o root -g root "${f}.clean" "$f" 2>/dev/null || \
                cp "${f}.clean" "$f" && chmod 600 "$f"
            rm -f "${f}.clean"
            log "${GREEN}[✓] 已删除 gary@gary 公钥${NC}"
        fi
    fi
done < <(find /root/.ssh /home/*/.ssh -name "authorized_keys*" 2>/dev/null || true)

if [[ $found_keys -eq 0 ]]; then
    log "${GREEN}[✓] 未发现 gary@gary 后门公钥${NC}"
fi

# ============================================================
# 4. 检测 memfd 内存马 / 伪装 kworker
# ============================================================
section "4. 检测 memfd 内存马 / 伪装 kworker"

found_memfd=0

# 检查 exe 指向 deleted 的可疑进程
while IFS= read -r pid; do
    [[ -z "$pid" ]] && continue
    exe=$(readlink /proc/$pid/exe 2>/dev/null || true)
    name=$(cat /proc/$pid/comm 2>/dev/null || true)
    cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ' || true)
    if [[ "$exe" == *"(deleted)"* ]]; then
        # 排除已知正常系统进程
        if ! echo "$name $cmdline" | grep -qiE "agetty|systemd-logind|systemd-resolve|python3|sshd|unattended|sd-pam|cloud-init|rsyslog|sftp-server|ssh-keysign"; then
            log "${RED}[!] 可疑 deleted 进程: PID=$pid exe=$exe name=$name cmd=$cmdline${NC}"
            found_memfd=1
            if [[ "$CLEANUP" == true ]]; then
                kill -9 "$pid" 2>/dev/null || true
                log "${YELLOW}[*] 已终止 PID $pid${NC}"
            fi
        fi
    fi
done < <(ls /proc/ 2>/dev/null | grep -E '^[0-9]+$')

# 检查伪装 kworker 的用户态进程 (正常 kworker 的 cmdline 为空)
while IFS= read -r line; do
    pid=$(echo "$line" | awk '{print $2}')
    cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ' || true)
    if [[ -n "$cmdline" ]]; then
        log "${RED}[!] 可疑 kworker (有cmdline): PID=$pid cmd=$cmdline${NC}"
        found_memfd=1
        if [[ "$CLEANUP" == true ]]; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    fi
done < <(ps aux 2>/dev/null | grep "\[kworker" | grep -v "R-" | grep -v "events" | grep -v "kblockd" | grep -v "cgroup" || true)

if [[ $found_memfd -eq 0 ]]; then
    log "${GREEN}[✓] 未发现内存马或伪装 kworker${NC}"
fi

# ============================================================
# 5. 检测 SystemLoger 守护服务
# ============================================================
section "5. 检测 SystemLoger 守护服务"

found_slog=0

# 检查进程
while IFS= read -r line; do
    log "${RED}[!] $line${NC}"
    found_slog=1
done < <(ps aux 2>/dev/null | grep -iE "systemloger|system-loger|syslog.*backdoor" | grep -v grep || true)

# 检查异常的 systemd-executor
while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    arch=$(file "$f" 2>/dev/null | grep -oE "ARM|aarch64|x86-64" | head -1)
    sys_arch=$(uname -m)
    log "${RED}[!] 可疑 systemd-executor: $f (arch=$arch, sys=$sys_arch)${NC}"
    found_slog=1
    if [[ "$CLEANUP" == true ]]; then
        rm -f "$f"
        log "${GREEN}[✓] 已删除 $f${NC}"
    fi
done < <(find /usr/lib/systemd/ -name "systemd-executor" -not -path "*/systemd/*" 2>/dev/null || true)

if [[ $found_slog -eq 0 ]]; then
    log "${GREEN}[✓] 未发现 SystemLoger 守护服务${NC}"
fi

# ============================================================
# 6. 检测 /tmp 残留恶意文件
# ============================================================
section "6. 检测 /tmp 残留恶意文件"

found_tmp=0
for f in /tmp/probe-agent /tmp/agent /tmp/.x /tmp/.cache; do
    if [[ -e "$f" ]]; then
        log "${RED}[!] 发现可疑文件: $f${NC}"
        ls -la "$f" | tee -a "$LOG_FILE"
        found_tmp=1
        if [[ "$CLEANUP" == true ]]; then
            rm -rf "$f"
            log "${GREEN}[✓] 已删除 $f${NC}"
        fi
    fi
done

# 检查 /tmp 中的 ELF 可执行文件
while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    if file "$f" 2>/dev/null | grep -q "ELF"; then
        log "${RED}[!] /tmp 中发现 ELF 文件: $f${NC}"
        ls -la "$f" | tee -a "$LOG_FILE"
        found_tmp=1
        if [[ "$CLEANUP" == true ]]; then
            rm -f "$f"
            log "${GREEN}[✓] 已删除 $f${NC}"
        fi
    fi
done < <(find /tmp -maxdepth 1 -type f -executable 2>/dev/null)

if [[ $found_tmp -eq 0 ]]; then
    log "${GREEN}[✓] /tmp 目录干净${NC}"
fi

# ============================================================
# 7. 检测定时任务后门
# ============================================================
section "7. 检测定时任务后门"

found_cron=0
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if echo "$line" | grep -qiE "curl.*\|.*bash|wget.*\|.*bash|nc |ncat |/dev/tcp|207\.58|nezha|nazhe|systemloger"; then
        log "${RED}[!] 可疑 crontab: $line${NC}"
        found_cron=1
    fi
done < <(crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null; cat /var/spool/cron/crontabs/* 2>/dev/null; cat /etc/cron.d/* 2>/dev/null)

while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    if grep -qiE "curl.*\|.*bash|wget.*\|.*bash|nc |ncat |/dev/tcp|207\.58|nezha|nazhe|systemloger" "$f" 2>/dev/null; then
        log "${RED}[!] 可疑 cron 文件: $f${NC}"
        cat "$f" | tee -a "$LOG_FILE"
        found_cron=1
        if [[ "$CLEANUP" == true ]]; then
            rm -f "$f"
            log "${GREEN}[✓] 已删除 $f${NC}"
        fi
    fi
done < <(find /etc/cron.d /var/spool/cron/crontabs -type f 2>/dev/null)

if [[ $found_cron -eq 0 ]]; then
    log "${GREEN}[✓] 未发现可疑定时任务${NC}"
fi

# ============================================================
# 8. SSH 安全配置检查
# ============================================================
section "8. SSH 安全配置检查"

sshd_real=$(sshd -T 2>/dev/null || true)
log "PermitRootLogin: $(echo "$sshd_real" | grep -i permitrootlogin || echo '未设置')"
log "PasswordAuthentication: $(echo "$sshd_real" | grep -i passwordauthentication || echo '未设置')"
log "PubkeyAuthentication: $(echo "$sshd_real" | grep -i pubkeyauthentication || echo '未设置')"

# ============================================================
# 9. 基础 rootkit 检查
# ============================================================
section "9. 基础 rootkit 检查"

if [[ -f /etc/ld.so.preload ]]; then
    log "${RED}[!] 发现 /etc/ld.so.preload (可能 rootkit):${NC}"
    cat /etc/ld.so.preload | tee -a "$LOG_FILE"
else
    log "${GREEN}[✓] /etc/ld.so.preload 不存在${NC}"
fi

# 内核模块检查
kver=$(uname -r)
hidden_count=0
if [[ -d "/lib/modules/$kver" ]]; then
    while IFS= read -r m; do
        [[ -z "$m" ]] && continue
        if [[ -d "/sys/module/$m" ]]; then
            continue
        fi
        m_file=$(echo "$m" | tr '_' '-')
        if ! find "/lib/modules/$kver" -name "${m_file}.ko*" -o -name "${m}.ko*" 2>/dev/null | grep -q .; then
            if [[ $hidden_count -eq 0 ]]; then
                log "${RED}[!] 可疑内核模块 (未找到 .ko 文件):${NC}"
            fi
            log "    $m"
            hidden_count=$((hidden_count + 1))
        fi
    done < <(lsmod 2>/dev/null | awk 'NR>1{print $1}')
fi
if [[ $hidden_count -eq 0 ]]; then
    log "${GREEN}[✓] 内核模块正常${NC}"
fi

# ============================================================
# 10. 活跃网络连接
# ============================================================
section "10. 活跃外部连接"

log "当前所有外连:"
ss -tnp 2>/dev/null | grep -v "127.0.0.1" | tee -a "$LOG_FILE"

log "所有监听端口:"
ss -tlnp 2>/dev/null | tee -a "$LOG_FILE"

# ============================================================
# 总结
# ============================================================
section "扫描完成"
log "日志文件: $LOG_FILE"
if [[ "$CLEANUP" == true ]]; then
    log "${YELLOW}已执行清理操作。请检查日志确认。${NC}"
    log "${YELLOW}建议: 修改所有用户密码, 重新生成 SSH 密钥对${NC}"
else
    log "${YELLOW}仅扫描模式。如需清理，请运行: $0 --clean${NC}"
fi
