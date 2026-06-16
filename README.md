# 哪吒探针漏洞 - 后门检测与清理脚本

针对哪吒监控探针 (Nezha Agent) 漏洞的后门检测与清理工具。

## 攻击载荷

| # | 载荷 | 说明 |
|---|------|------|
| 1 | 哪吒后门 Agent | 安装在 /opt/nezha，连接 C2 服务器 |
| 2 | gary@gary SSH 后门 | 植入恶意 SSH 公钥 |
| 3 | memfd 内存马 | 伪装 kworker 进程，驻留内存 |
| 4 | systemlog.service | 伪装系统日志服务，负责复活 |
| 5 | systemd-executor | 异常文件，可能为后门组件 |

## 使用方法

### 仅扫描 (推荐先执行)

```bash
bash <(curl -s https://raw.githubusercontent.com/clarencejh/Nezha-cleaner/main/nezha-agent-cleaner.sh)
```

### 扫描 + 自动清理

```bash
bash <(curl -s https://raw.githubusercontent.com/clarencejh/Nezha-cleaner/main/nezha-agent-cleaner.sh) --clean
```

### 手动下载执行

```bash
curl -sO https://raw.githubusercontent.com/clarencejh/Nezha-cleaner/main/nezha-agent-cleaner.sh
chmod +x nezha-agent-cleaner.sh
./nezha-agent-cleaner.sh          # 仅扫描
sudo ./nezha-agent-cleaner.sh --clean  # 扫描+清理
```

## 检测项

1. 伪装 systemlog.service (与 rsyslog 区分)
2. /opt/nezha 安装目录
3. gary@gary SSH 后门公钥
4. memfd 内存马 / 伪装 kworker
5. SystemLoger 守护服务
6. /tmp 残留恶意文件
7. 定时任务后门
8. SSH 安全配置审计
9. rootkit 检查 (ld.so.preload + 内核模块)
10. 活跃网络连接审计

## 注意事项

- 建议先用扫描模式检查，确认后再用 `--clean` 清理
- 清理后建议：修改所有用户密码，重新生成 SSH 密钥对
- 日志文件保存在 `/root/nezha-scan-<hostname>-<timestamp>.log`

## 致谢

感谢社区安全研究人员提供的攻击指标 (IoCs)。
