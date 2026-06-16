# 哪吒探针漏洞后门检测与清理脚本

用于检查和清理哪吒 Agent 被批量下发 payload 后留下的已知痕迹。

## 覆盖范围

1. 恶意哪吒 Agent 和残留目录：`/opt/nezha`、`/tmp/nezha-agent`
2. 已知 SSH 后门公钥：`gary@gary` 及两条已知 ed25519 key
3. memfd / `/dev/shm` 内存马和伪装 `kworker` 进程
4. `SystemLoger`、`c3pool`、`xmrig` 等持久化痕迹
5. cron 里的复活项，例如 `/dev/shm/.kworker_u8` 和 `/usr/freemem.sh`

## 使用方法

先只看清理计划：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/maiizii/Nezha-cleaner/main/nezha-agent-cleaner.sh) --dry-run
```

确认后执行清理：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/maiizii/Nezha-cleaner/main/nezha-agent-cleaner.sh) --clean --yes
```

清理后复查：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/maiizii/Nezha-cleaner/main/nezha-agent-cleaner.sh) --dry-run
```

复查时看到 `明确恶意 (Level 1): 0`、`高度可疑 (Level 2): 0`，并且显示 `无需清理的操作`，代表脚本覆盖的已知项已经清理完。

## 参数

```text
无参数      仅扫描
--dry-run   仅显示将执行的清理动作
--clean     扫描并清理，默认需要输入 YES
--yes       跳过确认，配合 --clean 使用
```

## 说明

- 脚本会先备份关键路径到 `/root/incident-backup-<timestamp>`。
- 哪吒 Agent 会优先按官方方式卸载，再删除残留目录和 service 文件。
- 这只能处理当前已知 IOC；被 root 控制过的机器仍建议轮换 SSH key，并按重要性排期重装。
