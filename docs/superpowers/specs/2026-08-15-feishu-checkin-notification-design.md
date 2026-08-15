# 飞书签到提醒配置设计

日期：2026-08-15

## 目标

为 `LeonardW-sl/anyrouter-autolog` 的四个账号签到任务启用飞书消息提醒，并复用 `grokregist` 当前使用的飞书机器人。

## 范围

- 不修改签到业务代码。
- 不新建飞书机器人。
- 不在命令输出、GitHub 日志或仓库文件中保存明文 webhook。
- 仅在首次运行、余额变化、账号失败或运行异常时提醒；全部成功且余额无变化时跳过。

## 配置与数据流

1. 通过 SSH 从 VM `/opt/store-checkin/notify.env` 读取非空的 `FEISHU_WEBHOOK_URL`。
2. 通过标准输入将该值写入 GitHub `production` 环境 Secret `FEISHU_WEBHOOK`。
3. GitHub Actions 将 Secret 映射为签到进程的 `FEISHU_WEBHOOK` 环境变量。
4. `NotificationKit.send_feishu` 以飞书交互卡片形式发送签到摘要。

## 安全与错误处理

- webhook 只经进程管道传输，不回显、不写入临时明文文件。
- 配置前验证远端变量存在且非空；缺失时停止，不覆盖 GitHub Secret。
- 只核验 GitHub Secret 名称和更新时间，不读取 Secret 值。
- 通知失败不掩盖签到结果；以 Actions 日志和飞书测试卡片共同验证。

## 验证

1. 确认 `production` 环境存在 `FEISHU_WEBHOOK` Secret。
2. 向同一 webhook 发送一条不含账号凭据和余额的测试卡片。
3. 手动触发一次签到工作流，确认四个账号仍正常执行。
4. 核对日志：若余额无变化且全部成功，允许出现“notification skipped”；若满足提醒条件，应出现飞书发送成功记录。

## 回滚

删除 GitHub `production` 环境中的 `FEISHU_WEBHOOK` Secret 即可停用飞书通知，不影响签到任务。
