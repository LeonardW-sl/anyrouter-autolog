# 飞书签到提醒实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 `grokregist` 已有飞书机器人安全配置到 AnyRouter GitHub Actions，并验证签到任务仍成功。

**Architecture:** 不修改 AnyRouter 业务代码。通过 SSH 从 VM `/opt/store-checkin/notify.env` 读取 `FEISHU_WEBHOOK_URL`，经标准输入写入 GitHub `production` 环境的 `FEISHU_WEBHOOK` Secret；工作流已有同名环境变量映射，运行时由 `utils.notify.NotificationKit.send_feishu` 发送交互卡片。

**Tech Stack:** GitHub CLI、SSH、GitHub Actions、Python/httpx、飞书机器人 Webhook。

## Global Constraints

- 不输出、记录或提交 webhook 明文。
- 不修改签到业务代码。
- 提醒条件固定为首次运行、余额变化、账号失败或运行异常。
- 全部成功且余额无变化时允许跳过提醒。
- 验证不得包含账号凭据或余额内容。

---

### Task 1: 配置 GitHub 环境 Secret

**Files:**
- Read: `/home/suli/grokregist/AGENTS.md:80-99`
- Read: `/home/suli/grokregist` VM file `/opt/store-checkin/notify.env`
- Write: GitHub environment Secret `production/FEISHU_WEBHOOK`

**Interfaces:**
- Consumes: VM variable `FEISHU_WEBHOOK_URL`.
- Produces: GitHub environment Secret `FEISHU_WEBHOOK` in `LeonardW-sl/anyrouter-autolog`.

- [ ] **Step 1: Read and validate the remote variable without printing it**

```bash
ssh -i /home/suli/grokregist/azure_vm_key suli@20.196.209.16 \
  "sudo awk -F= '\$1 == \"FEISHU_WEBHOOK_URL\" {print \$2}' /opt/store-checkin/notify.env" \
  | awk 'NF {found=1} END {exit found ? 0 : 1}'
```

Expected: exit code `0`; stdout must be redirected or consumed and must not be shown.

- [ ] **Step 2: Pipe the value directly into the GitHub Secret**

```bash
set -o pipefail
ssh -i /home/suli/grokregist/azure_vm_key suli@20.196.209.16 \
  "sudo awk -F= '\$1 == \"FEISHU_WEBHOOK_URL\" {print \$2}' /opt/store-checkin/notify.env" \
  | gh secret set FEISHU_WEBHOOK --repo LeonardW-sl/anyrouter-autolog --env production
```

Expected: exit code `0`; no webhook value appears in terminal output.

- [ ] **Step 3: Verify only Secret metadata**

```bash
gh secret list --repo LeonardW-sl/anyrouter-autolog --env production
```

Expected: `FEISHU_WEBHOOK` is listed; its value is never retrievable or printed.

### Task 2: Send a safe Feishu connectivity test

**Files:**
- Read: `utils/notify.py:73-85`

**Interfaces:**
- Consumes: GitHub Secret value from Task 1.
- Produces: One Feishu interactive card containing only a fixed test title and timestamp.

- [ ] **Step 1: Send a fixed-content card through the VM webhook without printing the URL**

```bash
ssh -i /home/suli/grokregist/azure_vm_key suli@20.196.209.16 \
  "sudo bash -c 'set -a; . /opt/store-checkin/notify.env; set +a; \
  python3 -c \"import json,os,urllib.request; \
  p={\\\"msg_type\\\":\\\"interactive\\\",\\\"card\\\":{\\\"header\\\":{\\\"template\\\":\\\"blue\\\",\\\"title\\\":{\\\"content\\\":\\\"AnyRouter 签到提醒测试\\\",\\\"tag\\\":\\\"plain_text\\\"}},\\\"elements\\\":[{\\\"tag\\\":\\\"markdown\\\",\\\"content\\\":\\\"飞书通知通道配置测试，不包含账号凭据和余额。\\\"}]}}; \
  r=urllib.request.urlopen(urllib.request.Request(os.environ[\\\"FEISHU_WEBHOOK_URL\\\"],data=json.dumps(p).encode(),headers={\\\"Content-Type\\\":\\\"application/json\\\"},method=\\\"POST\\\"),timeout=30); print(r.status)\"'" \
  | tail -1
```

Expected: HTTP status `200` (or the Feishu endpoint's successful HTTP response) and a visible test card in the configured Feishu group.

### Task 3: Run and verify the production workflow

**Files:**
- Read: `.github/workflows/checkin.yml:72-94`
- Read: `checkin.py:346-476`

**Interfaces:**
- Consumes: `ANYROUTER_ACCOUNTS` and `FEISHU_WEBHOOK` from `production`.
- Produces: A completed GitHub Actions run and sanitized verification output.

- [ ] **Step 1: Trigger the workflow manually**

```bash
gh workflow run 334879976 --repo LeonardW-sl/anyrouter-autolog --ref main
```

Expected: command exits `0` and a new run is created.

- [ ] **Step 2: Wait for the run and inspect sanitized status**

```bash
gh run watch <new-run-id> --repo LeonardW-sl/anyrouter-autolog --exit-status
```

Expected: exit code `0`; workflow conclusion `success`.

- [ ] **Step 3: Check only account count and final success summary**

```bash
gh run view <new-run-id> --repo LeonardW-sl/anyrouter-autolog --log \
  | grep -E 'Found [0-9]+ account|Success:|All accounts|Message push successful|Message push failed|notification skipped'
```

Expected: four accounts are found, `Success: 4/4`, and if the run meets notification conditions, a Feishu push success line appears; otherwise `notification skipped` is expected.

## Verification checklist

- [ ] `FEISHU_WEBHOOK` appears in the `production` Secret name list.
- [ ] The fixed-content Feishu test card is received.
- [ ] The new Actions run completes successfully.
- [ ] The run still reports four accounts and `Success: 4/4`.
- [ ] No secret, webhook, account cookie, API user, or balance is included in the report.

## Rollback

```bash
gh secret delete FEISHU_WEBHOOK --repo LeonardW-sl/anyrouter-autolog --env production
```

Deleting this one Secret disables Feishu notifications while leaving the check-in job intact.
