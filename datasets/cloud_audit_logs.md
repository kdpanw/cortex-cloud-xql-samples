# cloud_audit_logs

## Overview

Contains audit log events from cloud providers, capturing API calls, authentication events, and configuration changes across your cloud accounts.

**Use when you need to:**
- Investigate API activity within a cloud account
- Identify failed or unauthorized operations
- Support incident response and compliance auditing

---

## Queries

### Get failed API calls for a specific account (last 30 days)

Replace `<account_id | account_name>` with the target account identifier.

```xql
config timeframe = 30d
| dataset = cloud_audit_logs
| filter project = "<account_id | account_name>"
| filter operation_status != "Success"
```
