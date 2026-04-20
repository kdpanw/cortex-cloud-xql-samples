# ciem_permissions_with_last_access

## Overview

Contains cloud identity permissions enriched with last access data, enabling analysis of which identities have access to what resources and when they last used those permissions.

**Use when you need to:**
- Identify overprivileged identities
- Find permissions that have never been used or are stale
- Investigate specific permissions (e.g., `kms:Decrypt`, `s3:GetObject`) across roles and accounts
- Support least-privilege remediation efforts

---

## Queries

### Find AWS roles with access to KMS Decrypt

Lists all AWS roles that have the `kms:Decrypt` permission, grouped by role, account, and target key. Useful for identifying overly broad KMS access.

```xql
dataset = ciem_permissions_with_last_access
| filter source_cloud_type = "AWS"
| filter source_cloud_resource_type = "role"
| filter action_name = "kms:Decrypt"
| fields source_cloud_resource_name,
         action_name,
         source_cloud_resource_type,
         source_cloud_account_name,
         dest_cloud_resource_name
| comp values(source_cloud_resource_name) as target_keys
       by source_cloud_resource_name, action_name, source_cloud_resource_type, source_cloud_account_name
| sort asc source_cloud_resource_name
```
