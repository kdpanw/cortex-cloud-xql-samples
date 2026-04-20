# cloud_health_auditing

## Overview

Records error, warning, and recovery events for scanning capabilities including Agentless Disk Scanning (ADS), Data Security Posture Management (DSPM), Registry scanning, and the Discovery engine.

**Use when you need to:**
- Monitor the health of your cloud data sources
- Troubleshoot ingestion or connectivity errors
- Track permissions problems
- Verify scanning status across specific cloud accounts and regions

---

## Queries

### Investigate ADS errors for a specific cloud account

Replace `account-id` with the target cloud account ID.

```xql
dataset = cloud_health_auditing
| filter capability = "ADS"
      and classification != "Informational"
      and account = "account-id"
```

---

### Retrieve failed registry scan results

Returns the most recent failed registry scan per resource, filtered to key fields: name, error message, account, region, and timestamp.

```xql
dataset = cloud_health_auditing
| filter capability = "Registry"
      and classification = "Failed"
      and scope = "Asset"
| dedup resource_id, account, connector by desc _time
| fields
      name,
      message,
      account,
      region,
      connector,
      error,
      _time as timestamp,
      resource_id
```
