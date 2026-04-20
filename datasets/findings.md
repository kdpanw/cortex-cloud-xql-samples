# findings

## Overview

Contains security findings across all finding types (vulnerabilities, misconfigurations, compliance violations, etc.) ingested into Cortex Cloud.

**Use when you need to:**
- Query across all finding categories in one place
- Track finding age and SLA compliance
- Correlate findings with asset or identity context

---

## Queries

### Vulnerability findings open for more than 30 days

```xql
dataset = findings
| filter xdm.finding.category = "VULNERABILITY"
| filter timestamp_diff(current_time(), _time, "DAY") > 30
```
