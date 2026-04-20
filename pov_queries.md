# POV Queries

High-impact XQL queries useful for Proof of Value (POV) demonstrations. These queries showcase Cortex Cloud's cross-dataset visibility, identity intelligence, and cloud security depth.

---

## Cloud Asset Visibility

### All Kubernetes clusters in AWS
Demonstrates multi-cloud asset inventory and filtering by provider, compute class, and resource type.

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory
| filter (xdm.asset.provider = "AWS")
      and (xdm.asset.type.class = "Compute")
      and (xdm.asset.type.category = "Kubernetes Cluster")
```

---

### VMs running images older than 30 days
Demonstrates asset relationship traversal by joining VM instances to their source images and calculating true image age. Good for showing drift and hygiene gaps.

**Dataset:** `asset_inventory`

```xql
// Step 1: Find VM Images, extract the creation date, and calculate true age
dataset = asset_inventory
| filter xdm.asset.type.category = "VM Image"
| alter image_created_at_str = json_extract_scalar(xdm.asset.normalized_fields, "$['xdm.vm_image.created_at']"),
        image_asset_name = xdm.asset.name,
        image_asset_id = xdm.asset.id
| alter true_image_age_days = timestamp_diff(current_time(), parse_timestamp("%Y-%m-%dT%H:%M:%S.000Z", image_created_at_str), "DAY")
| filter true_image_age_days > 30

// Step 2: Join with VM Instances related to these images
| join (
    dataset = asset_inventory
    | filter xdm.asset.type.category = "VM Instance"
    | alter relation = json_extract_array(xdm.asset.normalized_fields, "$['xdm.asset.relations']")
    | arrayexpand relation
    | alter relation_asset_id = json_extract_scalar(relation, "$['xdm.asset.relation.asset_id']")
) as vm_asset vm_asset.relation_asset_id = image_asset_id

// Step 3: Display VM Instance and image age details
| fields xdm.asset.name as VM_Instance_Name,
         image_asset_name as Image_Name,
         image_created_at_str as Created_At,
         true_image_age_days,
         xdm.asset.provider as Cloud_Provider
```

---

## Identity & Permissions (CIEM)

### AWS roles with KMS Decrypt access
Shows identity intelligence by surfacing all roles with access to sensitive KMS keys, grouped by account and key. Good for demonstrating least-privilege gap analysis.

**Dataset:** `ciem_permissions_with_last_access`

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

---

## Vulnerability Management

### Vulnerability findings open for more than 30 days
Demonstrates SLA tracking and aging vulnerability risk. Simple but impactful for showing unresolved exposure.

**Dataset:** `findings`

```xql
dataset = findings
| filter xdm.finding.category = "VULNERABILITY"
| filter timestamp_diff(current_time(), _time, "DAY") > 30
```

---

## Cloud Audit & Compliance

### Failed API calls in a cloud account (last 30 days)
Useful for showing cloud audit log ingestion and quick access to failed/unauthorized activity.

**Dataset:** `cloud_audit_logs`

```xql
config timeframe = 30d
| dataset = cloud_audit_logs
| filter project = "<account_id | account_name>"
| filter operation_status != "Success"
```

---

## Scanning Health

### ADS errors for a specific account
Shows operational visibility into scanning health, useful for surfacing connectivity or permissions issues across cloud accounts.

**Dataset:** `cloud_health_auditing`

```xql
dataset = cloud_health_auditing
| filter capability = "ADS"
      and classification != "Informational"
      and account = "account-id"
```
