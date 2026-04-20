# asset_inventory

## Overview

Provides a normalized, structured inventory of all digital assets across your environment, including enterprise, multi-cloud, code, external surfaces, and AI assets.

Contains detailed metadata for each asset (type, cloud provider, region, security configurations) and maps relationships between assets.

**Use when you need to:**
- Gain comprehensive visibility into your cloud footprint
- Identify specific resources across providers
- Map complex cloud and AI dependencies to understand your security posture

---

## Queries

### Get all Kubernetes clusters in AWS

```xql
dataset = asset_inventory
| filter (xdm.asset.provider = "AWS")
      and (xdm.asset.type.class = "Compute")
      and (xdm.asset.type.category = "Kubernetes Cluster")
```

---

### Find VMs running images older than 30 days

Identifies VM instances and their associated images, calculating the true age of each image and filtering for those created more than 30 days ago.

```xql
// Step 1: Find VM Images, extract the creation date, and calculate true age
dataset = asset_inventory
| filter xdm.asset.type.category = "VM Image"
// Extract the string value and save the asset name
| alter image_created_at_str = json_extract_scalar(xdm.asset.normalized_fields, "$['xdm.vm_image.created_at']"),
        image_asset_name = xdm.asset.name,
        image_asset_id = xdm.asset.id
// Parse the string into a timestamp and calculate the exact age in days
| alter true_image_age_days = timestamp_diff(current_time(), parse_timestamp("%Y-%m-%dT%H:%M:%S.000Z", image_created_at_str), "DAY")
// Filter for images actually created more than 30 days ago
| filter true_image_age_days > 30

// Step 2: Join with VM Instances that are related to these images
| join (
    dataset = asset_inventory
    | filter xdm.asset.type.category = "VM Instance"
    | alter relation = json_extract_array(xdm.asset.normalized_fields, "$['xdm.asset.relations']")
    | arrayexpand relation
    | alter relation_asset_id = json_extract_scalar(relation, "$['xdm.asset.relation.asset_id']")
) as vm_asset vm_asset.relation_asset_id = image_asset_id

// Step 3: Display the corresponding VM Instance and the true image age details
| fields xdm.asset.name as VM_Instance_Name,
         image_asset_name as Image_Name,
         image_created_at_str as Created_At,
         true_image_age_days,
         xdm.asset.provider as Cloud_Provider
```
