# cwp_packages_raw

## Overview

Contains raw package data collected from workloads via Cloud Workload Protection (CWP) scans, including OS packages, package paths, and their relationship to scanned assets.

**Use when you need to:**
- Inventory software packages across cloud workloads
- Identify where specific packages are installed
- Join package data with asset metadata for enriched reporting

---

## Queries

### List packages with enriched asset metadata

Joins package records with `asset_inventory` to surface asset names alongside package details.

```xql
dataset = cwp_packages_raw
| fields related_asset_id, name, os_package, full_pkg_path
| join (
    dataset = asset_inventory
    | filter xdm.asset.id != null
) as pkgs_assts pkgs_assts.xdm.asset.id = related_asset_id
| fields name,
         xdm.asset.name,
         related_asset_id,
         xdm.asset.id,
         full_pkg_path
```
