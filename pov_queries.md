# POV Queries

Useful queries during onboarding, testing, and validation of capabilities.

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


# Knowledge Base XQL Queries

Full conversion of the Knowledge Base spreadsheet, matching the pov_queries.md schema.

---
### Cloud Instance troubleshooting
Surfaces cloud instances with operational errors to assist in troubleshooting connectivity or configuration issues.

**Dataset:** `cloud_health_auditing`

```xql
config case_sensitive = false | dataset = cloud_health_auditing | filter classification = "Error"
```

---

### Cloudtrail Logs:
**Dataset:** `cloud_health_auditing`

```xql
dataset = cloud_health_auditing | limit 100
```

---

### Clusters and VMs for scanner info
**Dataset:** `asset_inventory`

```xql
dataset in (asset_inventory) | FILTER  ( xdm.asset.provider = "AWS"  ) and  ( xdm.asset.type.class = "Compute"  ) and  ( xdm.asset.type.category = "Kubernetes Cluster"  ) and (xdm.asset.realm  = "866220957162" )
```

---

### Detecting VPC's that do not have VPC endpoints enabled
Contributor: Erick Moore

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory 
| filter xdm.asset.type.id = "EC2_VPC_ENDPOINT" 
| alter vpc_using_endpoint = xdm.asset.normalized_fields -> ["xdm.cloud.vpc_id"]
| fields vpc_using_endpoint
| join (dataset = asset_inventory 
    | filter xdm.asset.type.id = "EC2_VPC"
    | fields xdm.asset.strong_id as vpcId, xdm.asset.name as Name
) as vpc vpc.vpcId != vpc_using_endpoint 
| fields Name
```

---

### llatorre_Inventory_VMs by CSP
Contributor: Luis Latorre

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory
| filter xdm.asset.type.category = "VM Instance"
| fields xdm.asset.type.category, xdm.asset.provider, xdm.asset.last_observed 
| comp count(xdm.asset.type.category) as VM_Instances by xdm.asset.provider 
```

---

### identify all the Cloud VMs that don't have the XDR agent installed
Contributor: Erick Moore

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory
| filter xdm.asset.type.category = "VM Instance"
| alter scanType = xdm.asset.raw_fields -> CWP["analysis-info_csa_vulnerability_analyzer"].scanner_type
| alter agentType =  xdm.asset.normalized_fields -> ["xdm.agent.type"]
| alter Protected = if (agentType = null , "Not Protected", agentType in ("CLOUD", "REGULAR"), "Protected") 
| filter xdm.asset.cloud.region != null
| fields xdm.asset.name as Name, xdm.asset.strong_id as ResourceID, xdm.asset.provider as Cloud, xdm.asset.cloud.region as Region, xdm.asset.realm as Cloud_Account, Protected, agentType
| comp count (Name ) as VMs by protected
| view graph type = pie xaxis = Protected yaxis = VMs 
```

---

### Cortex Cloud Platform Activities
Contributor: Luis Latorre

**Dataset:** `management_auditing`

```xql
dataset = management_auditing 
| fields subtype
| comp count(subtype) by subtype
| view graph type = column subtype = grouped xaxis = subtype yaxis = count_1 
```

---

### Cortex Cloud health Check
Contributor: Luis Latorre

**Dataset:** `cloud_health_auditing`

```xql
dataset = cloud_health_auditing 
|filter classification !=  "Informational" 
|fields classification
|comp count (classification ) by classification
| view graph type = column subtype = grouped show_callouts = `true` show_callouts_names = `true` xaxis = classification yaxis = count_1 seriestitle("count_1","Count") 
```

---

### License calculator
Contributor: Erick Moore

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory 
| fields xdm.asset.type.category as Category, xdm.asset.type.id as Type
| filter Category  in ("Storage Bucket", "Database", "VM Instance", "Serverless Function", "Container Image")
| comp count() as Total by Category
| alter vm_total = if(Category = "VM Instance", Total)
| alter image_total = if(Category = "Container Image", Total)
| alter image_included = multiply(vm_total, 10)
| alter license = if(
    Category = "Storage Bucket", round(divide(Total , 10)),
    Category = "Database", round(divide(Total , 2)),
    Category = "VM Instance", Total,
    Category = "Serverless Function", round(divide(Total , 25)),
    Category = "Container Image", if(subtract(image_included, image_total) >0, divide(Total , 10), 0)
)
| fields Category , Total , license | sort asc Category 
```

---

### List of assets based for one issue
Contributor: Luis Latorre & Harri Ruuttila

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory
| fields xdm.asset.id,xdm.asset.name
| join (dataset = issues 
    | filter xdm.issue.name = "AWS VPC gateway endpoint policy is overly permissive"
    | arrayexpand xdm.issue.asset_ids 
    | fields xdm.issue.asset_ids as issueassetids, xdm.issue.name as issuename
) 
as issue xdm.asset.id = issue.issueassetids
| fields xdm.asset.name, issuename
| comp count (issuename) as Azure_Storage by issuename 
```

---

### # of Cloud Network Analyzer Issues
Contributor: Luis Latorre

**Dataset:** `issues`

```xql
dataset = issues 
| fields xdm.issue.name, xdm.issue.detection.method
| filter xdm.issue.detection.method = "CLOUD_NETWORK_ANALYZER"
| comp count() as Assets by xdm.issue.name
| sort desc Assets 
```

---

### llatorre - Number of Internet-exposed Issues - Graph
Contributor: Luis Latorre

**Dataset:** `issues`

```xql
dataset = issues 
| fields xdm.issue.name, xdm.issue.detection.method, xdm.issue.status.progress
| filter xdm.issue.detection.method = "CLOUD_NETWORK_ANALYZER" or xdm.issue.name = "Azure Storage Account default network access is set to 'Allow'"
| filter xdm.issue.status.progress != "Resolved"
| comp count() as Assets by xdm.issue.name
| sort desc Assets 
| view graph type = column subtype = stacked layout = horizontal xaxis = xdm.issue.name yaxis = xdm.issue.name,Assets
```

---

### llatorre - List of Assets affected by a Internet-exposed Issues
Contributor: Luis Latorre

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory
| fields xdm.asset.id,xdm.asset.name
| join (dataset = issues 
    | filter xdm.issue.detection.method = "CLOUD_NETWORK_ANALYZER" or xdm.issue.name = "Azure Storage Account default network access is set to 'Allow'"
    | filter xdm.issue.status.progress != "Resolved"
    | arrayexpand xdm.issue.asset_ids 
    | fields xdm.issue.asset_ids as issueassetids, xdm.issue.name as issuename, xdm.issue.detection.method as method
) 
as issue xdm.asset.id = issue.issueassetids
| fields _insert_time as Identified, xdm.asset.name as asset, issuename, _time as Last_Seen
| sort desc Identified 
```

---

### Inventory of all Azure Assets by Onboarded Azure Subscriptions
Contributor: Luis Latorre

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory 
| filter xdm.asset.provider = "AZURE"
| filter xdm.asset.realm not contains "mg-"
| comp count(xdm.asset.realm) as CloudAccount by xdm.asset.realm
```

---

### llatorre - Total Open Internet-exposed Issues
Contributor: Luis Latorre

**Dataset:** `issues`

```xql
dataset = issues 
| filter xdm.issue.domain = "POSTURE"
| filter xdm.issue.detection.method = "CLOUD_NETWORK_ANALYZER" or xdm.issue.name = "Azure Storage Account default network access is set to 'Allow'"
| filter xdm.issue.status.progress != "RESOLVED" // Only active issues
| comp count() as Issues by xdm.issue.domain 
| view graph type = single subtype = standard yaxis = Issues scale_threshold("#37f032") font = "Arial" headerfontsize = 40 
```

---

### Agentless logs
Contributor: Nik Perez

**Dataset:** `cloud_health_auditing`

```xql
dataset = cloud_health_auditing
| filter capability = "ADS"
    and account = "289997607820"
    and connector = "e3729aecfd5446a69eb6d91e744cb311"
| fields _time, account, connector, region, resource_id, classification, message, error
| sort desc _time
```

---

### llatorre - list of VMs that have self-managed Databases
Contributor: Luis Latorre

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory
| filter xdm.asset.provider = "AWS"
| filter xdm.asset.type.category = "VM Instance"
| join (dataset = asset_inventory 
    | filter xdm.asset.type.category = "Database"
    | alter vm = xdm.asset.raw_fields -> DSPM.raw_data.vm_uai_id
    | fields vm, xdm.asset.type.name as dbtype, xdm.asset.name as db_name
) as vmid xdm.asset.id = vmid.vm 
| fields xdm.asset.name as asset, vm, xdm.asset.type.category, dbtype, db_name 
```

---

### Cases by Status Duration
Contributor: Brad Green

**Dataset:** `cases`

```xql
dataset = cases
| alter duration = divide(to_number(xdm.case.custom_fields -> timerslamendonca.totalDuration), 3600)
| comp max(duration) as maximum, min(duration) as minimum, avg(duration) as average by xdm.case.status_progress
| view graph type = column subtype = grouped xaxis = xdm.case.status_progress yaxis = maximum,minimum,average 
```

---

### number of CVEs by severity
Contributor: Miguel Hernes

**Dataset:** `findings`

```xql
dataset = findings
| filter xdm.finding.category = "VULNERABILITY"
| alter severity = to_string(xdm.finding.normalized_fields -> ["xdm.vulnerability.severity"])
| join (
   dataset = asset_inventory
   | filter xdm.kubernetes.cluster.name != null and xdm.kubernetes.cluster.name != ""     
   | filter xdm.asset.type.category in ("VM Instance")
   | fields xdm.kubernetes.cluster.name, xdm.asset.id, xdm.asset.realm, xdm.asset.provider, xdm.asset.name, xdm.asset.type.name
) as a a.xdm.asset.id = xdm.finding.asset_id
| comp count() as total_cves by xdm.kubernetes.cluster.name, xdm.asset.name, xdm.asset.realm, xdm.asset.type.name
```

---

### Identify Vulns by namespaces
Contributor: Luis Latorre

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory 
| filter xdm.asset.type.category = "Kubernetes Resource"
| fields xdm.kubernetes.resource.namespace as namespace, xdm.asset.name as assetn, xdm.asset.type.name as assettype, xdm.asset.realm as cspaccount, xdm.asset.id as assetid
| join (
    dataset = issues 
    | filter xdm.issue.owner = "VULNERABILITY_MANAGEMENT"
    | arrayexpand xdm.issue.asset_ids
    | fields xdm.issue.owner as owner, xdm.issue.asset_ids as iassetid, xdm.issue.name as cvedet, xdm.vulnerability.cve_id as cve
) as issues2 assetid = issues2.iassetid 
| fields namespace, assetn, assettype, cspaccount, cve, cvedet 
```

---

### Endpoint: Clusters where the XDR agent is deployed
Contributor: Luis Latorre

**Dataset:** `endpoints`

```xql
dataset = endpoints 
| filter installation_type = ENUM.TYPE_KUBERNETES 
| filter endpoint_status = ENUM.CONNECTED 
| comp count(installation_type) as K8s_cklusters by cluster_name 
```

---

### Identify the AD group by AD Group ID
Contributor: Luis Latorre

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory 
| filter xdm.asset.provider = "Azure"
| filter xdm.asset.type.name = "Azure Active Directory Group"
| alter gpid = xdm.asset.raw_fields -> ["Platform Discovery"].groupId
| filter gpid = "<AD Group ID>"
```

---

### Monitor logs for the ADS Capability ()
Contributor: Luis Latorre

**Dataset:** `cloud_health_auditing`

```xql
dataset = cloud_health_auditing
| filter connector contains "AZURE"
| filter capability = "ADS"
```

---

### Attack Surface Management Identified Services:
Contributor: Luis Latorre

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory
| filter xdm.asset.type.class = "External Surface"
| filter xdm.asset.type.category = "Service"
| fields xdm.asset.strong_id, xdm.asset.provider, xdm.asset.name
```

---

### Identify VM scanned by ADS with Secret Issues:
Contributor: Luis Latorre

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory
| filter xdm.asset.type.category = "VM Instance"
| alter agentlessx = json_extract_scalar(xdm.asset.raw_fields, "$.CWP.analysis-info_agentless_malware_analyzer.scan_analysis_result") 
| filter agentlessx = "success"
| join (dataset = issues 
    | filter xdm.issue.detection.method contains "Secret"
    | filter xdm.issue.category != "DATA"
    | arrayexpand xdm.issue.asset_ids 
    | fields xdm.issue.asset_ids as issueassetids, xdm.issue.name as issuename
) 
as issue xdm.asset.id = issue.issueassetids
| fields xdm.asset.name, issuename
```

---

### FM - Use Case #1
Contributor: Luis Latorre

**Dataset:** `asset_inventory`

```xql
// By llatorre
dataset = asset_inventory 
| filter xdm.asset.provider = "aws" 
| filter xdm.asset.type.id = "EC2_SECURITY_GROUP" 
| filter xdm.cloud.vpc_id not in ("vpc-0c567ff9f256df8cf")
| alter gn = json_extract_scalar(xdm.asset.raw_fields, "$.Platform Discovery.groupName") 
| filter gn = "default"
| alter userIdGroupPairsroupIdy = true
```

---

### Pie of number of findings by Category
Contributor: Luis Latorre

**Dataset:** `findings`

```xql
dataset = findings 
| comp count(xdm.finding.asset_id ) as findings by xdm.finding.category
| view graph type = pie xaxis = xdm.finding.category yaxis = findings 
```

---

### XQL Query: Network Traffic from XDR Agent
Contributor: Luis Latorre 

**Dataset:** `xdr_data`

```xql
config timeframe = 1d 
| dataset = xdr_data 
| filter event_type = ENUM.NETWORK 
| fields 
    _time, 
    agent_hostname, 
    actor_process_image_name, 
    action_local_ip, 
    action_remote_ip, 
    action_remote_port 
| sort desc _time
| limit 100 
```

---

### Identify issues related to permissions across all CSPs
Contributor: Luis Latorre

**Dataset:** `cloud_health_auditing`

```xql
config case_sensitive = false 
| dataset = cloud_health_auditing 
| filter capability = "Permissions"
```

---

### Funnel by Vuln Severity
Contributor: Luis Latorre

**Dataset:** `issues`

```xql
dataset = issues 
| filter xdm.issue.category = "VULNERABILITY"
| fields xdm.issue.name, xdm.issue.category, xdm.issue.severity 
| comp count (xdm.issue.category) as severity by xdm.issue.severity
| view graph type = funnel xaxis = xdm.issue.severity yaxis = severity 
```

---

### is there a a package inventory or search capability? curl < 8.0.1
Contributor: Erick Moore

**Dataset:** `cwp_packages_raw`

```xql
dataset = cwp_packages_raw
| fields name, version , path, related_asset_type ,related_asset_id 
| filter name = "curl"
| alter semver = split(version,".") 
| filter (major < 8)
```

---

### List all account names, ids (realm) and tags for each account
Contributor: Phelipe Avila + Andres Rodriguez

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory | filter xdm.asset.type.category = "Account"
| fields account_name,xdm.asset.realm, tags
| filter account_name != null
| dedup xdm.asset.realm
```

---

### widget to display disconnected endpoints on a world map
Contributor: Oleg Fiksel

**Dataset:** `endpoints`

```xql
dataset = endpoints
| filter timestamp_diff(current_time(), last_seen, "HOUR") > 30
| iploc last_origin_ip loc_country 
| comp count(endpoint_name) as counter by loc_country
| view graph type = map header = "Disconnected agents since 30 hours" xaxis = loc_country yaxis = counter 
```

---

### Pie of number of Connected endpoints by Type
Contributor: Luis Latorre

**Dataset:** `endpoints`

```xql
dataset = endpoints 
| filter endpoint_status = ENUM.CONNECTED 
| fields endpoint_name, endpoint_type 
| comp count (endpoint_name ) as Endpoints by endpoint_type 
| view graph type = pie xaxis = endpoint_type yaxis = Endpoints 
```

---

### Pie of number of issues by Asset type
Contributor: Phelipe Avila

**Dataset:** `issues`

```xql
dataset = issues
| arrayexpand xdm.issue.asset_ids
| join type = inner (dataset = asset_inventory) as asset_data asset_data.xdm.asset.id = xdm.issue.asset_ids
| comp count(xdm.issue.id) as Issues by xdm.asset.type.category
| view graph type = pie xaxis = xdm.asset.type.category yaxis = Issues 
```

---

### Total issues by Category
Contributor: Luis Latorre

**Dataset:** `issues`

```xql
dataset = issues 
| filter xdm.issue.status.progress = ENUM.NEW 
| fields xdm.issue.name, xdm.issue.category, xdm.issue.severity 
| comp count (xdm.issue.name) as total by xdm.issue.category
```

---

### Table showing data classification issues on storage by asset name
Contributor: Luis Latorre

**Dataset:** `dspm_asset_file_inventory`

```xql
dataset = dspm_asset_file_inventory 
| join (  dataset = asset_inventory 
| filter xdm.asset.type.category = "Storage Bucket"
) as asset asset.assetid = asset_id 
| fields name, csp, category, account, dp, file_name, file_folder
```

---

### Identify when a Broker VM was disconnected
Contributor: Luis Latorre + Glean AI

**Dataset:** `management_auditing`

```xql
dataset = management_auditing 
| filter subtype = "Disconnect" 
| fields _time, host_name, device_id, description 
| sort desc _time
```

---

### Monitor SBAC Activity
Contributor: Luis Latorre

**Dataset:** `management_auditing`

```xql
dataset = management_auditing 
| filter subtype contains "Scope Edit" or subtype contains "Scoped Access"
```

---

### Detect new Azure subscription created
Contributor: Gabriel Tello

**Dataset:** `cloud_audit_logs`

```xql
dataset = cloud_audit_logs
| filter cloud_provider = ENUM.Azure and operation_name contains "Register subscription"
| fields raw_log, operation_name, _time
```

---

### Audit logs: Identify an event on aws by eventname
Identify when an AWS instance is launched via RunInstances.

**Dataset:** `cloud_audit_logs`

```xql
dataset = cloud_audit_logs 
| filter resource_type_orig = "ec2.amazonaws.com"
| alter eventnamev = raw_log -> ["eventName"]
| filter eventnamev = "RunInstances"
| fields region, caller_ip, eventnamev, raw_log 
```

---

### llatorre - Broker VM Monitor - only fails (Count)
Contributor: Luis Latorre

**Dataset:** `management_auditing`

```xql
dataset = management_auditing 
| filter management_auditing_result != ENUM.MANAGEMENT_AUDIT_SUCCESS 
| comp count() as TOTAL by subtype
```

---

### XDR Agents: Total number of connected Agents by Version
Contributor: Luis Latorre

**Dataset:** `endpoints`

```xql
dataset = endpoints 
| filter endpoint_status = ENUM.CONNECTED 
| comp count (agent_version ) as Endpoints by agent_version 
| sort desc Endpoints 
```

---

### llatorre-cloud-health-monitoring-table
Contributor: Luis Latorre

**Dataset:** `cloud_health_auditing`

```xql
dataset = cloud_health_auditing 
|filter classification not in  ("Informational" , "Success", "Scanned")
|comp count ( classification) as Count by classification, capability
| sort desc Count
```

---

### Critical severity vulnerability issues open - 1 Month
Contributor: Brett Berard

**Dataset:** `issues`

```xql
dataset = issues
| filter xdm.issue.category = "VULNERABILITY"
| filter xdm.issue.severity = "Critical"
| filter xdm.issue.status.progress != "Resolved"
| bin _insert_time span = 1MO
| comp count() as total_open_issues by _insert_time
```

---

### AWS Access logging not enabled on S3 buckets
Contributor: Shelby Grumer

**Dataset:** `findings`

```xql
dataset=findings  
| filter xdm.finding.name contains "AWS Access logging not enabled on S3 buckets"
| comp count() as issues by xdm.finding.name
| view graph type = pie xaxis = xdm.finding.name yaxis = issues
```

---

### Sgrumer - Public IP 
Contributor: Shelby Grumer

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory 
| filter xdm.asset.type.id = "EC2_NETWORK_INTERFACE"
| alter ip_address = json_extract_scalar(xdm.asset.raw_fields, "$.Platform Discovery.association.publicIp") 
| filter ip_address != null
| fields ip_address as Public_IP_Address, xdm.asset.name as Name
```

---

### Sgrumer - AWS GuardDuty
Contributor: Shelby Grumer

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory
| filter xdm.asset.type.id contains "Guardduty"
| fields xdm.asset.realm as Account_ID, xdm.asset.raw_fields as Full_JSON
```

---

### Sgrumer - Host Inventory
Contributor: Shelby Grumer

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory
| filter xdm.host.os_distribution != null
| comp count(xdm.asset.id) as Total by xdm.host.os_distribution
| view graph type = pie xaxis = xdm.host.os_distribution yaxis = Total 
```

---

### Sgrumer - Open Issues by Provider & Detection Method
Contributor: Shelby Grumer

**Dataset:** `issues`

```xql
dataset = issues 
| filter xdm.issue.status.progress != "RESOLVED"
| join type = inner (dataset = issue_to_asset) as issue_assets xdm.issue.id = issue_assets.xdm.issue.id 
| join type = left (dataset = asset_inventory) as asset_details issue_assets.xdm.asset.id = asset_details.xdm.asset.id 
| comp count(xdm.issue.id) as issues by provider 
```

---

### Listo fo AppSec Secret filename and line
Contributor: Luis Latorre

**Dataset:** `issues`

```xql
dataset = issues 
| filter xdm.issue.detection.method = "CAS_SECRET_SCANNER"
| fields xdm.file.path, xdm.file.filename, xdm.issue.description 
```

---

### Sgrumer - Package Search Widget
Contributor: Shelby Grumer

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory
| filter xdm.asset.type.name contains "Package"
| fields xdm.asset.name as name, version
```

---

### report to identify issues + asset name + realm + provider
Contributor: Luis Latorre

**Dataset:** `issues`

```xql
dataset = issues
| arrayexpand xdm.issue.asset_ids 
| join (dataset = asset_inventory) as asset_data asset_data.assetid = xdm.issue.asset_ids 
| fields xdm.issue.name, affectedasset, provider, cloudaccountid
```

---


