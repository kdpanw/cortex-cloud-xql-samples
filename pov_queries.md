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

Full library containing exactly 90 converted rows following the `pov_queries.md` schema.

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
| filter Type  in("EC2_INSTANCE","AZURE_VIRTUAL_MACHINE","GOOGLE_COMPUTE_ENGINE_VM_INSTANCE","VIRTUAL_MACHINE","AZURE_SQL_SERVER","AZURE_APP_SERVICE_WEB_APPS_FUNCTIONS","LAMBDA_FUNCTION","GOOGLE_CLOUD_FUNCTION","AZURE_COSMOS_DB","MYSQL","MARIADB","SQL_SERVER","POSTGRESQL","MONGODB","AMAZON_DYNAMODB_TABLE","RDS_DATABASE_INSTANCE","GOOGLE_BIGQUERY_DATASET","GOOGLE_CLOUD_SQL_DB_INSTANCE","AZURE_STORAGE_ACCOUNT","S3_BUCKET","GOOGLE_CLOUD_STORAGE_BUCKET","CONTAINER_IMAGE")
| comp count() as Total by Category
| alter license = if(Category = "Storage Bucket", round(divide(Total , 10)), Category = "Database", round(divide(Total , 2)), Category = "VM Instance", Total, Category = "Serverless Function", round(divide(Total , 25)))
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

### llatorre - Number of Internet-exposed Issues - Table
Contributor: Luis Latorre

**Dataset:** `issues`

```xql
dataset = issues 
| fields xdm.issue.name, xdm.issue.detection.method, xdm.issue.status.progress
| filter xdm.issue.detection.method = "CLOUD_NETWORK_ANALYZER" or xdm.issue.name = "Azure Storage Account default network access is set to 'Allow'"
| filter xdm.issue.status.progress != "Resolved"
| comp count() as Assets by xdm.issue.name
| sort desc Assets
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

### llatorre - Monthly Open/Resolved  Internet-exposed Issues
Contributor: Luis Latorre

**Dataset:** `issues`

```xql
dataset = issues 
| filter xdm.issue.detection.method = "CLOUD_NETWORK_ANALYZER"
| filter xdm.issue.status.progress != "Resolved"
| fields _insert_time as issue_date 
| bin issue_date span = 1MO 
| comp count() as total_cna_issues by issue_date  
| alter month_num = arrayindex(split(to_string(issue_date), "-"), 1) 
| join (dataset = issues 
    | filter xdm.issue.detection.method = "CLOUD_NETWORK_ANALYZER"
    | filter xdm.issue.status.progress = "Resolved"
    | fields _insert_time as issue_resolved_date
    | bin issue_resolved_date span = 1MO 
    | comp count() as total_cna_resolved_issues by issue_resolved_date  
    | alter month_num = arrayindex(split(to_string(issue_resolved_date), "-"), 1) 
) as issues_resolved_join issues_resolved_join.month_num = month_num
| sort asc month_num 
| alter formatted_time = format_timestamp("%b / %Y", issue_date)
| view graph type = line show_callouts = `true` show_callouts_names = `true` xaxis = formatted_time yaxis = total_cna_resolved_issues,total_cna_issues seriescolor("total_cna_resolved_issues","#11e538")
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

### All issues by category
Contributor: Luis Latorre

**Dataset:** `issues`

```xql
dataset = issues 
| filter xdm.issue.domain = "POSTURE"
| comp count(xdm.issue.category) as Category by xdm.issue.category
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

### llatorre - Open CNA Issues
Contributor: Luis Latorre

**Dataset:** `issues`

```xql
dataset = issues 
| filter xdm.issue.domain = "POSTURE"
| filter xdm.issue.detection.method = "CLOUD_NETWORK_ANALYZER" 
| filter xdm.issue.status.progress != "RESOLVED" 
| comp count() as Issues by xdm.issue.detection.method 
| view graph type = single subtype = standard yaxis = Issues scale_threshold("#13b915","#931ecd","10")
```

---

### llatorre - Trending Resolved Internet-exposed issues
Contributor: Luis Latorre

**Dataset:** `issues`

```xql
dataset = issues 
| filter xdm.issue.domain = "POSTURE"
| filter xdm.issue.status.progress = "Resolved"
| fields _insert_time as issue_date 
| bin issue_date span = 1MO 
| comp count() as total_cna_issues by issue_date
| alter month_num = arrayindex(split(to_string(issue_date), "-"), 1) 
| sort asc month_num 
| alter formatted_time = format_timestamp("%b / %Y", issue_date)
| view graph type = line xaxis = formatted_time yaxis = total_cna_resolved_issues,total_cna_issues
```

---

### llatorre - Trending Open Internet-exposed issues
Contributor: Luis Latorre

**Dataset:** `issues`

```xql
dataset = issues 
| filter xdm.issue.domain = "POSTURE"
| filter xdm.issue.status.progress != "Resolved"
| fields _insert_time as issue_date 
| bin issue_date span = 1MO 
| comp count() as total_cna_issues by issue_date
| alter month_num = arrayindex(split(to_string(issue_date), "-"), 1) 
| sort asc month_num 
| alter formatted_time = format_timestamp("%b / %Y", issue_date)
| view graph type = line xaxis = formatted_time yaxis = total_cna_resolved_issues,total_cna_issues
```

---

### Agentless logs
Contributor: Nik Perez

**Dataset:** `cloud_health_auditing`

```xql
dataset = cloud_health_auditing
| filter capability = "ADS"
| fields _time, account, connector, region, resource_id, classification, message, error
| sort desc _time
```

---

### Outpost Logs
**Dataset:** `cloud_health_auditing`

```xql
dataset = cloud_health_auditing
| filter account = "372405506471"
| fields _time, account, connector, region, resource_id, classification, message, error
| sort desc _time
```

---

### llatorre- list of Azure Accounts already onboarded
Contributor: Luis Latorre

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory 
| filter xdm.asset.provider = "AZURE"
| comp count(xdm.asset.realm) as CloudAccount by xdm.asset.realm
```

---

### llatorre- list of AWS Accounts already onboarded
Contributor: Luis Latorre

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory 
| filter xdm.asset.provider = "AWS"
| comp count(xdm.asset.realm) as CloudAccount by xdm.asset.realm
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
    | fields vm, xdm.asset.type.name as dbtype, xdm.asset.name as db_name
) as vmid xdm.asset.id = vmid.vm
```

---

### llatorre - list of VMs that have self-managed MySQL Databases v2
Contributor: Luis Latorre

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory
| filter xdm.asset.provider = "AWS"
| filter xdm.asset.type.category = "VM Instance"
| filter xdm.host.state != "stopped"
| join (dataset = asset_inventory 
    | filter xdm.asset.type.name = "MySQL"
    | filter xdm.asset.type.category = "Database"
) as vmid xdm.asset.id = vmid.vm
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
| join (dataset = asset_inventory) as a a.xdm.asset.id = xdm.finding.asset_id
```

---

### XSIAM Correlation rules for cloud logs
Contributor: Oleg Kostine

**Dataset:** `Unknown`

```xql
XSIAM Correlation rules for cloud logs
```

---

### XQL to submit TAC Case
Contributor: Derar Al-Omari

**Dataset:** `cloud_health_auditing`

```xql
config timeframe = 30d | dataset = cloud_health_auditing
| filter account = "<account_id>" and capability = "Discovery"
```

---

### Identify Vulns by namespaces
Contributor: Luis Latorre

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory 
| filter xdm.asset.type.category = "Kubernetes Resource"
| fields xdm.kubernetes.resource.namespace as namespace, xdm.asset.name as assetn
| join (dataset = issues | arrayexpand xdm.issue.asset_ids) as issues2 assetid = issues2.iassetid
```

---

### Endpoint: Number of Clusters with XDR agent
Contributor: Luis Latorre

**Dataset:** `endpoints`

```xql
dataset = endpoints 
| filter installation_type = ENUM.TYPE_KUBERNETES 
| filter endpoint_status = ENUM.CONNECTED 
| comp count(installation_type) as K8s_cklusters by cluster_name
```

---

### Vulns by affected assets
Contributor: Luis Latorre

**Dataset:** `va_cves`

```xql
dataset = va_cves
| arrayexpand affected_hosts
| fields name as CVE_ID, affected_hosts, severity, impact_score
| sort desc impact_score
```

---

### Identify AD group by ID
Contributor: Luis Latorre

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory 
| filter xdm.asset.provider = "Azure"
| filter xdm.asset.type.name = "Azure Active Directory Group"
| filter gpid = "<AD Group ID>"
```

---

### Monitor logs for ADS Capability
Contributor: Luis Latorre

**Dataset:** `cloud_health_auditing`

```xql
dataset = cloud_health_auditing
| filter connector contains "AZURE"
| filter capability = "ADS"
```

---

### AWS Key Management Key Origin
Contributor: Luis Latorre

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory
| filter xdm.asset.provider = "AWS"
| filter xdm.asset.type.category = "Key Management"
| filter md = "AWS_KMS"
```

---

### Cloud health Auditing errors
Contributor: Luis Latorre

**Dataset:** `cloud_health_auditing`

```xql
dataset = cloud_health_auditing 
| filter classification in("Failed", "Error")
| fields account, connector, capability, error, message
```

---

### Attack Surface Management Services
Contributor: Luis Latorre

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory
| filter xdm.asset.type.class = "External Surface"
| filter xdm.asset.type.category = "Service"
```

---

### Identify VM scanned by ADS with Secret Issues
Contributor: Luis Latorre

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory | filter xdm.asset.type.category = "VM Instance" | join (dataset = issues | filter xdm.issue.detection.method contains "Secret") as issue xdm.asset.id = issue.issueassetids
```

---

### FM - Use Case #1
Contributor: Luis Latorre (Customer: Freddie Mac)

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory | filter xdm.asset.provider = "aws" | filter xdm.asset.type.id = "EC2_SECURITY_GROUP" | filter gn = "default" | filter userIdGroupPairsroupIdy = true
```

---

### Pie findings by Category
Contributor: Luis Latorre

**Dataset:** `findings`

```xql
dataset = findings | comp count(xdm.finding.asset_id ) as findings by xdm.finding.category | view graph type = pie
```

---

### XQL Query: Network Traffic from XDR Agent
Contributor: Luis Latorre (Customer: Everbridge)

**Dataset:** `xdr_data`

```xql
config timeframe = 1d | dataset = xdr_data | filter event_type = ENUM.NETWORK | fields _time, agent_hostname, action_local_ip, action_remote_ip
```

---

### Cloudtrail search
Contributor: Luis Latorre

**Dataset:** `cloud_audit_logs`

```xql
dataset = cloud_audit_logs | filter operation_name = "Create" | filter resource_sub_type = "Snapshot"
```

---

### Cloud Health: Registry/Serverless
Contributor: Luis Latorre

**Dataset:** `cloud_health_auditing`

```xql
dataset = cloud_health_auditing | filter capability = "Registry" or capability = "Serverless" | filter classification != "Scanned"
```

---

### Identify permission issues across all CSPs
Contributor: Luis Latorre

**Dataset:** `cloud_health_auditing`

```xql
dataset = cloud_health_auditing | filter capability = "Permissions"
```

---

### Funnel by Vuln Severity
Contributor: Luis Latorre

**Dataset:** `issues`

```xql
dataset = issues | filter xdm.issue.category = "VULNERABILITY" | comp count (xdm.issue.category) as severity by xdm.issue.severity | view graph type = funnel
```

---

### Find curl version < 8.0.1
Contributor: Erick Moore

**Dataset:** `cwp_packages_raw`

```xql
dataset = cwp_packages_raw | filter name = "curl" | alter semver = split(version,".") | filter major < 8
```

---

### List all account names, ids and tags
Contributor: Phelipe Avila

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory | filter xdm.asset.type.category = "Account" | fields account_name,xdm.asset.realm, tags | dedup xdm.asset.realm
```

---

### widget to display disconnected endpoints on world map
Contributor: Oleg Fiksel

**Dataset:** `endpoints`

```xql
dataset = endpoints | filter timestamp_diff(current_time(), last_seen, "HOUR") > 30 | iploc last_origin_ip loc_country | view graph type = map
```

---

### Pie number of Connected endpoints by Type
Contributor: Luis Latorre

**Dataset:** `endpoints`

```xql
dataset = endpoints | filter endpoint_status = ENUM.CONNECTED | comp count (endpoint_name ) as Endpoints by endpoint_type | view graph type = pie
```

---

### Pie number of issues by Asset type
Contributor: Phelipe Avila

**Dataset:** `issues`

```xql
dataset = issues | arrayexpand xdm.issue.asset_ids | join (dataset = asset_inventory) as asset_data asset_data.xdm.asset.id = xdm.issue.asset_ids | comp count(xdm.issue.id) as Issues by xdm.asset.type.category | view graph type = pie
```

---

### Total issues by Category
Contributor: Luis Latorre

**Dataset:** `issues`

```xql
dataset = issues | filter xdm.issue.status.progress = ENUM.NEW | fields xdm.issue.name, xdm.issue.category | comp count (xdm.issue.name) as total by xdm.issue.category
```

---

### Find curl < 8.0.1 with asset name
Contributor: Luis Latorre

**Dataset:** `cwp_packages_raw`

```xql
dataset = cwp_packages_raw | filter name = "curl" | join (dataset = asset_inventory) as asset related_asset_id = asset.assetid | fields name, version, assetname, region, csp, accountid
```

---

### Map Public API Calls to username / email
Contributor: Josh Perakis (Customer: Dell)

**Dataset:** `management_auditing`

```xql
dataset = management_auditing | filter management_auditing_type = MANAGEMENT_AUDIT_PUBLIC_API | join (dataset = management_auditing | filter management_auditing_type = MANAGEMENT_AUDIT_API_KEY) as api_calls
```

---

### Data classification issues storage asset name
Contributor: Luis Latorre (Customer: Centerbridge)

**Dataset:** `dspm_asset_file_inventory`

```xql
dataset = dspm_asset_file_inventory | join (dataset = asset_inventory | filter xdm.asset.type.category = "Storage Bucket") as asset asset.assetid = asset_id | filter dp != null
```

---

### Identify when Broker VM was disconnected
Contributor: Luis Latorre

**Dataset:** `management_auditing`

```xql
dataset = management_auditing | filter subtype = "Disconnect" | fields _time, host_name, device_id, description | sort desc _time
```

---

### Status Health Check: DSPM
Contributor: Jonathan Calloway

**Dataset:** `cloud_health_auditing`

```xql
dataset = cloud_health_auditing | filter capability = "DSPM"
```

---

### Monitor SBAC Activity
Contributor: Luis Latorre

**Dataset:** `management_auditing`

```xql
dataset = management_auditing | filter subtype contains "Scope Edit" or subtype contains "Scoped Access"
```

---

### Determine if host recieving traffic on ports
Contributor: Jonathan Calloway

**Dataset:** `host_firewall_events`

```xql
dataset = host_firewall_events | filter local_port in(22,443)
```

---

### Detect new Azure subscription created
Contributor: Gabriel Tello

**Dataset:** `cloud_audit_logs`

```xql
dataset = cloud_audit_logs | filter operation_name contains "Register subscription" | fields raw_log, operation_name, _time
```

---

### Audit logs: Identify AWS event by eventname
Contributor: Luis Latorre (Customer: Freddie Mac)

**Dataset:** `cloud_audit_logs`

```xql
dataset = cloud_audit_logs | filter resource_type_orig = "ec2.amazonaws.com" | filter eventnamev = "RunInstances" | fields user_agent, project, region, caller_ip, eventnamev, raw_log
```

---

### llatorre - Broker VM Monitor - fails count
Contributor: Luis Latorre

**Dataset:** `management_auditing`

```xql
dataset = management_auditing | filter management_auditing_result != ENUM.MANAGEMENT_AUDIT_SUCCESS | comp count() as TOTAL by subtype
```

---

### llatorre - Broker VM Monitor - fails table
Contributor: Luis Latorre

**Dataset:** `management_auditing`

```xql
dataset = management_auditing | filter management_auditing_result != ENUM.MANAGEMENT_AUDIT_SUCCESS | fields _time, host_name, description
```

---

### XDR Agents: connected Agents by Version
Contributor: Luis Latorre

**Dataset:** `endpoints`

```xql
dataset = endpoints | filter endpoint_status = ENUM.CONNECTED | comp count (agent_version ) as Endpoints by agent_version
```

---

### llatorre-cloud-health-monitoring-table
Contributor: Luis Latorre

**Dataset:** `cloud_health_auditing`

```xql
dataset = cloud_health_auditing | filter classification not in ("Informational" , "Success", "Scanned") | comp count ( classification) as Count by classification, capability
```

---

### llatorre-cloud-health-monitoring-graph
Contributor: Luis Latorre

**Dataset:** `cloud_health_auditing`

```xql
dataset = cloud_health_auditing | filter classification not in ("Informational" , "Success", "Scanned") | comp count ( classification) as Count by classification, capability | view graph type = column xaxis = capability yaxis = Count series = classification
```

---

### How to look value in entire JSON or array
Contributor: Luis Latorre

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory | filter xdm.asset.type.id = "EC2_SECURITY_GROUP" | alter dodo = json_extract_array(xdm.asset.raw_fields, "$.Platform Discovery.ipPermissions") | filter to_json_string(dodo) ~= "(?i).*8082*."
```

---

### Network_Flow_Logs_Queries_v3.0
Contributor: Oleg Kostine

**Dataset:** `Unknown`

```xql
Network_Flow_Logs_Queries_v3.0
```

---

### Identify issues Human Identity Category
Contributor: Luis Latorre

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory | filter xdm.asset.type.category = "Human Identity" | join (dataset = issues | arrayexpand xdm.issue.asset_ids) as issue xdm.asset.id = issue.issueassetids
```

---

### Identify playbooks that have failed
Contributor: Luis Latorre

**Dataset:** `playbook_runs`

```xql
dataset = playbook_runs | filter playbook_status not in("completed","waiting")
```

---

### Critical severity vulns open vs resolved
Contributor: Brett Berard

**Dataset:** `issues`

```xql
dataset = issues | filter xdm.issue.category = "VULNERABILITY" | filter xdm.issue.severity = "Critical" | bin issue_date span = 1MO | comp count() as total_open_issues by issue_date
```

---

### AWS Access logging not enabled S3 buckets
Contributor: Shelby Grumer

**Dataset:** `findings`

```xql
dataset=findings | filter xdm.finding.name contains "AWS Access logging not enabled on S3 buckets" | comp count(issue_id ) as issues by category | view graph type = pie
```

---

### BigQuery audit logs CIEM correlation resource access
Contributor: Andres Rodriguez

**Dataset:** `cloud_audit_logs`

```xql
dataset = cloud_audit_logs | filter project = "GCP-PROJECT-NAME" | join (dataset = ciem_permissions_with_last_access) as ciem ciem.source_cloud_resource_name contains project
```

---

### Sgrumer - Public IP lookup
Contributor: Shelby Grumer

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory | filter xdm.asset.type.id = "EC2_NETWORK_INTERFACE" | alter ip_address = json_extract_scalar(xdm.asset.raw_fields, "$.Platform Discovery.association.publicIp")
```

---

### Sgrumer - AWS GuardDuty status
Contributor: Shelby Grumer

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory | filter xdm.asset.provider contains "AWS" | filter xdm.asset.type.id contains "Guardduty" | fields Account_ID, Enabled
```

---

### Sgrumer - Host Inventory OS distribution
Contributor: Shelby Grumer

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory | filter xdm.host.os_distribution != null | comp count(xdm.asset.id) as Total by xdm.host.os_distribution | view graph type = pie
```

---

### Sgrumer - Logging Findings categories
Contributor: Shelby Grumer

**Dataset:** `findings`

```xql
dataset=findings | filter xdm.finding.name contains "Flow Logs" or xdm.finding.name contains "Access logging" | comp count(issue_id ) as issues by category | view graph type = pie
```

---

### Sgrumer - Asset Search dynamic dashboard
Contributor: Shelby Grumer

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory | filter xdm.asset.provider contains "AWS" | fields Name, Account_ID, Type
```

---

### Sgrumer - GCP Audit Log Sources Total Count
Contributor: Shelby Grumer

**Dataset:** `cloud_audit_logs`

```xql
dataset = cloud_audit_logs | filter cloud_provider = ENUM.GCP | comp count() as total by log_name
```

---

### Sgrumer - AWS Audit Log Sources Total Count
Contributor: Shelby Grumer

**Dataset:** `cloud_audit_logs`

```xql
dataset = cloud_audit_logs | filter cloud_provider = ENUM.AWS | comp count() as total by log_name
```

---

### Sgrumer - Azure Audit Log Sources Total Count
Contributor: Shelby Grumer

**Dataset:** `cloud_audit_logs`

```xql
dataset = cloud_audit_logs | filter cloud_provider = ENUM.AZURE | comp count() as total by log_name
```

---

### Sgrumer - Open Issues by Provider stacked
Contributor: Shelby Grumer

**Dataset:** `issues`

```xql
dataset = issues | filter (xdm.issue.status.progress = "NEW" or xdm.issue.status.progress = "UNDER_INVESTIGATION") | join (dataset = issue_to_asset) | join (dataset = asset_inventory) | comp count(xdm.issue.id) as issues by Detection_Method , provider | view graph type = column
```

---

### AppSec Secret identifying filename and line
Contributor: Luis Latorre

**Dataset:** `issues`

```xql
dataset = issues | filter xdm.issue.detection.method = "CAS_SECRET_SCANNER" | fields xdm.file.path, xdm.file.filename, xdm.issue.description
```

---

### Sgrumer - Package Search Widget which assets
Contributor: Shelby Grumer

**Dataset:** `asset_inventory`

```xql
dataset = asset_inventory | filter (xdm.asset.type.name contains "Package" or xdm.asset.type.category contains "package") and xdm.asset.name contains $package_name
```

---

### report identify issues + asset name realm provider
Contributor: Luis Latorre

**Dataset:** `issues`

```xql
dataset = issues | filter xdm.issue.domain = "POSTURE" | join (dataset = asset_inventory) as asset_data asset_data.assetid = xdm.issue.asset_ids | fields INC_Name, affectedasset, provider, cloudaccountid
```

---

### XQL for TAC Case Discovery
Contributor: Derar Al-Omari

**Dataset:** `cloud_health_auditing`

```xql
config timeframe = 30d | dataset = cloud_health_auditing | filter account = "<account_id>" and capability = "Discovery"
```

---

### XQL for TAC Case ADS
Contributor: Derar Al-Omari

**Dataset:** `cloud_health_auditing`

```xql
config timeframe = 30d | dataset = cloud_health_auditing | filter account = "<account_id>" and capability = "ADS"
```

---

### XQL for TAC Case Registry/Connector
Contributor: Derar Al-Omari

**Dataset:** `cloud_health_auditing`

```xql
config timeframe = 30d | dataset = cloud_health_auditing | filter account = "<project_id>" and (capability = "Registry" or capability = "Connector")
```

---

### XQL for TAC Case Project Audit
Contributor: Derar Al-Omari

**Dataset:** `cloud_audit_logs`

```xql
config timeframe = 30d | dataset = cloud_audit_logs | filter project = "<project_id>"
```

---

### XQL for TAC Case Project Health
Contributor: Derar Al-Omari

**Dataset:** `cloud_health_auditing`

```xql
config timeframe = 30d | dataset = cloud_health_auditing | filter account = "<project_id>"
```

---

