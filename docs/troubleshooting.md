# Troubleshooting

## Conflicts in `summary`

A conflict is an audit event the engine could not reconcile with the snapshot. A small number is expected. Common causes:

* **Changes during collection.** The snapshot is not atomic. Re-collect off-peak.
* **Missing ingestion.** The log export was taken before recent events reached the workspace. Wait about 30 minutes after the snapshot before exporting.
* **Unknown operation names.** Run `queries/discover_operations.kql` to list every operation in your tenant, and `itm-shapes` to see how each one is parsed.

## Validating the parser on your tenant

```bash
itm-shapes auditlogs.json > shapes.txt
```

For each operation the report shows target layout, modified property names, additional detail keys, and whether it was parsed. Identifiers are redacted, so the output can be shared in an issue.

## 403 from the collector

The Azure CLI token covers the standard directory reads. Some tenants or endpoints require explicit Graph permissions. Use an app registration with the permissions listed in the README and run with `--auth sdk`, setting `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_CLIENT_SECRET`.

## The KQL query fails in PowerShell

In PowerShell, `$(cat file.kql)` joins all lines into one, so the first `//` comment disables the rest of the query. Use Bash (for example Azure Cloud Shell), or pass the file with `(Get-Content queries/auditlogs_export.kql -Raw)`.

## Large tenants

The Log Analytics query API returns at most about 500,000 rows or 64 MB per query. Split the export by time range and concatenate the results. Ephemeral detection recomputes tier-0 reach at every change point, so very large, busy tenants take longer. Narrow the window with `--from` and `--to`.
