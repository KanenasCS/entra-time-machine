# Security policy

Report vulnerabilities in this tool through GitHub private vulnerability reporting
(Security tab > Report a vulnerability). Please do not open public issues for security problems.

This tool is read-only against Microsoft Entra ID and Microsoft Graph. Its inputs (anchor snapshots,
AuditLogs exports) contain identity data. Never attach real tenant files to issues or pull requests.
Use `python -m itm.shapes`, which redacts identifiers, when sharing diagnostic output.
