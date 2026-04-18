# HOLMES Full QA Focus Report

Input: `rules/holmes_full`
Model: `qwen2.5-coder:14b`

## Summary

- Total rules: 3092
- PASS: 2907
- FAIL: 185
- Errors: 0

## Top Failure Types

- `FAIL_RELATION_MISMATCH`: 137
- `FAIL_CLOUD_MISMATCH`: 29

## Relation Mismatch Hotspots

- `hholmes_windows/network_connection`: 44
- `hholmes_windows/powershell/powershell_script`: 15
- `hholmes_windows/dns_query`: 14
- `hholmes_windows/process_creation`: 11
- `hholmes_windows/builtin/security/account_management`: 8
- `hholmes_web/proxy_generic`: 7
- `hholmes_network/zeek`: 6
- `hholmes_application/opencanary`: 5

Representative examples:

- `hholmes_application/github/audit/github_new_org_member.json`
- `hholmes_application/kubernetes/audit/kubernetes_audit_privileged_pod_creation.json`
- `hholmes_application/kubernetes/audit/kubernetes_audit_rbac_permisions_listing.json`
- `hholmes_windows/network_connection/net_connection_win_domain_cloudflared_communication.json`

Observed pattern:

- Many rules use `relation: CONNECT` or other non-file behaviors while `object.type` remains `File`.
- Audit, DNS, proxy, and network-derived rules often store semantic network or identity attributes under a file-shaped object node.

## Cloud Mismatch Hotspots

- `hholmes_windows/network_connection`: 5
- `hholmes_application/opencanary`: 3
- `hholmes_network/zeek`: 3
- `hholmes_windows/dns_query`: 3
- `hholmes_linux/network_connection`: 2
- `hholmes_network/dns`: 2

Representative examples:

- `hholmes_application/kubernetes/audit/kubernetes_audit_pod_in_system_namespace.json`
- `hholmes_cloud/azure/activity_logs/azure_kubernetes_secret_or_config_object_access.json`
- `hholmes_windows/network_connection/net_connection_win_domain_cloudflared_communication.json`

Observed pattern:

- The reviewer treats many cloud, SaaS, audit, and service telemetry rules as mismatched because entity modeling still defaults to `Process` and `File`.
- Kubernetes, Azure, DNS, Zeek, and OpenCanary rules often look more like event, identity, or network objects than classic process-file relations.

## Likely Root Cause

- `scripts/translator/builder.py` currently infers object type with a very narrow heuristic:
  - IP-like keys -> `NetFlow`
  - `file_path` -> `File`
  - otherwise -> `File`
- That fallback likely causes most of the `RELATION_MISMATCH` and part of the `CLOUD_MISMATCH` cluster.

## Suggested Next Pass

- Expand object type inference beyond `File` and `NetFlow`.
- Add special handling for:
  - DNS and hostname-based network indicators
  - Registry and audit-log objects
  - Cloud and identity audit events
  - Kubernetes resource objects
- Re-run linter and LLM reviewer after heuristic updates.
