# HOLMES Full Remaining 42

Input: `rules/holmes_full`
Source summary: `qa_reports/14b_review_summary_holmes_full_retag2.json`

## Current Counts

- `FAIL_RELATION_MISMATCH`: 14
- `FAIL_CLOUD_MISMATCH`: 11
- `FAIL_EMPTY_OBJECT`: 9
- `FAIL_OVERFITTING`: 7
- `FAIL_NO_PREREQUISITE`: 1

## Likely Auto-Fixable

These still look reducible with deterministic type or relation heuristics.

### Relation mismatch

- `hholmes_network/cisco/bgp/cisco_bgp_md5_auth_failed.json`
- `hholmes_network/zeek/zeek_smb_converted_win_impacket_secretdump.json`
- `hholmes_network/zeek/zeek_smb_converted_win_transferring_files_with_credential_data.json`
- `hholmes_windows/builtin/security/account_management/win_security_member_added_security_enabled_global_group.json`
- `hholmes_windows/builtin/security/account_management/win_security_member_removed_security_enabled_global_group.json`
- `hholmes_windows/builtin/security/account_management/win_security_susp_rottenpotato.json`
- `hholmes_windows/builtin/security/win_security_mal_wceaux_dll.json`
- `hholmes_windows/builtin/security/win_security_susp_possible_shadow_credentials_added.json`
- `hholmes_windows/network_connection/net_connection_win_susp_binary_no_cmdline.json`

Observed pattern:

- Windows security event rules still use `Process`/`File` where `Event`, `Identity`, or `NetFlow` may fit better.
- Some Zeek and Cisco network rules still carry file-shaped attributes like `path`, `name`, or `file_path`.

### Cloud mismatch

- `hholmes_cloud/azure/activity_logs/azure_kubernetes_secret_or_config_object_access.json`
- `hholmes_cloud/azure/audit_logs/azure_ad_guest_users_invited_to_tenant_by_non_approved_inviters.json`
- `hholmes_cloud/azure/signin_logs/azure_ad_failed_auth_from_countries_you_do_not_operate_out_of.json`
- `hholmes_windows/builtin/security/win_security_ad_object_writedac_access.json`
- `hholmes_windows/builtin/security/win_security_susp_add_sid_history.json`
- `hholmes_windows/builtin/security/win_security_transf_files_with_cred_data_via_network_shares.json`
- `hholmes_windows/dns_query/dns_query_win_mal_cobaltstrike.json`
- `hholmes_windows/network_connection/net_connection_win_winlogon_net_connections.json`

Observed pattern:

- Some Azure rules are semantically cloud or identity events but still use generic `EXECUTE` or `CONNECT` framing with sparse objects.
- A few Windows security rules likely want identity or directory-object modeling instead of `File`.

## Likely Need Re-Translation Or Manual Rule Repair

These mostly have empty object attributes or content-level issues rather than type-label issues.

### Empty object

- `hholmes_application/opencanary/opencanary_smb_file_open.json`
- `hholmes_windows/builtin/code_integrity/win_codeintegrity_blocked_protected_process_file.json`
- `hholmes_windows/file/file_change/file_change_win_unusual_modification_by_dns_exe.json`
- `hholmes_windows/file/file_event/file_event_win_wmi_persistence_script_event_consumer_write.json`
- `hholmes_windows/process_creation/proc_creation_win_bitsadmin_download_susp_extensions.json`
- `hholmes_windows/process_creation/proc_creation_win_bitsadmin_download_susp_targetfolder.json`
- `hholmes_windows/process_creation/proc_creation_win_cmd_rmdir_execution.json`
- `hholmes_windows/process_creation/proc_creation_win_rundll32_unc_path.json`
- `hholmes_windows/process_creation/proc_creation_win_schtasks_schedule_via_masqueraded_xml_file.json`

Observed pattern:

- Subject side has signal, but object extraction is `{}`.
- These likely need prompt-level extraction improvements or targeted regeneration from source Sigma.

### Overfitting

- `hholmes_windows/builtin/bits_client/win_bits_client_new_transfer_via_ip_address.json`
- `hholmes_windows/builtin/system/microsoft_windows_Iphlpsvc/win_system_isatap_router_address_set.json`
- `hholmes_windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_clip_services.json`
- `hholmes_windows/file/file_event/file_event_win_creation_unquoted_service_path.json`
- `hholmes_windows/file/file_event/file_event_win_writing_local_admin_share.json`
- `hholmes_windows/process_creation/proc_creation_win_hktl_impacket_lateral_movement.json`
- `hholmes_windows/process_creation/proc_creation_win_powershell_download_cradle_obfuscated.json`

### Missing prerequisite

- `hholmes_windows/powershell/powershell_script/posh_ps_susp_iofilestream.json`

## Suggested Next Steps

- Add one more heuristic pass for Windows security and Zeek identity/object modeling.
- Regenerate the 9 empty-object rules from source Sigma one by one.
- Review the 7 overfitting rules for hardcoded IPs, paths, or exact strings.
