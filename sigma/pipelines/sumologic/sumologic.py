from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.processing.transformations import *
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.pipelines.common import *
from sigma.pipelines.sysmon import *

# placeholder to possibly transform Windows application log levels between numeric codes and text vals
# for example, translate level: 2 to level: error
windows_severity_levels = {}

alt_windows_logsources = [
    "appxdeployment-server",
    "bits-client",
    "codeintegrity-operational",
    "diagnosis-scripted",
    "dns-server",
    "firewall-as",
    "ldap_debug",
    "msexchange-management",
    "ntlm",
    "openssh",
    "printservice-operational",
    "printservice-admin",
    "security-mitigations",
    "shell-core",
    "smbclient-security",
    "taskscheduler",
    "terminalservices-localsessionmanager",
    "wmi"
]

windows_sysmon_conditions = [
    logsource_windows_process_creation(),
    logsource_windows_file_change(),
    logsource_windows_network_connection(),
    logsource_windows_driver_load(),
    logsource_windows_image_load(),
    logsource_windows_create_remote_thread(),
    logsource_windows_raw_access_thread(),
    logsource_windows_process_access(),
    logsource_windows_file_event(),
    logsource_windows_registry_add(),
    logsource_windows_registry_delete(),
    logsource_windows_registry_set(),
    logsource_windows_registry_event(),
    logsource_windows_create_stream_hash(),
    logsource_windows_pipe_created(),
    logsource_windows_wmi_event(),
    logsource_windows_dns_query(),
    logsource_windows_file_delete()
]

linux_sysmon_conditions = [
    LogsourceCondition(
        category=item,
        product="linux"
    )
    for item in sysmon.sysmon_generic_logsource_eventid_mapping
]

ps_categories = [
    "ps_classic_start",
    "ps_module",
    "ps_script"
]

powershell_logsource_conditions = [
    LogsourceCondition(
        product="windows",
        category=cat
    )
    for cat in ps_categories
]

def logsource_antivirus() -> LogsourceCondition:
    return LogsourceCondition(
        category="antivirus"
    )

def logsource_windows_security() -> LogsourceCondition:
    return LogsourceCondition(
        product="windows",
        service="security"
    )

def logsource_windows_application() -> LogsourceCondition:
    return LogsourceCondition(
        product="windows",
        service="application"
    )

def logsource_windows_system() -> LogsourceCondition:
    return LogsourceCondition(
        product="windows",
        service="system"
    )

def logsource_windows_defender() -> LogsourceCondition:
    return LogsourceCondition(
        product="windows",
        service="windefend"
    )

def logsource_aws() -> LogsourceCondition:
    return LogsourceCondition(
        product="aws",
        service="cloudtrail"
    )

def logsource_azure() -> LogsourceCondition:
    return LogsourceCondition(
        product="azure"
    )

def logsource_gcp() -> LogsourceCondition:
    return LogsourceCondition(
        product="gcp",
        service="gcp.audit"
    )

def logsource_gworkspace() -> LogsourceCondition:
    return LogsourceCondition(
        product="google_workspace"
    )

def logsource_m365() -> LogsourceCondition:
    return LogsourceCondition(
        product="m365"
    )

def logsource_okta() -> LogsourceCondition:
    return LogsourceCondition(
        product="okta",
        service="okta"
    )

def logsource_onelogin() -> LogsourceCondition:
    return LogsourceCondition(
        product="onelogin",
        service="onelogin.events"
    )

def logsource_linux() -> LogsourceCondition:
    return LogsourceCondition(
        product="linux"
    )

def logsource_macos() -> LogsourceCondition:
    return LogsourceCondition(
        product="macos"
    )

def logsource_generic_dns_query() -> LogsourceCondition:
    return LogsourceCondition(
        category="dns"
    )

def logsource_web_proxy() -> LogsourceCondition:
    return LogsourceCondition(
        category="proxy"
    )

def logsource_firewall() -> LogsourceCondition:
    return LogsourceCondition(
        category="firewall"
    )

def logsource_apache() -> LogsourceCondition:
    return LogsourceCondition(
        service="apache"
    )

def logsource_webserver() -> LogsourceCondition:
    return LogsourceCondition(
        category="webserver"
    )

def sumologic_cip_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="SumoLogic CIP Processing Pipeline",
        priority=20,
        items=[
            # prohibit field names with spaces
            ProcessingItem(
                identifier="sumologic_cip_fail_space_in_field_name",
                transformation=DetectionItemFailureTransformation("The SumoLogic backend does not permit spaces in field names."),
                field_name_conditions=[
                    IncludeFieldCondition(
                        fields=[r".*\ .*"],
                        type="re"
                    )
                ],
            ),
            # antivirus field mapping
            ProcessingItem(
                identifier="sumologic_cip_antivirus_fieldmapping",
                transformation=FieldMappingTransformation({
                    "Computer": "src_host",
                    "FileName": "file_path",
                    "Filename": "file_path",
                    "Signature": "signature",
                    "User": "src_user"
                }),
                rule_conditions=[
                    logsource_antivirus()
                ]
            ),
            # generic windows field mapping
            ProcessingItem(
                identifier="sumologic_cip_windows_generic_fieldmapping",
                transformation=FieldMappingTransformation({
                    "EventID": "event_id",
                    "Channel": "event_type",
                    "ProviderName": "event_subtype",
                    "Provider_Name": "event_subtype"
                }),
            rule_conditions=[
                LogsourceCondition(
                        product="windows"
                    )
                ]
            ),
            # generic sysmon field mapping
            ProcessingItem(
                identifier="sumologic_cip_sysmon_generic_fieldmapping",
                rule_condition_linking=any,
                transformation=FieldMappingTransformation({
                    "ProcessId": "process_id",
                    "ProcessID": "process_id",
                    "UtcTime": "time_utc",
                    "Computer": "src_host",
                    "ComputerName": "src_host",
                    "FileVersion": "file_version",
                    "Product": "product",
                    "Company": "company",
                    "Keywords": "keywords",
                    "User": "src_user",
                    "Description": "description",
                    "Image": "process_path",
                    "md5": "process_hash_md5",
                    "sha1": "process_hash_sha1",
                    "sha256": "process_hash_sha256",
                    "Imphash": "process_hash_imphash",
                    "MD5": "process_hash_md5",
                    "SHA1": "process_hash_sha1",
                    "SHA256": "process_hash_sha256",
                    "IMPHASH": "process_hash_imphash",
                    "Hashes": "hashes"
                }),
            rule_conditions=windows_sysmon_conditions
            ),
            # process creation field mapping (sysmon event 1)
            ProcessingItem(
                identifier="sumologic_cip_process_creation_fieldmapping",
                transformation=FieldMappingTransformation({
                    "CurrentDirectory": "current_directory",
                    "OriginalFilename": "orig_filename",
                    "OriginalFileName": "orig_filename",
                    "LogonGuid": "logon_guid",
                    "LogonId": "src_logon_id",
                    "TerminalSessionId": "terminal_session_id",
                    "IntegrityLevel": "integrity_level",
                    "ParentProcessGuid": "parent_process_guid",
                    "ParentProcessId": "parent_process_id",
                    "ParentImage": "parent_process_path",
                    "CommandLine": "command_line",
                    "ParentCommandLine": "parent_command_line"
                }),
                rule_conditions=[
                    logsource_windows_process_creation()
                ]
            ),
            # file change (sysmon event 2)
            ProcessingItem(
                identifier="sumologic_cip_file_change_fieldmapping",
                transformation=FieldMappingTransformation({
                    "TargetFilename": "target_file_path",
                    "CreationUtcTime": "creation_time_utc",
                    "PreviousCreationUtcTime": "prev_creation_time_utc"
                }),
                rule_conditions=[
                    logsource_windows_file_change()
                ]
            ),
            # network connection (sysmon event 3)
            ProcessingItem(
                identifier="sumologic_cip_network_connection_fieldmapping",
                transformation=FieldMappingTransformation({
                    "DestinationHostname": "dst_host",
                    "DestinationIp": "dst_ip",
                    "DestinationIsIpv6": "dst_is_ipv6",
                    "DestinationPort": "dst_port",
                    "Initiated": "initiated",
                    "Protocol": "protocol",
                    "RemoteAddress": "dst_ip",
                    "SourceIp": "src_ip",
                    "SourcePort": "src_port"
                }),
                rule_conditions=[
                    logsource_windows_network_connection()
                ]
            ),
            # driver loaded (sysmon event 6)
            ProcessingItem(
                identifier="sumologic_cip_driver_loaded_fieldmapping",
                transformation=FieldMappingTransformation({
                    "ImageLoaded": "image_loaded",
                    "ImagePath": "image_loaded",
                    "SignatureStatus": "signature_status",
                    "Signed": "signed"
                }),
                rule_conditions=[
                    logsource_windows_driver_load()
                ]
            ),
            # image loaded (sysmon event 7)
            ProcessingItem(
                identifier="sumologic_cip_image_loaded_fieldmapping",
                transformation=FieldMappingTransformation({
                    "ImageLoaded": "image_loaded",
                    "OriginalFileName": "orig_filename",
                    "SignatureStatus": "signature_status",
                    "Signed": "signed",
                    "Signature": "signature"
                }),
                rule_conditions=[
                    logsource_windows_image_load()
                ]
            ),
            # create remote thread (sysmon event 8)
            ProcessingItem(
                identifier="sumologic_cip_remote_thread_fieldmapping",
                transformation=FieldMappingTransformation({
                    "SourceProcessGuid": "src_process_guid",
                    "SourceProcessId": "src_process_id",
                    "SourceImage": "src_image",
                    "SourceParentImage": "src_parent_image",
                    "TargetProcessGuid": "target_process_guid",
                    "TargetProcessId": "target_process_id",
                    "TargetParentProcessId": "target_parent_process_id",
                    "TargetImage": "target_image",
                    "NewThreadId": "new_thread_id",
                    "StartAddress": "start_address",
                    "StartFunction": "start_function",
                    "StartModule": "start_module"
                }),
                rule_conditions=[
                    logsource_windows_create_remote_thread()
                ]
            ),
            # raw access thread (sysmon event 9)
            ProcessingItem(
                identifier="sumologic_cip_raw_access_thread_fieldmapping",
                transformation=FieldMappingTransformation({
                    "Device": "device"
                }),
                rule_conditions=[
                    logsource_windows_raw_access_thread()
                ]
            ),
            # process access (sysmon event 10)
            ProcessingItem(
                identifier="sumologic_cip_process_access_fieldmapping",
                transformation=FieldMappingTransformation({
                    "SourceProcessGuid": "src_process_guid",
                    "SourceProcessId": "src_process_id",
                    "SourceThreadId": "src_thread_id",
                    "SourceImage": "src_image",
                    "TargetProcessGuid": "target_process_guid",
                    "TargetProcessId": "target_process_id",
                    "TargetImage": "target_image",
                    "GrantedAccess": "granted_access",
                    "CallTrace": "call_trace"
                }),
                rule_conditions=[
                    logsource_windows_process_access()
                ]
            ),
            # file event (sysmon event 11)
            ProcessingItem(
                identifier="sumologic_cip_file_event_fieldmapping",
                transformation=FieldMappingTransformation({
                    "PipeName": "pipe_name",
                    "ServiceFileName": "service_file_name",
                    "ServiceName": "service_name",
                    "TargetFileName": "target_file_path",
                    "TargetFilename": "target_file_path"
                }),
                rule_conditions=[
                    logsource_windows_file_event()
                ]
            ),
            # registry event (sysmon events 12-14)
            ProcessingItem(
                identifier="sumologic_cip_registry_event_fieldmapping",
                rule_condition_linking=any,
                transformation=FieldMappingTransformation({
                    "EventType": "reg_event_type",
                    "TargetObject": "target_reg_object",
                    "Details": "reg_details",
                    "details": "reg_details",
                    "NewName": "new_name"
                }),
                rule_conditions=[
                    logsource_windows_registry_add(),
                    logsource_windows_registry_delete(),
                    logsource_windows_registry_set(),
                    logsource_windows_registry_event()
                ]
            ),
            # file create stream hash (sysmon event 15)
            ProcessingItem(
                identifier="sumologic_cip_file_create_stream_hash_fieldmapping",
                transformation=FieldMappingTransformation({
                    "Contents": "contents",
                    "TargetFilename": "target_file_path"
                }),
                rule_conditions=[
                    logsource_windows_create_stream_hash()
                ]
            ),
            # pipe created (sysmon events 17-18)
            ProcessingItem(
                identifier="sumologic_cip_pipe_created_fieldmapping",
                transformation=FieldMappingTransformation({
                    "PipeName": "pipe_name",
                }),
                rule_conditions=[
                    logsource_windows_pipe_created()
                ]
            ),
            # wmi event (sysmon events 19-21)
            ProcessingItem(
                identifier="sumologic_cip_wmi_event_fieldmapping",
                transformation=FieldMappingTransformation({
                    "EventType": "wmi_event_type",
                    "Operation": "wmi_operation",
                    "EventNamespace": "wmi_event_namespace",
                    "Name": "wmi_object_name",
                    "Query": "wmi_query",
                    "Type": "wmi_type",
                    "Destination": "wmi_dest",
                    "Consumer": "wmi_consumer",
                    "Filter": "wmi_filter"
                }),
                rule_conditions=[
                    logsource_windows_wmi_event()
                ]
            ),
            # dns query (sysmon event 22)
            ProcessingItem(
                identifier="sumologic_cip_dns_query_fieldmapping",
                transformation=FieldMappingTransformation({
                    "QueryName": "dns_query",
                    "QueryResults": "dns_query_answers",
                    "QueryStatus": "query_status"
                }),
                rule_conditions=[
                    logsource_windows_dns_query()
                ]
            ),
            # file delete (sysmon event 23)
            ProcessingItem(
                identifier="sumologic_cip_file_delete_fieldmapping",
                transformation=FieldMappingTransformation({
                    "TargetFilename": "target_file_path",
                    "FileName": "target_file_path",
                    "IsExecutable": "is_executable",
                    "Archived": "archived"
                }),
                rule_conditions=[
                    logsource_windows_file_delete()
                ]
            ),
            # generic windows security event field mapping
            ProcessingItem(
                identifier="sumologic_cip_windows_security_fieldmapping",
                transformation=FieldMappingTransformation({
                    "AccessList": "access_list",
                    "AccessMask": "access_mask",
                    "Accesses": "accesses",
                    "AllowedToDelegateTo": "allowed_to_delegate_to",
                    "Application": "application_name",
                    "AttributeLDAPDisplayName": "ldap_display_name",
                    "AttributeValue": "attribute_value",
                    "AuditPolicyChanges": "audit_policy_changes",
                    "AuditSourceName": "audit_source_name",
                    "AuthenticationPackageName": "auth_package",
                    "CallerProcessName": "process_path",
                    "CertThumbprint": "cert_thumbprint",
                    "ClassName": "class_name",
                    "ClientProcessId": "client_process_id",
                    "ComputerName": "dst_host",
                    "DestAddress": "dst_ip",
                    "DestPort": "dst_port",
                    "DeviceDescription": "device_description",
                    "EventCode": "event_id",
                    "FailureCode": "failure_code",
                    "FilterOrigin": "filter_origin",
                    "ImpersonationLevel": "impersonation_level",
                    "IpAddress": "src_ip",
                    "KeyLength": "key_length",
                    "Keywords": "keywords",
                    "LayerRTID": "layer_rt_id",
                    "LogonProcessName": "logon_process",
                    "LogonType": "logon_type",
                    "NewTargetUserName": "new_dst_user",
                    "NewTemplateContent": "new_template_content",
                    "NewUacValue": "new_uac_value",
                    "NewValue": "new_value",
                    "ObjectClass": "object_class",
                    "ObjectName": "object_name",
                    "ObjectServer": "object_server",
                    "ObjectType": "object_type",
                    "ObjectValueName": "object_value",
                    "OldTargetUserName": "old_dst_user",
                    "OldUacValue": "old_uac_user",
                    "ParentProcessId": "parent_process_id",
                    "PasswordLastSet": "password_last_set",
                    "PrivilegeList": "privilege_list",
                    "ProcessID": "process_id",
                    "ProcessName": "process_path",
                    "Properties": "properties",
                    "RelativeTargetName": "relative_target_name",
                    "SamAccountName": "dst_user",
                    "Service": "service",
                    "ServiceFileName": "service_file_name",
                    "ServiceName": "service_name",
                    "ServicePrincipalNames": "service_principal_names",
                    "ServiceStartType": "service_start_type",
                    "ServiceType": "service_type",
                    "ShareName": "share_name",
                    "SidHistory": "sid_history",
                    "SourceAddress": "src_address",
                    "SourcePort": "src_port",
                    "Status": "status",
                    "SubjectDomainName": "src_user_domain",
                    "SubjectLogonId": "src_logon_id",
                    "SubjectUserName": "src_user",
                    "SubjectUserSid": "src_user_sid",
                    "TargetLogonId": "dst_logon_id",
                    "TargetName": "target_name",
                    "TargetOutboundUserName": "target_outbound_user",
                    "TargetServerName": "dst_host",
                    "TargetSid": "dst_sid",
                    "TargetUserName": "dst_user",
                    "TargetUserSid": "dst_user_sid",
                    "Task": "task_content",
                    "TaskContent": "task_content",
                    "TaskContentNew": "new_task_content",
                    "TaskName": "task_name",
                    "TemplateContent": "template_content",
                    "TicketEncryptionType": "ticket_encryption",
                    "TicketOptions": "ticket_options",
                    "Workstation": "src_host",
                    "WorkstationName": "src_hostname"
                }),
                rule_conditions=[
                    logsource_windows_security()
                ]
            ),
            # add both hex and string representations for keywords in Windows event logs
            # accounts for situations where the rule/event log has EITHER 'Audit Failure/Success' OR their hex representations
            # drops success keyword detection item (hex value)
            ProcessingItem(
                identifier="sumologic_cip_windows_security_drop_success_keywords_hex",
                transformation=DropDetectionItemTransformation(),
                rule_conditions=[
                    logsource_windows_security(),
                    RuleContainsDetectionItemCondition(
                        field="keywords",
                        value="0x8020000000000000"
                    )
                ],
                rule_condition_linking=all,
                field_name_conditions=[
                    IncludeFieldCondition(fields=["keywords"]),
                ]
            ),
            # drops failure keyword detection item (hex value)
            ProcessingItem(
                identifier="sumologic_cip_windows_security_drop_failure_keywords_hex",
                transformation=DropDetectionItemTransformation(),
                rule_conditions=[
                    logsource_windows_security(),
                    RuleContainsDetectionItemCondition(
                        field="keywords",
                        value="0x8010000000000000"
                    )
                ],
                rule_condition_linking=all,
                field_name_conditions=[
                    IncludeFieldCondition(fields=["keywords"]),
                ]
            ),
            # drops success keyword detection item (string value)
            ProcessingItem(
                identifier="sumologic_cip_windows_security_drop_success_keywords_str",
                transformation=DropDetectionItemTransformation(),
                rule_conditions=[
                    logsource_windows_security(),
                    RuleContainsDetectionItemCondition(
                        field="keywords",
                        value="Audit Success"
                    )
                ],
                rule_condition_linking=all,
                field_name_conditions=[
                    IncludeFieldCondition(fields=["keywords"]),
                ]
            ),
            # drops failure keyword detection item (string value)
            ProcessingItem(
                identifier="sumologic_cip_windows_security_drop_failure_keywords_str",
                transformation=DropDetectionItemTransformation(),
                rule_conditions=[
                    logsource_windows_security(),
                    RuleContainsDetectionItemCondition(
                        field="keywords",
                        value="Audit Failure"
                    )
                ],
                rule_condition_linking=all,
                field_name_conditions=[
                    IncludeFieldCondition(fields=["keywords"]),
                ]
            ),
            # adds success keyword detection item back in with hex and string values
            ProcessingItem(
                identifier="sumologic_cip_windows_security_add_success_keywords",
                transformation=AddConditionTransformation({
                    "keywords": ["0x8020000000000000", "Audit Success"],
                }),
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("sumologic_cip_windows_security_drop_success_keywords_hex"),
                    RuleProcessingItemAppliedCondition("sumologic_cip_windows_security_drop_success_keywords_str")
                ],
                rule_condition_linking=any
            ),
            # adds failure keyword detection item back in with hex and string values
            ProcessingItem(
                identifier="sumologic_cip_windows_security_add_failure_keywords",
                transformation=AddConditionTransformation({
                    "keywords": ["0x8010000000000000", "Audit Failure"],
                }),
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("sumologic_cip_windows_security_drop_failure_keywords_hex"),
                    RuleProcessingItemAppliedCondition("sumologic_cip_windows_security_drop_failure_keywords_str")
                ],
                rule_condition_linking=any
            ),
            # windows application
            ProcessingItem(
                identifier="sumologic_cip_windows_application_fieldmapping",
                transformation=FieldMappingTransformation({
                    "AppName": "app_name",
                    "Data": "event_data",
                    "ExceptionCode": "error_code",
                    "Level": "severity",
                    "Message": "event_msg"
                }),
                rule_conditions=[
                    logsource_windows_application()
                ]
            ),
            # windows system
            ProcessingItem(
                identifier="sumologic_cip_windows_system_fieldmapping",
                transformation=FieldMappingTransformation({
                    "AccountName": "account_name",
                    "Caption": "caption",
                    "Channel": "event_type",
                    "Description": "event_msg",
                    "DeviceName": "device_name",
                    "HiveName": "hive_name",
                    "ImagePath": "process_path",
                    "Level": "severity",
                    "Origin": "origin",
                    "ProcessId": "process_id",
                    "ServiceName": "service_name",
                    "ServiceType": "service_type",
                    "StartType": "service_start_type",
                    "param1": "param_1",
                    "param2": "param_2",
                    "param3": "param_3"
                }),
                rule_conditions=[
                    logsource_windows_system()
                ]
            ),
            # windows defender
            ProcessingItem(
                identifier="sumologic_cip_windows_defender_fieldmapping",
                transformation=FieldMappingTransformation({
                    "NewValue": "new_value",
                    "OldValue": "old_value",
                    "Path": "path",
                    "ProcessName": "process_name",
                    "SourceName": "source_name",
                    "Value": "value"
                }),
                rule_conditions=[
                    logsource_windows_defender()
                ]
            ),
            # windows powershell
            ProcessingItem(
                identifier="sumologic_cip_powershell_fieldmapping",
                transformation=FieldMappingTransformation({
                    "ContextInfo": "context_info",
                    "EngineVersion": "engine_version",
                    "HostApplication": "host_application",
                    "HostName": "host_name",
                    "HostVersion": "host_version",
                    "Payload": "payload",
                    "Path": "script_path",
                    "ScriptBlockText": "script_block"
                }),
                rule_conditions=powershell_logsource_conditions,
                rule_condition_linking=any
            ),
            # unsupported powershell field
            ProcessingItem(
                identifier="sumologic_cip_fail_powershell_fields",
                transformation=DetectionItemFailureTransformation("The ParentImage and CommandLine fields are not supported for Powershell rules (did you mean to use them in a Process Creation rule?)."),
                rule_conditions=powershell_logsource_conditions,
                rule_condition_linking=any,
                field_name_conditions=[
                    IncludeFieldCondition(
                        fields=[
                            "ParentImage",
                            "CommandLine"
                        ]
                    )
                ]
            ),
            # alternative windows log source field mapping
            ProcessingItem(
                identifier="sumologic_cip_alt_windows_fieldmapping",
                transformation=FieldMappingTransformation({
                    "LocalName": "local_name",
                    "RemoteName": "remote_name",
                    "processPath": "bits_process_path",
                    "FileNameBuffer": "filename_buffer",
                    "ProcessNameBuffer": "process_name_buffer",
                    "RequestedPolicy": "requested_policy",
                    "ValidatedPolicy": "validated_policy",
                    "PackagePath": "package_path",
                    "QName": "query_name",
                    "Action": "action",
                    "ApplicationPath": "application_path",
                    "ModifyingApplication": "modifying_application",
                    "SearchFilter": "search_filter",
                    "Data": "event_msg",
                    "ProcessName": "process_name",
                    "WorkstationName": "workstation_name",
                    "TargetName": "target_name",
                    "ErrorCode": "error_code",
                    "PluginDllName": "plugin_dll_name",
                    "ProcessPath": "proces_path",
                    "ImageName": "image_name",
                    "AppID": "app_id",
                    "Name": "app_name",
                    "Description": "event_msg",
                    "UserName": "smb_src_user",
                    "ServerName": "smb_server_name",
                    "ShareName": "smb_share_name",
                    "TaskName": "task_name",
                    "Path": "path",
                    "PackageFullName": "package_full_name",
                    "Address": "address",
                    "Provider": "wmi_event_provider",
                    "Query": "wmi_query",
                    "User": "wmi_user",
                    "PossibleCause": "possible_cause"
                }),
                rule_conditions=[
                    LogsourceCondition(product="windows",
                                    service=svc)
                    for svc in alt_windows_logsources
                ],
                rule_condition_linking=any
            ),
            # aws field mapping
            ProcessingItem(
                identifier="sumologic_cip_aws_fieldmapping",
                transformation=FieldMappingTransformation({
                    "errorCode": "error_code",
                    "errorMessage": "error_msg",
                    "eventName": "event_name",
                    "eventSource": "event_source",
                    "eventType": "event_type",
                    "requestParameters.attribute": "request_attribute",
                    "requestParameters.containerDefinitions.command": "container_command",
                    "requestParameters.userName": "src_user",
                    "responseElements": "resp_elements",
                    "responseElements.accessKey.userName": "dst_user",
                    "responseElements.pendingModifiedValues.masterUserPassword": "master_user_password",
                    "responseElements.publiclyAccessible": "publicly_accessible",
                    "sourceIPAddress": "src_ip",
                    "userIdentity.arn": "user_arn",
                    "userIdentity.sessionContext.sessionIssuer.type": "session_issuer_type",
                    "userIdentity.type": "user_type"
                }),
                rule_conditions=[
                    logsource_aws()
                ]
            ),
            # azure field mapping
            ProcessingItem(
                identifier="sumologic_cip_azure_fieldmapping",
                transformation=FieldMappingTransformation({
                    "ActivityDetails": "activity_details",
                    "ActivityDisplayName": "activity_display_name",
                    "ActivityType": "activity_type",
                    "AppId": "app_id",
                    "AuthenticationRequirement": "auth_requirement",
                    "Category": "category",
                    "CategoryValue": "category_value",
                    "ConsentContext.IsAdminConsent": "admin_consent",
                    "DeviceDetail.deviceId": "device_id",
                    "DeviceDetail.isCompliant": "device_compliant",
                    "HomeTenantId": "home_tenant_id",
                    "InitiatedBy": "initiated_by",
                    "Initiatedby": "initiated_by",
                    "Location": "location",
                    "LoggedByService": "logged_by_service",
                    "NetworkLocationDetails": "network_location",
                    "Operation": "operation_name",
                    "OperationName": "operation_name",
                    "OperationNameValue": "operation_name",
                    "ResourceDisplayName": "resource_display_name",
                    "ResourceId": "resource_id",
                    "ResourceTenantId": "resource_tenant_id",
                    "ResultDescription": "result_description",
                    "ResultType": "result",
                    "Status": "status",
                    "Target": "target",
                    "TargetResources": "target_resources",
                    "TargetUserName": "username",
                    "Username": "username",
                    "Workload": "workload",
                    "conditionalAccessStatus": "conditional_access_status",
                    "eventName": "operation_name",
                    "eventSource": "workload",
                    "operationName": "operation_name",
                    "properties.message": "activity_display_name",
                    "status": "result",
                    "userAgent": "user_agent"
                }),
                rule_conditions=[
                    logsource_azure()
                ]
            ),
            # unsupported azure fields
            ProcessingItem(
                identifier="sumologic_cip_fail_azure_fields",
                rule_condition_linking=any,
                transformation=DetectionItemFailureTransformation("The SumoLogic CIP backend does not support the Count, ModifiedProperties{}.NewValue, or resourceProvider fields for Azure events."),
                rule_conditions=[
                    logsource_azure()
                ],
                field_name_conditions=[
                    IncludeFieldCondition(
                        fields=[
                            "Count",
                            "ModifiedProperties{}.NewValue",
                            "ResourceProviderValue",
                            "ClientApp"
                        ]
                    )
                ]
            ),
            # gcp field mapping
            ProcessingItem(
                identifier="sumologic_cip_gcp_fieldmapping",
                transformation=FieldMappingTransformation({
                    "gcp.audit.method_name": "method_name"
                }),
                rule_conditions=[
                    logsource_gcp()
                ]
            ),
            # google workspace field mapping
            ProcessingItem(
                identifier="sumologic_cip_gworkspace_fieldmapping",
                transformation=FieldMappingTransformation({
                    "eventName": "event_name",
                    "eventService": "event_service"
                }),
                rule_conditions=[
                    logsource_gworkspace()
                ]
            ),
            # m365 field mapping
            ProcessingItem(
                identifier="sumologic_cip_m365_fieldmapping",
                transformation=FieldMappingTransformation({
                    "Payload": "operation",
                    "eventName": "event_name",
                    "eventSource": "event_service",
                    "status": "result"
                }),
                rule_conditions=[
                    logsource_m365()
                ]
            ),
            # m365 value conversion for successful events
            ProcessingItem(
                identifier="sumologic_cip_m365_drop_success_item",
                transformation=DropDetectionItemTransformation(),
                rule_conditions=[
                    logsource_m365(),
                    RuleContainsDetectionItemCondition(
                        field="result",
                        value="success"
                    )
                ],
                rule_condition_linking=all,
                field_name_conditions=[
                    IncludeFieldCondition(fields=["result"]),
                ]
            ),
            ProcessingItem(
                identifier="sumologic_cip_m365_add_success_item",
                transformation=AddConditionTransformation({
                    "result": ["success", "succeeded"],
                }),
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("sumologic_cip_m365_drop_success_item")
                ]
            ),
            # okta field mapping
            ProcessingItem(
                identifier="sumologic_cip_okta_fieldmapping",
                transformation=FieldMappingTransformation({
                    "displaymessage": "display_message",
                    "eventtype": "event_type"
                }),
                rule_conditions=[
                    logsource_okta()
                ]
            ),
            # onelogin field mapping
            ProcessingItem(
                identifier="sumologic_cip_onelogin_fieldmapping",
                transformation=FieldMappingTransformation({
                    "event_type_id": "event_id"
                }),
                rule_conditions=[
                    logsource_onelogin()
                ]
            ),
            # sysmon linux field mapping
            ProcessingItem(
                identifier="sumologic_cip_linux_sysmon_fieldmapping",
                transformation=FieldMappingTransformation({
                    "CommandLine": "command_line",
                    "CurrentDirectory": "current_directory",
                    "DestinationHostname": "dst_host",
                    "DestinationIp": "dst_ip",
                    "Image": "process_path",
                    "LogonId": "src_logon_id",
                    "ParentCommandLine": "parent_command_line",
                    "ParentImage": "parent_process_path",
                    "TargetFilename": "target_filename",
                    "User": "src_user",
                }),
                rule_conditions=linux_sysmon_conditions,
                rule_condition_linking=any
            ),
            # generic linux field mapping
            ProcessingItem(
                identifier="sumologic_cip_linux_fieldmapping",
                transformation=FieldMappingTransformation({
                    "USER": "src_user",
                    "a0": "cmd_arg_1",
                    "a1": "cmd_arg_2",
                    "a2": "cmd_arg_3",
                    "a3": "cmd_arg_4",
                    "a4": "cmd_arg_5",
                    "a5": "cmd_arg_6",
                    "a6": "cmd_arg_7",
                    "a7": "cmd_arg_8",
                    "a8": "cmd_arg_9",
                    "a9": "cmd_arg_10",
                    "comm": "process_name",
                    "cwd": "current_directory",
                    "exe": "process_exe_path",
                    "key": "log_key",
                    "name": "file_name",
                    "nametype": "name_type",
                    "pam_message": "pam_result",
                    "pam_rhost": "dst_host",
                    "pam_user": "src_user_pam",
                    "proctitle": "proc_title",
                    "syscall": "sys_call",
                    "type": "event_type",
                    "uid": "src_user_id",
                    "unit": "service_name"
                }),
                rule_conditions=[
                    logsource_linux()
                ]
            ),
            # linux syscall value replacement
            ProcessingItem(
                identifier="sumologic_cip_linux_syscall_code_replacement",
                transformation=ReplaceStringTransformation(
                    regex="59",
                    replacement="execve",
                ),
                rule_conditions=[
                    logsource_linux()
                ],
                field_name_conditions=[
                    IncludeFieldCondition(fields=["sys_call"])
                ]
            ),
            # generic dns field mapping
            ProcessingItem(
                identifier="sumologic_cip_dns_fieldmapping",
                transformation=FieldMappingTransformation({
                    "parent_domain": "root_domain"
                }),
                rule_conditions=[
                    logsource_generic_dns_query()
                ]
            ),
            # proxy field mapping
            ProcessingItem(
                identifier="sumologic_cip_proxy_fieldmapping",
                transformation=FieldMappingTransformation({
                    "ClientIP": "src_ip",
                    "c-ip": "src_ip",
                    "c-ua": "user_agent",
                    "c-uri": "url",
                    "c-uri-extension": "url_extension",
                    "c-uri-query": "uri_query",
                    "c-useragent": "user_agent",
                    "cs-cookie": "cookie",
                    "cs-host": "src_host",
                    "cs-ip": "src_ip",
                    "cs-method": "method",
                    "cs-uri": "url",
                    "r-dns": "dst_domain",
                    "sc-bytes": "bytes_out",
                    "sc-status": "response_code"
                }),
                rule_conditions=[
                    logsource_web_proxy()
                ]
            ),
            # web server field mapping
            ProcessingItem(
                identifier="sumologic_webserver_fieldmapping",
                rule_condition_linking=any,
                transformation=FieldMappingTransformation({
                    "c-dns": "dst_domain",
                    "c-ip": "src_ip",
                    "c-uri": "url",
                    "c-useragent": "user_agent",
                    "client_ip": "src_ip",
                    "cs-User-Agent": "user_agent",
                    "cs-method": "method",
                    "cs-referer": "referrer",
                    "cs-status": "response_code",
                    "cs-uri": "url",
                    "cs-uri-query": "uri_query",
                    "cs-uri-stem": "uri_stem",
                    "cs-username": "src_user",
                    "sc-status": "response_code",
                    "url": "url",
                    "user-agent": "user_agent",
                    "vhost": "virtual_host"
                }),
                rule_conditions=[
                    logsource_apache(),
                    logsource_webserver()
                ]
            )
        ]
        +
        # windows/linux sysmon processing - add event ID field and map all sysmon fields
        [
            # add event ID field
            ProcessingItem(
                identifier="sumologic_cip_sysmon_{log_source}_eventid".format(log_source=item[0]),
                transformation=AddConditionTransformation({
                    "event_id": item[1],
                }),
                rule_conditions=[
                    LogsourceCondition(
                        category=item[0]
                    )
                ]
            )
            for item in sysmon.sysmon_generic_logsource_eventid_mapping.items()
        ]
    )

def sumologic_cse_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="SumoLogic CSE Processing Pipeline",
        priority=20,
        items=[
            # prohibit field names with spaces (unless they are enclosed by brackets like fields['EventData.Source Name']
            ProcessingItem(
                identifier="sumologic_cse_fail_space_in_field_name",
                transformation=DetectionItemFailureTransformation("The SumoLogic backend does not permit spaces in field names."),
                field_name_conditions=[
                    IncludeFieldCondition(
                        fields=[r".*\ (?![^\[]*\]).*"],
                        type="re"
                    )
                ],
            )
        ,
        # antivirus field mapping
            ProcessingItem(
                identifier="sumologic_cse_antivirus_fieldmapping",
                transformation=FieldMappingTransformation({
                    "Computer": "device_hostname",
                    "FileName": "file_path",
                    "Filename": "file_path",
                    "Signature": "threat_name",
                    "User": "user_username"
                }),
                rule_conditions=[
                    logsource_antivirus()
                ]
            ),
            # generic windows field mapping
            ProcessingItem(
                identifier="sumologic_cse_windows_generic_fieldmapping",
                transformation=FieldMappingTransformation({
                    "Channel": "fields['Channel']",
                    "EventID": "fields['EventID']",
                    "Keywords": "fields['Keywords']",
                    "ProviderName": "fields['Provider.Name']",
                    "Provider_Name": "fields['Provider.Name']"
                }),
            rule_conditions=[
                LogsourceCondition(
                        product="windows"
                    )
                ]
            ),
            # add vendor/product info (Microsoft/Windows)
            ProcessingItem(
                identifier="sumologic_cse_windows_vendor_product_info",
                transformation=AddConditionTransformation({
                    "metadata_vendor": "Microsoft",
                    "metadata_product": "Windows"
                }),
                rule_conditions=[
                    LogsourceCondition(
                        product="windows"
                    )
                ]
            ),
            # add vendor/product info (AWS/CloudTrail)
            ProcessingItem(
                identifier="sumologic_cse_aws_vendor_product_info",
                transformation=AddConditionTransformation({
                    "metadata_vendor": "AWS",
                    "metadata_product": "CloudTrail"
                }),
                rule_conditions=[
                    logsource_aws()
                ]
            ),
            # add vendor/product info (Microsoft/Azure)
            ProcessingItem(
                identifier="sumologic_cse_azure_vendor_product_info",
                transformation=AddConditionTransformation({
                    "metadata_vendor": "Microsoft",
                    "metadata_product": "Azure"
                }),
                rule_conditions=[
                    logsource_azure()
                ]
            ),
            # add vendor/product info (Microsoft/Office 365)
            ProcessingItem(
                identifier="sumologic_cse_m365_vendor_product_info",
                transformation=AddConditionTransformation({
                    "metadata_vendor": "Microsoft",
                    "metadata_product": "Office 365"
                }),
                rule_conditions=[
                    logsource_m365()
                ]
            ),
            # add vendor/product info (Google/Google Cloud Platform)
            ProcessingItem(
                identifier="sumologic_cse_gcp_vendor_product_info",
                transformation=AddConditionTransformation({
                    "metadata_vendor": "Google",
                    "metadata_product": "Google Cloud Platform"
                }),
                rule_conditions=[
                    logsource_gcp()
                ]
            ),
            # add vendor/product info (Google/G Suite)
            ProcessingItem(
                identifier="sumologic_cse_gworkspace_vendor_product_info",
                transformation=AddConditionTransformation({
                    "metadata_vendor": "Google",
                    "metadata_product": "G Suite"
                }),
                rule_conditions=[
                    logsource_gworkspace()
                ]
            ),
            # add vendor/product info (Okta/Single Sign-On)
            ProcessingItem(
                identifier="sumologic_cse_okta_vendor_product_info",
                transformation=AddConditionTransformation({
                    "metadata_vendor": "Okta",
                    "metadata_product": "Single Sign-On"
                }),
                rule_conditions=[
                    logsource_okta()
                ]
            ),
            # add vendor/product info (OneLogin/OneLogin Single Sign-On)
            ProcessingItem(
                identifier="sumologic_cse_onelogin_vendor_product_info",
                transformation=AddConditionTransformation({
                    "metadata_vendor": "OneLogin",
                    "metadata_product": "OneLogin Single Sign-On"
                }),
                rule_conditions=[
                    logsource_onelogin()
                ]
            ),
            # add vendor/product info (Linux/Sysmon for Linux)
            ProcessingItem(
                identifier="sumologic_cse_sysmon_linux_vendor_product_info",
                transformation=AddConditionTransformation({
                    "metadata_vendor": "Linux",
                    "metadata_product": "Sysmon for Linux"
                }),
                rule_conditions=linux_sysmon_conditions,
                rule_condition_linking=any
            ),
            # generic sysmon field mapping
            ProcessingItem(
                identifier="sumologic_cse_sysmon_generic_fieldmapping",
                rule_condition_linking=any,
                transformation=FieldMappingTransformation({
                    "ProcessId": "pid",
                    "ProcessID": "pid",
                    "UtcTime": "timestamp",
                    "Computer": "device_hostname",
                    "ComputerName": "device_hostname",
                    "FileVersion": "fields['EventData.FileVersion']",
                    "Product": "fields['EventData.Product']",
                    "Company": "fields['EventData.Company']",
                    "User": "user_username",
                    "Description": "description",
                    "Image": "baseImage",
                    "md5": "file_hash_md5",
                    "sha1": "file_hash_sha1",
                    "sha256": "file_hash_sha256",
                    "Imphash": "file_hash_imphash",
                    "MD5": "file_hash_md5",
                    "SHA1": "file_hash_sha1",
                    "SHA256": "file_hash_sha256",
                    "IMPHASH": "file_hash_imphash",
                    "Hashes": "fields['EventData.Hashes']"
                }),
            rule_conditions=windows_sysmon_conditions
            ),
            # process creation field mapping (sysmon event 1)
            ProcessingItem(
                identifier="sumologic_cse_process_creation_fieldmapping",
                transformation=FieldMappingTransformation({
                    "CurrentDirectory": "fields['EventData.CurrentDirectory']",
                    "OriginalFilename": "fields['EventData.OriginalFileName']",
                    "OriginalFileName": "fields['EventData.OriginalFileName']",
                    "LogonGuid": "fields['EventData.LogonGuid']",
                    "LogonId": "fields['EventData.LogonId']",
                    "TerminalSessionId": "fields['EventData.TerminalSessionId']",
                    "IntegrityLevel": "fields['EventData.IntegrityLevel']",
                    "ParentProcessGuid": "fields['EventData.ParentProcessGuid']",
                    "ParentProcessId": "parentPid",
                    "CommandLine": "commandLine",
                    "ParentImage": "parentBaseImage",
                    "ParentCommandLine": "parentCommandLine"
                }),
                rule_conditions=[
                    logsource_windows_process_creation()
                ]
            ),
            # file change (sysmon event 2)
            ProcessingItem(
                identifier="sumologic_cse_file_change_fieldmapping",
                transformation=FieldMappingTransformation({
                    "TargetFilename": "file_path",
                    "CreationUtcTime": "fields['EventData.CreationUtcTime']",
                    "PreviousCreationUtcTime": "fields['EventData.PreviousCreationUtcTime']"
                }),
                rule_conditions=[
                    logsource_windows_file_change()
                ]
            ),
            # network connection (sysmon event 3)
            ProcessingItem(
                identifier="sumologic_cse_network_connection_fieldmapping",
                transformation=FieldMappingTransformation({
                    "DestinationHostname": "dstDevice_hostname",
                    "DestinationIp": "dstDevice_ip",
                    "DestinationIsIpv6": "fields['EventData.DestinationIsIpv6']",
                    "DestinationPort": "dstPort",
                    "Initiated": "fields['EventData.Initiated']",
                    "Protocol": "fields['EventData.Protocol']",
                    "RemoteAddress": "dstDevice_ip",
                    "SourceIp": "srcDevice_ip",
                    "SourcePort": "srcPort"
                }),
                rule_conditions=[
                    logsource_windows_network_connection()
                ]
            ),
            # driver loaded (sysmon event 6)
            ProcessingItem(
                identifier="sumologic_cse_driver_loaded_fieldmapping",
                transformation=FieldMappingTransformation({
                    "ImageLoaded": "file_path",
                    "ImagePath": "file_path",
                    "Signature": "fields['EventData.Signature']",
                    "SignatureStatus": "fields['EventData.SignatureStatus']",
                    "Signed": "fields['EventData.Signed']"
                }),
                rule_conditions=[
                    logsource_windows_driver_load()
                ]
            ),
            # image loaded (sysmon event 7)
            ProcessingItem(
                identifier="sumologic_cse_image_loaded_fieldmapping",
                transformation=FieldMappingTransformation({
                    "Image": "parentBaseImage",
                    "ImageLoaded": "baseImage",
                    "OriginalFileName": "fields['EventData.OriginalFileName']",
                    "SignatureStatus": "fields['EventData.SignatureStatus']",
                    "Signed": "fields['EventData.Signed']",
                    "Signature": "fields['EventData.Signature']"
                }),
                rule_conditions=[
                    logsource_windows_image_load()
                ]
            ),
            # create remote thread (sysmon event 8)
            ProcessingItem(
                identifier="sumologic_cse_remote_thread_fieldmapping",
                transformation=FieldMappingTransformation({
                    "SourceProcessGuid": "fields['EventData.SourceProcessGuid']",
                    "SourceProcessId": "pid",
                    "SourceImage": "baseImage",
                    "TargetProcessGuid": "fields['EventData.TargetProcessGuid']",
                    "TargetProcessId": "fields['EventData.TargetProcessId']",
                    "TargetImage": "file_path",
                    "NewThreadId": "fields['EventData.NewThreadId']",
                    "StartAddress": "fields['EventData.StartAddress']",
                    "StartFunction": "fields['EventData.StartFunction']",
                    "StartModule": "fields['EventData.StartModule']"
                }),
                rule_conditions=[
                    logsource_windows_create_remote_thread()
                ]
            ),
            # raw access thread (sysmon event 9)
            ProcessingItem(
                identifier="sumologic_cse_raw_access_thread_fieldmapping",
                transformation=FieldMappingTransformation({
                    "Device": "fields['EventData.Device']"
                }),
                rule_conditions=[
                    logsource_windows_raw_access_thread()
                ]
            ),
            # process access (sysmon event 10)
            ProcessingItem(
                identifier="sumologic_cse_process_access_fieldmapping",
                transformation=FieldMappingTransformation({
                    "SourceProcessGuid": "fields['EventData.SourceProcessGuid']",
                    "SourceProcessId": "fields['EventData.SourceProcessId']",
                    "SourceThreadId": "fields['EventData.SourceThreadId']",
                    "SourceImage": "fields['EventData.SourceImage']",
                    "TargetProcessGuid": "fields['EventData.TargetProcessGuid']",
                    "TargetProcessId": "fields['EventData.TargetProcessId']",
                    "TargetImage": "fields['EventData.TargetImage']",
                    "GrantedAccess": "fields['EventData.GrantedAccess']",
                    "CallTrace": "fields['EventData.CallTrace']"
                }),
                rule_conditions=[
                    logsource_windows_process_access()
                ]
            ),
            # file event (sysmon event 11)
            ProcessingItem(
                identifier="sumologic_cse_file_event_fieldmapping",
                transformation=FieldMappingTransformation({
                    "TargetFileName": "file_path",
                    "TargetFilename": "file_path"
                }),
                rule_conditions=[
                    logsource_windows_file_event()
                ]
            ),
            # registry event (sysmon events 12-14)
            ProcessingItem(
                identifier="sumologic_cse_registry_event_fieldmapping",
                rule_condition_linking=any,
                transformation=FieldMappingTransformation({
                    "EventType": "action",
                    "TargetObject": "changeTarget",
                    "Details": "resource",
                    "details": "resource",
                    "NewName": "fields['EventData.NewName']"
                }),
                rule_conditions=[
                    logsource_windows_registry_add(),
                    logsource_windows_registry_delete(),
                    logsource_windows_registry_set(),
                    logsource_windows_registry_event()
                ]
            ),
            # file create stream hash (sysmon event 15)
            ProcessingItem(
                identifier="sumologic_cse_file_create_stream_hash_fieldmapping",
                transformation=FieldMappingTransformation({
                    "Contents": "fields['EventData.Contents']",
                    "TargetFilename": "file_path"
                }),
                rule_conditions=[
                    logsource_windows_create_stream_hash()
                ]
            ),
            # pipe created (sysmon events 17-18)
            ProcessingItem(
                identifier="sumologic_cse_pipe_created_fieldmapping",
                transformation=FieldMappingTransformation({
                    "PipeName": "resource",
                }),
                rule_conditions=[
                    logsource_windows_pipe_created()
                ]
            ),
            # wmi event (sysmon events 19-21)
            ProcessingItem(
                identifier="sumologic_cse_wmi_event_fieldmapping",
                transformation=FieldMappingTransformation({
                    "EventType": "fields['EventData.EventType']",
                    "Operation": "fields['EventData.Operation']",
                    "EventNamespace": "fields['EventData.EventNamespace']",
                    "Name": "fields['EventData.Name']",
                    "Query": "fields['EventData.Query']",
                    "Type": "fields['EventData.Type']",
                    "Destination": "fields['EventData.Destination']",
                    "Consumer": "fields['EventData.Destination']",
                    "Filter": "fields['EventData.Filter']"
                }),
                rule_conditions=[
                    logsource_windows_wmi_event()
                ]
            ),
            # dns query (sysmon event 22)
            ProcessingItem(
                identifier="sumologic_cse_dns_query_fieldmapping",
                transformation=FieldMappingTransformation({
                    "QueryName": "dns_query",
                    "QueryResults": "dns_reply",
                    "QueryStatus": "dns_returnCode"
                }),
                rule_conditions=[
                    logsource_windows_dns_query()
                ]
            ),
            # file delete (sysmon event 23)
            ProcessingItem(
                identifier="sumologic_cse_file_delete_fieldmapping",
                transformation=FieldMappingTransformation({
                    "TargetFilename": "file_path",
                    "FileName": "file_path",
                    "IsExecutable": "fields['EventData.IsExecutable']",
                    "Archived": "fields['EventData.Archived']"
                }),
                rule_conditions=[
                    logsource_windows_file_delete()
                ]
            ),
            # generic windows security event field mapping
            ProcessingItem(
                identifier="sumologic_cse_windows_security_fieldmapping",
                transformation=FieldMappingTransformation({
                    "AccessList": "fields['EventData.AccessList']",
                    "AccessMask": "fields['EventData.AccessMask']",
                    "Accesses": "fields['EventData.Accesses']",
                    "AllowedToDelegateTo": "fields['EventData.AllowedToDelegateTo']",
                    "Application": "fields['EventData.Application']",
                    "AttributeLDAPDisplayName": "fields['EventData.AttributeLDAPDisplayName']",
                    "AttributeValue": "fields['EventData.AttributeValue']",
                    "AuditPolicyChanges": "changeTarget",
                    "AuditSourceName": "fields['EventData.AuditSourceName']",
                    "AuthenticationPackageName": "fields['EventData.AuthenticationPackageName']",
                    "CallerProcessName": "fields['EventData.CallerProcessName']",
                    "CertThumbprint": "fields['EventData.CertThumbprint']",
                    "ClassName": "fields['EventData.ClassName']",
                    "ClientProcessId": "fields['EventData.ClientProcessId']",
                    "ComputerName": "device_hostname",
                    "DestAddress": "fields['EventData.DestAddress']",
                    "DestPort": "fields['EventData.DestPort']",
                    "DeviceDescription": "fields['EventData.DeviceDescription']",
                    "FailureCode": "fields['EventData.Status']",
                    "FilterOrigin": "fields['EventData.FilterOrigin']",
                    "ImpersonationLevel": "fields['EventData.ImpersonationLevel']",
                    "IpAddress": "srcDevice_ip",
                    "KeyLength": "fields['EventData.KeyLength']",
                    "Keywords": "fields['EventData.Keywords']",
                    "LayerRTID": "fields['EventData.LayerRTID']",
                    "LogonProcessName": "fields['EventData.LogonProcessName']",
                    "LogonType": "fields['EventData.LogonType']",
                    "NewTargetUserName": "fields['EventData.NewTargetUserName']",
                    "NewTemplateContent": "fields['EventData.NewTemplateContent']",
                    "NewUacValue": "fields['EventData.NewUacValue']",
                    "NewValue": "fields['EventData.NewValue']",
                    "ObjectClass": "fields['EventData.ObjectClass']",
                    "ObjectName": "file_path",
                    "ObjectServer": "fields['EventData.ObjectServer']",
                    "ObjectType": "fields['EventData.ObjectType']",
                    "ObjectValueName": "fields['EventData.ObjectValueName']",
                    "OldValue": "fields['EventData.OldValue']",
                    "OldTargetUserName": "fields['EventData.OldTargetUserName']",
                    "OldUacValue": "fields['EventData.OldUacValue']",
                    "ParentProcessId": "parentPid",
                    "PasswordLastSet": "fields['EventData.PasswordLastSet']",
                    "PrivilegeList": "fields['EventData.PrivilegeList']",
                    "ProcessID": "pid",
                    "ProcessName": "baseImage",
                    "Properties": "changeType",
                    "RelativeTargetName": "baseImage",
                    "SamAccountName": "changeTarget",
                    "Service": "fields['EventData.Service']",
                    "ServiceFileName": "fields['EventData.ServiceFileName']",
                    "ServiceName": "fields['EventData.ServiceName']",
                    "ServicePrincipalNames": "fields['EventData.ServicePrincipalNames']",
                    "ServiceStartType": "fields['EventData.ServiceStartType']",
                    "ServiceType": "fields['EventData.ServiceType']",
                    "ShareName": "file_path",
                    "SidHistory": "fields['EventData.SidHistory']",
                    "SourceAddress": "fields['EventData.SourceAddress']",
                    "SourcePort": "fields['EventData.SourcePort']",
                    "Status": "errorCode",
                    "SubjectDomainName": "user_authDomain",
                    "SubjectLogonId": "fields['EventData.SubjectLogonId']",
                    "SubjectUserName": "user_username",
                    "SubjectUserSid": "user_userId",
                    "TargetLogonId": "fields['EventData.TargetLogonId']",
                    "TargetName": "fields['EventData.TargetName']",
                    "TargetOutboundUserName": "fields['EventData.TargetOutboundUserName']",
                    "TargetServerName": "fields['EventData.TargetServerName']",
                    "TargetSid": "fields['EventData.TargetSid']",
                    "TargetUserName": "changeTarget",
                    "TargetUserSid": "fields['EventData.TargetUserSid']",
                    "Task": "fields['EventData.TaskName']",
                    "TaskContent": "fields['EventData.TaskContent']",
                    "TaskContentNew": "fields['EventData.TaskContentNew']",
                    "TaskName": "fields['EventData.TaskName']",
                    "TemplateContent": "fields['EventData.TemplateContent']",
                    "TicketEncryptionType": "fields['EventData.TicketEncryptionType']",
                    "TicketOptions": "fields['EventData.TicketOptions']",
                    "Workstation": "srcDevice_hostname",
                    "WorkstationName": "srcDevice_hostname"
                }),
                rule_conditions=[
                    logsource_windows_security()
                ]
            ),
            # windows application
            ProcessingItem(
                identifier="sumologic_cse_windows_application_fieldmapping",
                transformation=FieldMappingTransformation({
                    "AppName": "fields['EventData.Data.1']",
                    "Data": "fields['Message']",
                    "ExceptionCode": "fields['EventData.Data.7']",
                    "Level": "severity",
                    "Message": "fields['Message']"
                }),
                rule_conditions=[
                    logsource_windows_application()
                ]
            ),
            # windows system
            ProcessingItem(
                identifier="sumologic_cse_windows_system_fieldmapping",
                transformation=FieldMappingTransformation({
                    "AccountName": "fields['EventData.AccountName']",
                    "Caption": "fields['EventData.Caption']",
                    "Description": "fields['EventData.Message']",
                    "DeviceName": "fields['EventData.DeviceName']",
                    "HiveName": "fields['EventData.HiveName']",
                    "ImagePath": "baseImage",
                    "Level": "fields['Level']",
                    "Origin": "fields['EventData.Origin']",
                    "ProcessId": "pid",
                    "ServiceName": "fields['EventData.ServiceName']",
                    "ServiceType": "fields['EventData.ServiceType']",
                    "StartType": "fields['EventData.StartType']",
                    "param1": "fields['EventData.param1']",
                    "param2": "fields['EventData.param2']",
                    "param3": "fields['EventData.param3']"
                }),
                rule_conditions=[
                    logsource_windows_system()
                ]
            ),
            # windows defender
            ProcessingItem(
                identifier="sumologic_cse_windows_defender_fieldmapping",
                transformation=FieldMappingTransformation({
                    "NewValue": "fields['EventData.NewValue']",
                    "OldValue": "fields['EventData.OldValue']",
                    "Path": "fields['EventData.Path']",
                    "ProcessName": "baseImage",
                    "SourceName": "fields['EventData.Source Name']",
                    "Value": "fields['EventData.Value']"
                }),
                rule_conditions=[
                    logsource_windows_defender()
                ]
            ),
            # windows powershell
            ProcessingItem(
                identifier="sumologic_cse_powershell_fieldmapping",
                transformation=FieldMappingTransformation({
                    "ContextInfo": "fields['EventData.ContextInfo']",
                    "Payload": "fields['EventData.Payload']",
                    "Path": "file_path",
                    "ScriptBlockText": "commandLine"
                }),
                rule_conditions=powershell_logsource_conditions,
                rule_condition_linking=any
            ),
            # unsupported powershell field
            ProcessingItem(
                identifier="sumologic_cse_fail_powershell_fields",
                transformation=DetectionItemFailureTransformation("The ParentImage, CommandLine, HostApplication, HostName, HostVersion, and EngineVersion fields are not supported for Powershell rules."),
                rule_conditions=powershell_logsource_conditions,
                rule_condition_linking=any,
                field_name_conditions=[
                    IncludeFieldCondition(
                        fields=[
                            "ParentImage",
                            "CommandLine",
                            "HostApplication",
                            "HostName",
                            "HostVersion",
                            "EngineVersion"
                        ]
                    )
                ]
            ),
            # alternative windows log source field mapping
            ProcessingItem(
                identifier="sumologic_cse_alt_windows_fieldmapping",
                transformation=FieldMappingTransformation({
                    "LocalName": "fields['EventData.LocalName']",
                    "RemoteName": "fields['EventData.RemoteName']",
                    "processPath": "fields['EventData.processPath']",
                    "FileNameBuffer": "fields['EventData.FileNameBuffer']",
                    "ProcessNameBuffer": "fields['EventData.ProcessNameBuffer']",
                    "RequestedPolicy": "fields['EventData.RequestedPolicy']",
                    "ValidatedPolicy": "fields['EventData.ValidatedPolicy']",
                    "PackagePath": "fields['EventData.PackagePath']",
                    "QName": "fields['EventData.QName']",
                    "Action": "fields['EventData.Action']",
                    "ApplicationPath": "fields['EventData.ApplicationPath']",
                    "ModifyingApplication": "fields['EventData.ModifyingApplication']",
                    "SearchFilter": "fields['EventData.SearchFilter']",
                    "ProcessName": "fields['EventData.ProcessName']",
                    "WorkstationName": "fields['EventData.WorkstationName']",
                    "TargetName": "fields['EventData.TargetName']",
                    "process": "fields['EventData.process']",
                    "payload": "fields['EventData.payload']",
                    "ErrorCode": "fields['EventData.ErrorCode']",
                    "PluginDllName": "fields['EventData.PluginDllName']",
                    "ProcessPath": "fields['EventData.ProcessPath']",
                    "ImageName": "fields['EventData.ImageName']",
                    "AppID": "fields['EventData.AppID']",
                    "Name": "fields['EventData.AppID']",
                    "Description": "fields['Message']",
                    "UserName": "fields['EventData.UserName']",
                    "ServerName": "fields['EventData.ServerName']",
                    "ShareName": "fields['EventData.ShareName']",
                    "TaskName": "fields['EventData.TaskName']",
                    "Path": "fields['EventData.Path']",
                    "PackageFullName": "fields['EventData.PackageFullName']",
                    "Address": "fields['EventData.Address']",
                    "Provider": "fields['EventData.Provider']",
                    "Query": "fields['EventData.Query']",
                    "User": "fields['EventData.User']",
                    "PossibleCause": "fields['EventData.PossibleCause']"
                }),
                rule_conditions=[
                    LogsourceCondition(product="windows",
                                    service=svc)
                    for svc in alt_windows_logsources
                ],
                rule_condition_linking=any
            ),
            # aws field mapping
            ProcessingItem(
                identifier="sumologic_cse_aws_fieldmapping",
                transformation=FieldMappingTransformation({
                    "errorCode": "fields['errorCode']",
                    "errorMessage": "fields['errorMessage']",
                    "eventName": "action",
                    "eventSource": "application",
                    "eventType": "fields['eventType']",
                    "requestParameters.attribute": "fields['requestParameters.attribute']",
                    "requestParameters.containerDefinitions.command": "fields['requestParameters.containerDefinitions.command']",
                    "requestParameters.userName": "fields['requestParameters.userName']",
                    "responseElements": "resp_elements",
                    "responseElements.accessKey.userName": "fields['responseElements.accessKey.userName']",
                    "responseElements.pendingModifiedValues.masterUserPassword": "fields['responseElements.pendingModifiedValues.masterUserPassword']",
                    "responseElements.publiclyAccessible": "fields['responseElements.publiclyAccessible']",
                    "sourceIPAddress": "srcDevice_ip",
                    "userIdentity.arn": "fields['userIdentity.arn']",
                    "userIdentity.sessionContext.sessionIssuer.type": "fields['userIdentity.sessionContext.sessionIssuer.type']",
                    "userIdentity.type": "fields['userIdentity.type']"
                }),
                rule_conditions=[
                    logsource_aws()
                ]
            ),
            # azure field mapping
            ProcessingItem(
                identifier="sumologic_cse_azure_fieldmapping",
                transformation=FieldMappingTransformation({
                    "ActivityDisplayName": "fields['properties.activityDisplayName']",
                    "ActivityType": "changeType",
                    "AppId": "fields['properties.appId']",
                    "AuthenticationRequirement": "fields['properties.authenticationRequirement']",
                    "Category": "fields['properties.category']",
                    "CategoryValue": "fields['category']",
                    "ConsentContext.IsAdminConsent": "fields['modified_property_ConsentContext.IsAdminConsent']",
                    "DeviceDetail.deviceId": "device_uniqueId",
                    "DeviceDetail.isCompliant": "fields['properties.deviceDetail.isCompliant']",
                    "HomeTenantId": "fields['properties.homeTenantId']",
                    "InitiatedBy": "user_username",
                    "Initiatedby": "user_username",
                    "Location": "fields['location']",
                    "LoggedByService": "cloud_service",
                    "Operation": "action",
                    "OperationName": "action",
                    "OperationNameValue": "action",
                    "ResourceDisplayName": "fields['properties.resourceDisplayName']",
                    "ResourceId": "fields['properties.resourceId']",
                    "ResourceTenantId": "fields['properties.resourceTenantId']",
                    "ResultDescription": "fields['resultDescription']",
                    "ResultType": "errorCode",
                    "Status": "errorCode",
                    "Target": "changeTarget",
                    "TargetResources": "changeTarget",
                    "TargetUserName": "targetUser_username",
                    "Username": "user_username",
                    "conditionalAccessStatus": "fields['properties.conditionalAccessStatus']",
                    "eventName": "operation_name",
                    "operationName": "fields['operationName']",
                    "properties.message": "fields['properties.activityDisplayName']",
                    "status": "errorCode",
                    "userAgent": "fields['properties.userAgent']"
                }),
                rule_conditions=[
                    logsource_azure()
                ]
            ),
            # unsupported azure fields
            ProcessingItem(
                identifier="sumologic_cse_fail_azure_fields",
                rule_condition_linking=any,
                transformation=DetectionItemFailureTransformation("The SumoLogic CIP backend does not support the Count, ModifiedProperties{}.NewValue, or resourceProvider fields for Azure events."),
                rule_conditions=[
                    logsource_azure()
                ],
                field_name_conditions=[
                    IncludeFieldCondition(
                        fields=[
                            "Count",
                            "ModifiedProperties{}.NewValue",
                            "ResourceProviderValue",
                            "ActivityDetails",
                            "ClientApp",
                            "NetworkLocationDetails",
                            "Workload",
                            "eventSource"
                        ]
                    )
                ]
            ),
            # gcp field mapping
            ProcessingItem(
                identifier="sumologic_cse_gcp_fieldmapping",
                transformation=FieldMappingTransformation({
                    "gcp.audit.method_name": "action"
                }),
                rule_conditions=[
                    logsource_gcp()
                ]
            ),
            # google workspace field mapping
            ProcessingItem(
                identifier="sumologic_cse_gworkspace_fieldmapping",
                transformation=FieldMappingTransformation({
                    "eventName": "action",
                    "new_value": "fields['event.parameters.NEW_VALUE']"
                }),
                rule_conditions=[
                    logsource_gworkspace()
                ]
            ),
            # google workspace drop eventService
            ProcessingItem(
                identifier="sumologic_cse_gworkspace_drop_eventService",
                transformation=DropDetectionItemTransformation(),
                rule_conditions=[
                    logsource_gworkspace(),
                    RuleContainsDetectionItemCondition(
                        field="eventService",
                        value="admin.googleapis.com"
                    )
                ],
                rule_condition_linking=all,
                field_name_conditions=[
                    IncludeFieldCondition(fields=["eventService"])
                ]
            ),
            # m365 field mapping
            ProcessingItem(
                identifier="sumologic_cse_m365_fieldmapping",
                transformation=FieldMappingTransformation({
                    "Payload": "fields['Operation']",
                    "eventName": "fields['eventName']",
                    "eventSource": "fields['SecurityComplianceCenter']",
                    "status": "fields['ResultStatus']"
                }),
                rule_conditions=[
                    logsource_m365()
                ]
            ),
            # m365 value conversion for successful events
            ProcessingItem(
                identifier="sumologic_cse_m365_drop_success_item",
                transformation=DropDetectionItemTransformation(),
                rule_conditions=[
                    logsource_m365(),
                    RuleContainsDetectionItemCondition(
                        field="result",
                        value="success"
                    )
                ],
                rule_condition_linking=all,
                field_name_conditions=[
                    IncludeFieldCondition(fields=["result"]),
                ]
            ),
            ProcessingItem(
                identifier="sumologic_cse_m365_add_success_item",
                transformation=AddConditionTransformation({
                    "result": ["success", "succeeded"],
                }),
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("sumologic_cip_m365_drop_success_item")
                ]
            ),
            # okta field mapping
            ProcessingItem(
                identifier="sumologic_cse_okta_fieldmapping",
                transformation=FieldMappingTransformation({
                    "displaymessage": "description",
                    "eventtype": "metadata_deviceEventId"
                }),
                rule_conditions=[
                    logsource_okta()
                ]
            ),
            # onelogin field mapping
            ProcessingItem(
                identifier="sumologic_cse_onelogin_fieldmapping",
                transformation=FieldMappingTransformation({
                    "event_type_id": "fields['event.event_type_id']"
                }),
                rule_conditions=[
                    logsource_onelogin()
                ]
            ),
            # sysmon linux field mapping
            ProcessingItem(
                identifier="sumologic_cse_linux_sysmon_fieldmapping",
                transformation=FieldMappingTransformation({
                    "CommandLine": "commandLine",
                    "CurrentDirectory": "fields['EventData.CurrentDirectory']",
                    "DestinationHostname": "dstDevice_hostname",
                    "DestinationIp": "dstDevice_ip",
                    "Image": "baseImage",
                    "LogonId": "fields['EventData.LogonId']",
                    "ParentCommandLine": "parentCommandLine",
                    "ParentImage": "parentBaseImage",
                    "TargetFilename": "file_path",
                    "User": "user_username",
                }),
                rule_conditions=linux_sysmon_conditions,
                rule_condition_linking=any
            ),
            # generic dns field mapping
            ProcessingItem(
                identifier="sumologic_cip_dns_fieldmapping",
                transformation=FieldMappingTransformation({
                    "parent_domain": "dns_queryDomain"
                }),
                rule_conditions=[
                    logsource_generic_dns_query()
                ]
            ),
            # proxy field mapping
            ProcessingItem(
                identifier="sumologic_cip_proxy_fieldmapping",
                transformation=FieldMappingTransformation({
                    "ClientIP": "dstDevice_ip",
                    "c-ip": "dstDevice_ip",
                    "c-ua": "http_userAgent",
                    "c-uri": "http_url",
                    "c-uri-extension": "url_extension",
                    "c-useragent": "http_userAgent",
                    "cs-host": "srcDevice_hostname",
                    "cs-ip": "srcDevice_ip",
                    "cs-method": "http_method",
                    "cs-uri": "http_url",
                    "r-dns": "dns_queryDomain",
                    "sc-bytes": "bytesOut",
                    "sc-status": "http_response_statusCode"
                }),
                rule_conditions=[
                    logsource_web_proxy()
                ]
            ),
            # web server field mapping
            ProcessingItem(
                identifier="sumologic_webserver_fieldmapping",
                rule_condition_linking=any,
                transformation=FieldMappingTransformation({
                    "c-dns": "dstDevice_hostname",
                    "c-ip": "srcDevice_ip",
                    "c-uri": "http_url",
                    "c-useragent": "http_userAgent",
                    "client_ip": "srcDevice_ip",
                    "cs-User-Agent": "http_userAgent",
                    "cs-method": "http_method",
                    "cs-referer": "http_referer",
                    "cs-status": "http_response_statusCode",
                    "cs-uri": "http_url",
                    "cs-username": "user_username",
                    "sc-status": "http_response_statusCode",
                    "url": "http_url",
                    "user-agent": "http_userAgent"
                }),
                rule_conditions=[
                    logsource_apache(),
                    logsource_webserver()
                ]
            ),
            # web-related fields not supported
            ProcessingItem(
                identifier="sumologic_cse_fail_web_fields",
                transformation=DetectionItemFailureTransformation("The c-uri-query, cs-cookie, cs-uri-query, cs-uri-stem, and vhost fields are not supported for Powershell rules."),
                rule_conditions=[
                    logsource_apache(),
                    logsource_webserver()
                ],
                rule_condition_linking=any,
                field_name_conditions=[
                    IncludeFieldCondition(
                        fields=[
                            "c-uri-query",
                            "cs-cookie",
                            "cs-uri-query",
                            "cs-uri-stem",
                            "vhost"
                        ]
                    )
                ]
            ),
        ]
        +
        # windows/linux sysmon processing - add event ID field and map all sysmon fields
        [
            # add event ID field
            ProcessingItem(
                identifier="sumologic_cse_sysmon_{log_source}_eventid".format(log_source=item[0]),
                transformation=AddConditionTransformation({
                    "fields['EventID']": item[1],
                }),
                rule_conditions=[
                    LogsourceCondition(
                        category=item[0]
                    )
                ]
            )
            for item in sysmon.sysmon_generic_logsource_eventid_mapping.items()
        ]
    )
