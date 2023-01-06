# maps best-guess parsing statements for each mapped field name, per log source
parsing_statement_config = {
    "sumologic_cip_antivirus_fieldmapping": {},
    "sumologic_cip_windows_generic_fieldmapping": {
        "event_id": """| json "EventID" as event_id""",
        "event_type": """| json "Channel" as event_type""",
        "event_subtype": """| json "Provider.Name" as event_subtype""",
        "event_msg": """| json "Message" as event_msg"""
    },
    "sumologic_cip_sysmon_generic_fieldmapping": {
        "process_id": """| json "EventData.ProcessId" as process_id""",
        "time_utc": """| json "EventData.UtcTime" as time_utc""",
        "src_host": """| json "Computer" as src_host""",
        "keywords": """| json "Keyworeds" as keywords""",
        "src_user": """| json "EventData.User" as src_user""",
        "description": """| json "EventData.Description" as description""",
        "product": """| json "EventData.Product" as product""",
        "company": """| json "EventData.Company" as company""",
        "process_path": """| json "EventData.Image" as process_path""",
        "parent_process_path": """| json "EventData.ParentImage" as parent_process_path""",
        "command_line": """| json "EventData.CommandLine" as command_line""",
        "parent_command_line": """| json "EventData.ParentCommandLine" as parent_command_line""",
        "process_hash_md5": "| parse regex \"MD5=(?<process_hash_md5>.*?)(?:\,|$)\"",
        "process_hash_sha1": "| parse regex \"SHA1=(?<process_hash_sha1>.*?)(?:\,|$)\"",
        "process_hash_sha256": "| parse regex \"SHA256=(?<process_hash_sha256>.*?)(?:\,|$)\"",
        "process_hash_imphash": "| parse regex \"IMPHASH=(?<process_hash_imphash>.*?)(?:\,|$)\"",
        "hashes":  """| json "EventData.Hashes" as hashes""",
        "provider_name": """| json "Provider.Name" as provider_name"""
    },
    "sumologic_cip_process_creation_fieldmapping": {
        "file_version": """| json "EventData.FileVersion" as file_version""",
        "product": """| json "EventData.Product" as product""",
        "company": """| json "EventData.Company" as company""",
        "command_line": """| json "EventData.CommandLine" as command_line""",
        "current_directory": """| json "EventData.CurrentDirectory" as current_directory""",
        "orig_filename": """| json "EventData.OriginalFileName" as orig_filename""",
        "logon_guid": """| json "EventData.LogonGuid" as logon_guid""",
        "src_logon_id": """| json "EventData.LogonId" as src_logon_id""",
        "terminal_session_id": """| json "EventData.TerminalSessionId" as terminal_session_id""",
        "integrity_level": """| json "EventData.IntegrityLevel" as integrity_level""",
        "parent_process_guid": """| json "EventData.ParentProcessGuid" as parent_process_guid""",
        "parent_process_id": """| json "EventData.ParentProcessId" as parent_process_id""",
        "parent_process_path": """| json "EventData.ParentImage" as parent_process_path""",
        "parent_command_line": """| json "EventData.ParentCommandLine" as parent_command_line"""
    },
    "sumologic_cip_file_change_fieldmapping": {
        "target_file_path": """| json "EventData.TargetFilename" as target_file_path""",
        "creation_time_utc": """| json "EventData.CreationUtcTime" as creation_time_utc""",
        "prev_creation_time_utc": """| json "EventData.PreviousCreationUtcTime" as prev_creation_time_utc"""
    },
    "sumologic_cip_network_connection_fieldmapping": {
        "dst_host": """| json "EventData.DestinationHostname" as dst_host""",
        "dst_ip": """| json "EventData.DestinationIp" as dst_ip""",
        "dst_is_ipv6": """| json "EventData.DestinationIsIpv6" as dst_is_ipv6""",
        "dst_host": """| json "EventData.DestinationHostname" as dst_host""",
        "dst_port": """| json "EventData.DestinationPort" as dst_port""",
        "initiated": """| json "EventData.Initiated" as initiated""",
        "protocol": """| json "EventData.Protocol" as protocol""",
        "src_ip": """| json "EventData.SourceIp" as src_ip""",
        "src_port": """| json "EventData.SourcePort" as src_port"""
    },
    "sumologic_cip_driver_loaded_fieldmapping": {
        "image_loaded": """| json "EventData.ImageLoaded" as image_loaded""",
        "signature_status": """| json "EventData.SignatureStatus" as signature_status""",
        "signed": """| json "EventData.Signed" as signed"""
    },
    "sumologic_cip_image_loaded_fieldmapping": {
        "image_loaded": """| json "EventData.ImageLoaded" as image_loaded""",
        "orig_filename": """| json "EventData.OriginalFileName" as orig_filename""",
        "signature_status": """| json "EventData.SignatureStatus" as signature_status""",
        "signed": """| json "EventData.Signed" as signed""",
        "signature": """| json "EventData.Signature" as signature"""
    },
    "sumologic_cip_remote_thread_fieldmapping": {
        "src_process_guid": """| json "EventData.SourceProcessGuid" as src_process_guid""",
        "src_process_id": """| json "EventData.SourceProcessId" as src_process_id""",
        "src_image": """| json "EventData.SourceImage" as src_image""",
        "src_parent_image": """| json "EventData.SourceParentImage" as src_parent_image""",
        "target_process_guid": """| json "EventData.TargetProcessGuid" as target_process_guid""",
        "target_process_id": """| json "EventData.TargetProcessId" as target_process_id""",
        "target_parent_process_id": """| json "EventData.TargetParentProcessId" as target_parent_process_id""",
        "target_image": """| json "EventData.TargetImage" as target_image""",
        "new_thread_id": """| json "EventData.NewThreadId" as new_thread_id""",
        "start_address": """| json "EventData.StartAddress" as start_address""",
        "start_function": """| json "EventData.StartFunction" as start_function""",
        "start_module": """| json "EventData.StartModule" as start_module"""
    },
    "sumologic_cip_raw_access_thread_fieldmapping": {
        "device": """| json "EventData.Device" as device"""
    },
    "sumologic_cip_process_access_fieldmapping": {
        "src_process_guid": """| json "EventData.SourceProcessGuid" as src_process_guid""",
        "src_process_id": """| json "EventData.SourceProcessId" as src_process_id""",
        "src_thread_id": """| json "EventData.SourceThreadId" as src_thread_id""",
        "src_image": """| json "EventData.SourceImage" as src_image""",
        "target_process_guid": """| json "EventData.TargetProcessGuid" as target_process_guid""",
        "target_process_id": """| json "EventData.TargetProcessId" as target_process_id""",
        "target_image": """| json "EventData.TargetImage" as target_image""",
        "granted_access": """| json "EventData.GrantedAccess" as granted_access""",
        "call_trace": """| json "EventData.CallTrace" as call_trace"""
    },
    "sumologic_cip_file_event_fieldmapping": {
        "pipe_name": """| json "EventData.PipeName" as pipe_name""",
        "service_file_name": """| json "EventData.ServiceFileName" as service_file_name""",
        "service_name": """| json "EventData.ServiceName" as service_name""",
        "target_file_path": """| json "EventData.TargetFilename" as target_file_path"""
    },
    "sumologic_cip_registry_event_fieldmapping": {
        "reg_event_type": """| json "EventData.EventType" as reg_event_type""",
        "target_reg_object": """| json "EventData.TargetObject" as target_reg_object""",
        "reg_details": """| json "EventData.Details" as reg_details""",
        "new_name": """| json "EventData.NewName" as new_name""",
    },
    "sumologic_cip_file_create_stream_hash_fieldmapping": {
        "contents": """| json "EventData.Contents" as contents""",
        "target_file_path": """| json "EventData.TargetFilename" as target_file_path"""
    },
    "sumologic_cip_pipe_created_fieldmapping": {
        "pipe_name": """| json "EventData.PipeName" as pipe_name"""
    },
    "sumologic_cip_wmi_event_fieldmapping": {
        "wmi_event_type": """| json "EventData.EventType" as wmi_event_type""",
        "wmi_operation": """| json "EventData.Operation" as wmi_operation""",
        "wmi_event_namespace": """| json "EventData.EventNamespace" as wmi_event_namespace""",
        "wmi_object_name": """| json "EventData.Name" as wmi_object_name""",
        "wmi_query": """| json "EventData.Query" as wmi_query""",
        "wmi_type": """| json "EventData.Type" as wmi_type""",
        "wmi_dest": """| json "EventData.Destination" as wmi_dest""",
        "wmi_consumer": """| json "EventData.Consumer" as wmi_consumer""",
        "wmi_filter": """| json "EventData.Filter" as wmi_filter"""
    },
    "sumologic_cip_dns_query_fieldmapping": {
        "dns_query": """| json "EventData.QueryName" as dns_query""",
        "dns_query_answers": """| json "EventData.QueryResults" as dns_query_answers""",
        "query_status": """| json "EventData.QueryStatus" as query_status"""
    },
    "sumologic_cip_file_delete_fieldmapping": {
        "target_file_path": """| json "EventData.TargetFilename" as target_file_path""",
        "is_executable": """| json "EventData.IsExecutable" as is_executable""",
        "archived": """| json "EventData.Archived" as archived"""
    },
    "sumologic_cip_windows_security_fieldmapping": {
        "access_list": """| json "EventData.AccessList" as access_list""",
        "access_mask": """| json "EventData.AccessMask" as access_mask""",
        "accesses": """| json "EventData.Accesses" as accesses""",
        "allowed_to_delegate_to": """| json "EventData.AllowedToDelegateTo" as allowed_to_delegate_to""",
        "application_name": """| json "EventData.Application" as application_name""",
        "ldap_display_name": """| json "EventData.AttributeLDAPDisplayName" as ldap_display_name""",
        "attribute_value": """| json "EventData.AttributeValue" as attribute_value""",
        "audit_policy_changes": """| json "EventData.AuditPolicyChanges" as audit_policy_changes""",
        "audit_source_name": """| json "EventData.AuditSourceName" as audit_source_name""",
        "auth_package": """| json "EventData.AuthenticationPackageName" as auth_package""",
        "process_path": """| json "EventData.CallerProcessName" as process_path""",
        "cert_thumbprint": """| json "EventData.CertThumbprint" as cert_thumbprint""",
        "class_name": """| json "EventData.ClassName" as class_name""",
        "client_process_id": """| json "EventData.ClientProcessId" as client_process_id""",
        "dst_host": """| json "EventData.ComputerName" as dst_host""",
        "dst_ip": """| json "EventData.DestAddress" as dst_ip""",
        "dst_port": """| json "EventData.DestPort" as dst_port""",
        "device_description": """| json "EventData.DeviceDescription" as device_description""",
        "failure_code": """| json "EventData.Status" as failure_code""",
        "filter_origin": """| json "EventData.FilterOrigin" as filter_origin nodrop""",
        "impersonation_level": """| json "EventData.ImpersonationLevel" as impersonation_level""",
        "src_ip": """| json "EventData.IpAddress" as src_ip""",
        "key_length": """| json "EventData.KeyLength" as key_length""",
        "keywords": """| json "EventData.Keywords" as keywords""",
        "layer_rt_id": """| json "EventData.LayerRTID" as layer_rt_id""",
        "logon_process": """| json "EventData.LogonProcessName" as logon_process""",
        "logon_type": """| json "EventData.LogonType" as logon_type""",
        "new_dst_user": """| json "EventData.NewTargetUserName" as new_dst_user""",
        "new_template_content": """| json "EventData.NewTemplateContent" as new_template_content""",
        "new_uac_value": """| json "EventData.NewUacValue" as new_uac_value""",
        "new_value": """| json "EventData.NewValue" as new_value""",
        "object_class": """| json "EventData.ObjectClass" as object_class""",
        "object_name": """| json "EventData.ObjectName" as object_name""",
        "object_server": """| json "EventData.ObjectServer" as object_server""",
        "object_type": """| json "EventData.ObjectType" as object_type""",
        "object_value": """| json "EventData.ObjectValueName" as object_value""",
        "old_dst_user": """| json "EventData.OldTargetUserName" as old_dst_user""",
        "old_uac_user": """| json "EventData.OldUacValue" as old_uac_user""",
        "parent_process_id": """| json "EventData.ParentProcessId" as parent_process_id""",
        "password_last_set": """| json "EventData.PasswordLastSet" as password_last_set""",
        "privilege_list": """| json "EventData.PrivilegeList" as privilege_list""",
        "process_id": """| json "Execution.ProcessID" as process_id""",
        "process_path": """| json "EventData.ProcessName" as process_path""",
        "properties": """| json "EventData.Properties" as properties""",
        "relative_target_name": """| json "EventData.RelativeTargetName" as relative_target_name""",
        "dst_user": """| json "EventData.TargetUserName" as dst_user""",
        "service": """| json "EventData.Service" as service""",
        "service_file_name": """| json "EventData.ServiceFileName" as service_file_name""",
        "service_name": """| json "EventData.ServiceName" as service_name""",
        "service_principal_names": """| json "EventData.ServicePrincipalNames" as service_principal_names""",
        "service_start_type": """| json "EventData.ServiceStartType" as service_start_type""",
        "service_type": """| json "EventData.ServiceType" as service_type""",
        "share_name": """| json "EventData.ShareName" as share_name""",
        "sid_history": """| json "EventData.SidHistory" as sid_history""",
        "src_ip": """| json "EventData.SourceAddress" as src_ip""",
        "src_port": """| json "EventData.SourcePort" as src_port""",
        "status": """| json "EventData.Status" as status""",
        "src_user_domain": """| json "EventData.SubjectDomainName" as src_user_domain""",
        "src_logon_id": """| json "EventData.SubjectLogonId" as src_logon_id""",
        "src_user": """| json "EventData.SubjectUserName" as src_user""",
        "src_user_sid": """| json "EventData.SubjectUserSid" as src_user_sid""",
        "dst_logon_id": """| json "EventData.TargetLogonId" as dst_logon_id""",
        "target_name": """| json "EventData.TargetName" as target_name""",
        "target_outbound_user": """| json "EventData.TargetOutboundUserName" as target_outbound_user""",
        "dst_host": """| json "EventData.TargetServerName" as dst_host""",
        "dst_sid": """| json "EventData.TargetSid" as dst_sid""",
        "dst_user": """| json "EventData.TargetUserName" as dst_user""",
        "dst_user_sid": """| json "EventData.TargetUserSid" as dst_user_sid""",
        "task_content": """| json "EventData.TaskContent" as task_content""",
        "new_task_content": """| json "EventData.TaskContentNew" as new_task_content""",
        "task_name": """| json "EventData.TaskName" as task_name""",
        "template_content": """| json "EventData.TemplateContent" as template_content""",
        "ticket_encryption": """| json "EventData.TicketEncryptionType" as ticket_encryption""",
        "ticket_options": """| json "EventData.TicketOptions" as ticket_options""",
        "src_host": """| json "EventData.Workstation" as src_host""",
        "src_hostname": """| json "EventData.WorkstationName" as src_hostname"""
    },
    "sumologic_cip_windows_application_fieldmapping": {
        "app_name": """| json "EventData.Data[0]" as app_name""",
        "event_data": """| json "EventData.Data" as event_data | toString(event_data)""",
        "error_code": """| json "EventData.Data[6]" as error_code""",
        "severity": """| json "Level" as severity"""
    },
    "sumologic_cip_windows_system_fieldmapping": {
        "account_name": """| json "EventData.AccountName" as account_name""",
        "caption": """| json "EventData.Caption" as caption""",
        "device_name": """| json "EventData.DeviceName" as device_name""",
        "hive_name": """| json "EventData.HiveName" as hive_name""",
        "process_path": """| json "EventData.ImagePath" as process_path""",
        "severity": """| json "Level" as severity""",
        "origin": """| json "EventData.Origin" as origin""",
        "process_id": """| json "Execution.ProcessID" as process_id""",
        "service_name": """| json "EventData.ServiceName" as service_name""",
        "service_type": """| json "EventData.ServiceType" as service_type""",
        "service_start_type": """| json "EventData.ServiceStartType" as service_start_type""",
        "param_1": """| json "EventData.param1" as param_1""",
        "param_2": """| json "EventData.param2" as param_2""",
        "param_3": """| json "EventData.param3" as param_3"""
    },
    "sumologic_cip_windows_defender_fieldmapping": {
        "new_value": """| json "EventData.Data[3]" as new_value""",
        "old_value": """| json "EventData.Data[2]" as old_value""",
        "path": """| json "EventData.Data[6]" as path""",
        "process_name": """| json "EventData.Data[7]" as process_name""",
        "source_name": """| json "EventData.Data[17]" as source_name""",
        "value": """| json "EventData.Value" as value"""
    },
    "sumologic_cip_powershell_fieldmapping": {
        "context_info": """| json "EventData.ContextInfo" as context_info""",
        "engine_version": r"""| parse "EngineVersion=*\\r" as engine_version""",
        "host_application": """| parse "HostApplication=* " as host_application""",
        "host_name": r"""| parse "HostName=*\\r" as host_name""",
        "host_version": r"""| parse "HostVersion=*\\r" as host_version""",
        "payload": """| json "EventData.Payload" as payload""",
        "script_path": """| json "EventData.Path" as script_path""",
        "script_block": """| json "EventData.ScriptBlockText" as script_block"""
    },
    "sumologic_cip_alt_windows_fieldmapping": {
        "local_name": """| json "EventData.LocalName" as local_name""",
        "remote_name": """| json "EventData.RemoteName" as remote_name""",
        "bits_process_path": """| json "EventData.processPath" as process_path""",
        "filename_buffer": """| json "EventData.FileNameBuffer" as filename_buffer""",
        "process_name_buffer": """| json "EventData.ProcessNameBuffer" as process_name_buffer""",
        "requested_policy": """| json "EventData.RequestedPolicy" as requested_policy""",
        "validated_policy": """| json "EventData.ValidatedPolicy" as validated_policy""",
        "package_path": """| json "EventData.PackagePath" as package_path""",
        "query_name": """| json "EventData.QName" as query_name""",
        "action": """| json "EventData.Action" as action""",
        "application_path": """| json "EventData.ApplicationPath" as application_path""",
        "modifying_application": """| json "EventData.ModifyingApplication" as modifying_application""",
        "search_filter": """| json "EventData.SearchFilter" as search_filter""",
        "process_name": """| json "EventData.ProcessName" as process_name""",
        "workstation_name": """| json "EventData.WorkstationName" as workstation_name""",
        "target_name": """| json "EventData.TargetName" as target_name""",
        "process": """| json "EventData.process" as process""",
        "payload": """| json "EventData.payload" as payload""",
        "error_code": """| json "EventData.ErrorCode" as error_code""",
        "plugin_dll_name": """| json "EventData.PluginDllName" as plugin_dll_name""",
        "proces_path": """| json "EventData.ProcessPath" as process_path""",
        "image_name": """| json "EventData.ImageName" as image_name""",
        "app_id": """| json "EventData.AppID" as app_id""",
        "app_name": """| json "EventData.AppID" as app_name""", 
        "smb_src_user": """| json "EventData.UserName" as smb_src_user""",
        "smb_server_name": """| json "EventData.ServerName" as smb_server_name""",
        "smb_share_name": """| json "EventData.ShareName" as smb_share_name""",
        "schtask_name": """| json "EventData.TaskName" as schtask_name""",
        "schtask_path": """| json "EventData.Path" as schtask_path""",
        "address": """| json "EventData.Address" as address""",
        "wmi_event_provider": """| json "EventData.Provider" as wmi_event_provider""",
        "wmi_query": """| json "EventData.Query" as wmi_query""",
        "wmi_user": """| json "EventData.User" as wmi_user""",
        "possible_cause": """| json "EventData.PossibleCause" as possible_cause"""
    },
    "sumologic_cip_aws_fieldmapping": {
        "error_code": """| json "errorCode" as error_code""",
        "error_msg": """| json "errorMessage" as error_msg""",
        "event_name": """| json "eventName" as event_name""",
        "event_source": """| json "eventSource" as event_source""",
        "event_type": """| json "eventType" as event_type""",
        "request_attribute": """| json "requestParameters.attribute" as request_attribute""",
        "container_command": """| json "requestParameters.containerDefinitions.command" as container_command | toString(container_command)""",
        "src_user": """| json "requestParameters.userName" as src_user""",
        "resp_elements": """| json "responseElements" as resp_elements | toString(resp_elements)""",
        "dst_user": """| json "responseElements.accessKey.userName" as dst_user""",
        "master_user_password": """| json "responseElements.pendingModifiedValues.masterUserPassword" as master_user_password""",
        "publicly_accessible": """| json "responseElements.publiclyAccessible" as publicly_accessible""",
        "src_ip": """| json "sourceIPAddress" as src_ip""",
        "user_arn": """| json "userIdentity.arn" as user_arn""",
        "session_issuer_type": """| json "userIdentity.sessionContext.sessionIssuer.type" as session_issuer_type""",
        "user_type": """| json "userIdentity.type" as user_type"""
    },
    "sumologic_cip_azure_fieldmapping": {
        "activity_details": """| json "operationName" as activity_details | if(activity_details = "Sign-in activity", "Sign-ins", "") as activity_details""",
        "activity_display_name": """| json "properties.activityDisplayName" as activity_display_name""",
        "activity_type": """| json "operationName" as activity_type | if(activity_type in ("Reset password (self-service)", "Reset user password"), "Password reset", "") as activity_type""",
        "app_id": """| json "properties.appId" as app_id""",
        "auth_requirement": """| json "properties.authenticationRequirement" as auth_requirement""",
        "category": """| json "properties.category" as category""",
        "category_value": """| json "category" as category_value""",
        "client_app": """| json "properties.targetResources[0].modifiedProperties[0].displayName", "properties.targetResources[0].modifiedProperties[0].newValue" as modified_property, new_val | if(modified_property = "ConsentContext.IsAdminConsent", "admin_consent", "nothing") as tmp | if(new_val = "False" and tmp = "admin_consent", "false", "N/A") as is_admin_consent""",
        "admin_consent": """| json "ConsentContext.IsAdminConsent" as admin_consent""",
        "count": """| json "Count" as count""",
        "device_id": """| json "properties.deviceDetail.deviceId" as deviceId""",
        "device_compliant": """| json "properties.deviceDetail.isCompliant" as device_compliant""",
        "home_tenant_id": """| json "properties.homeTenantId" as home_tenant_id""",
        "initiated_by": """| json "properties.initiatedBy.userPrincipalName" as initiated_by""",
        "location": """| json "properties.location" as location | toString(location)""",
        "logged_by_service": """| json "properties.loggedByService" as logged_by_service""",
        "network_location": """| json "properties.networkLocationDetails" as network_location | toString(network_location)""",
        "operation_name": """| json "operationName" as operation_name""",
        "resource_display_name": """| json "properties.resourceDisplayName" as resource_display_name""",
        "resource_id": """| json "properties.resourceId" as resource_id""",
        "resource_tenant_id": """| json "properties.resourceTenantId" as resource_tenant_id""",
        "result_description": """| json "resultDescription" as result_description""",
        "result": """| json "resultType" as result""",
        "status": """| json "properties.status.errorCode" as status | if(status = 0, "Success", "Failure") as status""",
        "target": """| json "properties.target" as target""",
        "target_resources": """| json "properties.targetResources" as target_resources | toString(target_resources)""",
        "username": """| json "properties.userPrincipalName" as dst_user""",
        "src_user": """| json "Username" as src_user""",
        "workload": """| json "Workload" as workload""",
        "conditional_access_status": """| json "properties.conditionalAccessStatus" as conditional_access_status""",
        "operation_name": """| json "Operation" as operation_name""",
        "user_agent": """| json "properties.userAgent" as user_agent"""
    },
    "sumologic_cip_gcp_fieldmapping": {
        "method_name": """| json "message.data.protoPayload.methodName" as method_name"""
    },
    "sumologic_cip_gworkspace_fieldmapping": {
        "event_name": r"""| json "events" as events | parse regex field=events "\"name\"\:\"(?<event_name>.*?)\".*?\]" nodrop""",
        "event_service": r"""| "admin.googleapis.com" as event_service""",
        "new_value": """| json "events" as events | parse regex field=events "\"NEW_VALUE\"\,\"value\"\:\"(?<new_value>.*?)\".\]"""
    },
    "sumologic_cip_m365_fieldmapping": {
        "operation": """| json "Operation" as operation""",
        "event_name": """| json "Name" as event_name""",
        "event_service": """| json "Workload" as event_service""",
        "result": """| json "ResultStatus" as result"""
    },
    "sumologic_cip_okta_fieldmapping": {
        "display_message": """| json "displayMessage" as display_message""",
        "event_type": """| json "eventType" as event_type"""
    },
    "sumologic_cip_onelogin_fieldmapping": {
        "event_id": """| json "event.event_type_id" as event_id"""
    },
    "sumologic_cip_linux_sysmon_fieldmapping": {
        "command_line": """| json "EventData.CommandLine" as command_line""",
        "current_directory": """| json "EventData.CurrentDirectory" as current_directory""",
        "dst_host": """| json "EventData.DestinationHostname" as dst_host""",
        "dst_ip": """| json "EventData.DestinationIp" as dst_ip""",
        "process_path": """| json "EventData.Image" as process_path""",
        "src_logon_id": """| json "EventData.LogonId" as src_logon_id""",
        "parent_command_line": """| json "EventData.ParentCommandLine" as parent_command_line""",
        "parent_process_path": """| json "EventData.ParentImage" as parent_process_path""",
        "target_filename": """| json "EventData.TargetFilename" as target_filename""",
        "src_user": """| json "EventData.User" as src_user"""
    },
    "sumologic_cip_linux_fieldmapping": {
        "event_id": """| json "EventID" as event_id""",
        "src_user": """| parse "USER=* " as src_user""",
        "cmd_arg_1": r"""| parse "a0=\"*\" " as cmd_arg_1""",
        "cmd_arg_2": r"""| parse "a1=\"*\" " as cmd_arg_2""",
        "cmd_arg_3": r"""| parse "a2=\"*\" " as cmd_arg_3""",
        "cmd_arg_4": r"""| parse "a3=\"*\" " as cmd_arg_4""",
        "cmd_arg_5": r"""| parse "a4=\"*\" " as cmd_arg_5""",
        "cmd_arg_6": r"""| parse "a5=\"*\" " as cmd_arg_6""",
        "cmd_arg_7": r"""| parse "a6=\"*\" " as cmd_arg_7""",
        "cmd_arg_8": r"""| parse "a7=\"*\" " as cmd_arg_8""",
        "cmd_arg_9": r"""| parse "a8=\"*\" " as cmd_arg_9""",
        "cmd_arg_10": r"""| parse "a9=\"*\" " as cmd_arg_10""",
        "process_name": r"""| parse "comm=\"*\" " as process_name""",
        "current_directory": r"""| parse "cwd=\"*\" " as current_directory""",
        "process_exe_path": r"""| parse "exe=\"*\" " as process_exe_path""",
        "log_key": r"""| parse "key=\"*\" " as log_key""",
        "file_name": r"""| parse "name=\"*\" " as file_name""",
        "name_type": r"""| parse "nametype=* " as name_type""",
        "pam_result": r"""| parse ":auth): *;" as pam_result""",
        "dst_host": r"""| parse regex \"\S*\s+\d+\s+\d+:\d+:\d+\s+(?<dst_host>\S*)\"""",
        "src_user_pam": """| parse "user=* " as src_user""",
        "proc_title": r"""| parse "proctitle=*" as proc_title nodrop | hexToAscii(proc_title)""",
        "sys_call": """| parse "syscall=* " as sys_call""",
        "event_type": """| parse "type=* " as event_type""",
        "src_user_id": """| parse "uid=* " as src_user_id""",
        "service_name": """| parse "unit=* " as service_name"""
    },
    "sumologic_cip_dns_fieldmapping": {
        "": ""
    },
    "sumologic_cip_proxy_fieldmapping": {
        "": ""
    },
    "sumologic_webserver_fieldmapping": {
        "": ""
    }
}
