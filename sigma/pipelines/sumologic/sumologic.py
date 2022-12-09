from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.processing.transformations import ChangeLogsourceTransformation, AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.pipelines.common import logsource_windows_network_connection,logsource_windows_network_connection_initiated, logsource_windows_process_creation, logsource_windows_dns_query

# TODO: the following code is just an example extend/adapt as required.
# See https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html for further documentation.

def logsource_windows_security() -> LogsourceCondition:
    return LogsourceCondition(
        product="windows",
        service="security"
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

def sumologic_cip_pipeline() -> ProcessingPipeline:      # Processing pipelines should be defined as functions that return a ProcessingPipeline object.
    return ProcessingPipeline(
        name="Generic Log Sources to SumoLogic CIP Transformation",
        priority=10,
        items=[
            # Process Creation field mapping
            ProcessingItem(
                identifier="sumologic_cip_process_creation_fieldmapping",
                transformation=FieldMappingTransformation({
                    "ProcessId": "process_pid",
                    "Image": "process_path",
                    "CommandLine": "command_line",
                    "User": "src_user",
                    "ParentProcessId": "parent_process_pid",
                    "ParentImage": "parent_process_path",
                    "ParentCommandLine": "parent_command_line",
                    "ParentUser": "parent_process_user",
                    "md5": "process_hash_md5",
                    "sha1": "process_hash_sha1",
                    "sha256": "process_hash_sha256"
                }),
                rule_conditions=[
                    logsource_windows_process_creation(),
                ]
            )
        ]
    )
