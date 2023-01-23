import pytest
from sigma.collection import SigmaCollection
from sigma.backends.sumologic import sumologicCIPBackend, sumologicCSEBackend

@pytest.fixture
def sumologic_cip_backend():
    return sumologicCIPBackend()

@pytest.fixture
def sumologic_cse_backend():
    return sumologicCSEBackend()

def test_sumologic_cip_av_fieldmapping(sumologic_cip_backend : sumologicCIPBackend):
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: antivirus
            detection:
                sel:
                    Computer: 'My Computer'
                    Signature: 'Ransomware Detected'
                condition: sel
        """)
    ) == ["""//Category and Keyword Definition
_sourceCategory=/antivirus

//Selection Query
| where toLowerCase(src_host) = "my computer" AND toLowerCase(signature) = "ransomware detected"

//Display Fields
| fields signature, src_host"""]

def test_sumologic_cse_av_fieldmapping(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: antivirus
            detection:
                sel:
                    Computer: 'My Computer'
                    Signature: 'Ransomware Detected'
                condition: sel
        """)
    ) == ["""lower(device_hostname) = 'my computer' AND lower(threat_name) = 'ransomware detected'"""]

def test_sumologic_cip_windows_generic_fieldmapping(sumologic_cip_backend : sumologicCIPBackend):
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                product: windows
            detection:
                sel:
                    EventID: 1000
                    Channel: Test
                condition: sel
        """)
    ) == ["""//Category and Keyword Definition
_sourceCategory=/os/windows

//Parsing Statements
| json "Channel" as event_type
| json "EventID" as event_id

//Selection Query
| where event_id = 1000 AND toLowerCase(event_type) = "test"

//Display Fields
| fields event_id, event_type"""]

def test_sumologic_cse_windows_generic_fieldmapping(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                product: windows
            detection:
                sel:
                    EventID: 1000
                    Channel: Test
                condition: sel
        """)
    ) == ["""lower(metadata_vendor) = 'microsoft' AND lower(metadata_product) = 'windows' AND fields['EventID'] = 1000 AND lower(fields['Channel']) = 'test'"""]

def test_sumologic_cip_winsysmon_generic_fieldmapping(sumologic_cip_backend : sumologicCIPBackend):
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image|endswith: '\cmd.exe'
                    ComputerName: AcmeDC-01
                condition: sel
        """)
    ) == [r"""//Category and Keyword Definition
_sourceCategory=/os/windows/sysmon

//Parsing Statements
| json "Computer" as src_host
| json "EventData.Image" as process_path
| json "EventID" as event_id

//Selection Query
| where event_id = 1 AND toLowerCase(process_path) matches "*\\cmd.exe" AND toLowerCase(src_host) = "acmedc-01"

//Display Fields
| fields event_id, process_path, src_host"""]

def test_sumologic_cse_winsysmon_generic_fieldmapping(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image|endswith: '\cmd.exe'
                    ComputerName: AcmeDC-01
                condition: sel
        """)
    ) == [r"""fields['EventID'] = 1 AND lower(metadata_vendor) = 'microsoft' AND lower(metadata_product) = 'windows' AND lower(baseImage) LIKE '%\cmd.exe' AND lower(device_hostname) = 'acmedc-01'"""]
