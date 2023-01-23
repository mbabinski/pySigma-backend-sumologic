import pytest, json
from sigma.collection import SigmaCollection
from sigma.backends.sumologic import sumologicCIPBackend, sumologicCSEBackend
from sigma.processing.transformations import DetectionItemFailureTransformation
from sigma.exceptions import SigmaTransformationError

@pytest.fixture
def sumologic_cip_backend():
    return sumologicCIPBackend()

@pytest.fixture
def sumologic_cse_backend():
    return sumologicCSEBackend()

def test_sumologic_cip_and_expression(sumologic_cip_backend : sumologicCIPBackend):
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    ) == ["""//Category and Keyword Definition
_sourceCategory=/test_category/test_product

//Selection Query
| where toLowerCase(fieldA) = "valuea" AND toLowerCase(fieldB) = "valueb"

//Display Fields
| fields fieldA, fieldB"""]

def test_sumologic_cse_and_expression(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    ) == ["""lower(fieldA) = 'valuea' AND lower(fieldB) = 'valueb'"""]

def test_sumologic_cip_compare_op_expression(sumologic_cip_backend : sumologicCIPBackend):
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field1|lt: 100
                    field2|gt: 0
                    field3|gte: 20
                    field4|lte: 40
                condition: sel
        """)
    ) == ["""//Category and Keyword Definition
_sourceCategory=/test_category/test_product

//Selection Query
| where field1 < 100 AND field2 > 0 AND field3 >= 20 AND field4 <= 40

//Display Fields
| fields field1, field2, field3, field4"""]

def test_sumologic_cse_compare_op_expression(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field1|lt: 100
                    field2|gt: 0
                    field3|gte: 20
                    field4|lte: 40
                condition: sel
        """)
    ) == ["""field1 < 100 AND field2 > 0 AND field3 >= 20 AND field4 <= 40"""]

def test_sumologic_cip_or_expression(sumologic_cip_backend : sumologicCIPBackend):
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    ) == ["""//Category and Keyword Definition
_sourceCategory=/test_category/test_product

//Selection Query
| where toLowerCase(fieldA) = "valuea" OR toLowerCase(fieldB) = "valueb"

//Display Fields
| fields fieldA, fieldB"""]

def test_sumologic_cse_or_expression(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    ) == ["""lower(fieldA) = 'valuea' OR lower(fieldB) = 'valueb'"""]

def test_sumologic_cip_and_or_expression(sumologic_cip_backend : sumologicCIPBackend):
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ["""//Category and Keyword Definition
_sourceCategory=/test_category/test_product

//Selection Query
| where (toLowerCase(fieldA) in ("valuea1", "valuea2")) AND (toLowerCase(fieldB) in ("valueb1", "valueb2"))

//Display Fields
| fields fieldA, fieldB"""]

def test_sumologic_cse_and_or_expression(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ["""lower(fieldA) IN ('valuea1', 'valuea2') AND lower(fieldB) IN ('valueb1', 'valueb2')"""]

def test_sumologic_cip_or_and_expression(sumologic_cip_backend : sumologicCIPBackend):
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """)
    ) == ["""//Category and Keyword Definition
_sourceCategory=/test_category/test_product

//Selection Query
| where toLowerCase(fieldA) = "valuea1" AND toLowerCase(fieldB) = "valueb1" OR toLowerCase(fieldA) = "valuea2" AND toLowerCase(fieldB) = "valueb2"

//Display Fields
| fields fieldA, fieldB"""]

def test_sumologic_cse_or_and_expression(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """)
    ) == ["""lower(fieldA) = 'valuea1' AND lower(fieldB) = 'valueb1' OR lower(fieldA) = 'valuea2' AND lower(fieldB) = 'valueb2'"""]

def test_sumologic_cip_in_expression(sumologic_cip_backend : sumologicCIPBackend):
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC
                condition: sel
        """)
    ) == ["""//Category and Keyword Definition
_sourceCategory=/test_category/test_product

//Selection Query
| where toLowerCase(fieldA) in ("valuea", "valueb", "valuec")

//Display Fields
| fields fieldA"""]

def test_sumologic_cse_in_expression(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC
                condition: sel
        """)
    ) == ["""lower(fieldA) IN ('valuea', 'valueb', 'valuec')"""]

def test_sumologic_cip_regex_query(sumologic_cip_backend : sumologicCIPBackend):
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    ) == ["""//Category and Keyword Definition
_sourceCategory=/test_category/test_product

//Selection Query
| where fieldA matches /foo.*bar/i AND toLowerCase(fieldB) = "foo"

//Display Fields
| fields fieldA, fieldB"""]

def test_sumologic_cse_regex_query(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    ) == ["""lower(fieldA) RLIKE 'foo.*bar' AND lower(fieldB) = 'foo'"""]

def test_sumologic_cip_cidr_query(sumologic_cip_backend : sumologicCIPBackend):
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ["""//Category and Keyword Definition
_sourceCategory=/test_category/test_product

//Selection Query
| where compareCIDRPrefix(field, "192.168.0.0", "16")

//Display Fields
| fields field"""]

def test_sumologic_cse_cidr_query(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ["""compareCIDRPrefix(field, '192.168.0.0', '16')"""]

def test_sumologic_cip_null_value_query(sumologic_cip_backend : sumologicCIPBackend):
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field1: null
                condition: sel
        """)
    ) == ["""//Category and Keyword Definition
_sourceCategory=/test_category/test_product

//Selection Query
| where isNull(field1)

//Display Fields
| fields field1"""]

def test_sumologic_cse_null_value_query(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field1: null
                condition: sel
        """)
    ) == ["""isNull(field1)"""]

def test_sumologic_cip_field_name_with_whitespace(sumologic_cip_backend : sumologicCIPBackend):
    with pytest.raises(SigmaTransformationError, match="The SumoLogic backend does not permit spaces in field names."):
        sumologic_cip_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        field name: value
                    condition: sel
            """)
        )

def test_sumologic_cse_field_name_with_whitespace_fail(sumologic_cse_backend : sumologicCSEBackend):
    with pytest.raises(SigmaTransformationError, match="The SumoLogic backend does not permit spaces in field names."):
        sumologic_cse_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        field name: value
                    condition: sel
            """)
        )

def test_sumologic_cse_field_name_with_whitespace_success(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fields['Test Field']: test
                condition: sel
        """)
    ) == ["""lower(fields['Test Field']) = 'test'"""]

def test_sumologic_cip_contains_query(sumologic_cip_backend : sumologicCIPBackend):
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field1|contains: valA
                condition: sel
        """)
    ) == ["""//Category and Keyword Definition
_sourceCategory=/test_category/test_product

//Selection Query
| where toLowerCase(field1) matches "*vala*"

//Display Fields
| fields field1"""]

def test_sumologic_cse_contains_query(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field1|contains: valA
                condition: sel
        """)
    ) == ["""lower(field1) LIKE '%vala%'"""]

def test_sumologic_cip_contains_any_query(sumologic_cip_backend : sumologicCIPBackend):
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field1|contains:
                        - val1
                        - val2
                        - val3
                condition: sel
        """)
    ) == ["""//Category and Keyword Definition
_sourceCategory=/test_category/test_product

//Selection Query
| where field1 matches /^.*(val1|val2|val3).*$/i

//Display Fields
| fields field1"""]

def test_sumologic_cse_contains_any_query(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field1|contains:
                        - val1
                        - val2
                        - val3
                condition: sel
        """)
    ) == ["""lower(field1) RLIKE '^.*(val1|val2|val3).*$'"""]

def test_sumologic_cip_contains_all_query(sumologic_cip_backend : sumologicCIPBackend):
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field1|contains|all:
                        - val1
                        - val2
                        - val3
                condition: sel
        """)
    ) == ["""//Category and Keyword Definition
_sourceCategory=/test_category/test_product

//Selection Query
| where field1 matches /^.*(?=.*val1)(?=.*val2)(?=.*val3).*$/i

//Display Fields
| fields field1"""]

def test_sumologic_cse_contains_all_query(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field1|contains|all:
                        - val1
                        - val2
                        - val3
                condition: sel
        """)
    ) == ["""lower(field1) RLIKE '^.*(?=.*val1)(?=.*val2)(?=.*val3).*$'"""]

def test_sumologic_cip_startswith_query(sumologic_cip_backend : sumologicCIPBackend):
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field1|startswith: valueA
                condition: sel
        """)
    ) == ["""//Category and Keyword Definition
_sourceCategory=/test_category/test_product

//Selection Query
| where toLowerCase(field1) matches "valuea*"

//Display Fields
| fields field1"""]

def test_sumologic_cse_startswith_query(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field1|startswith: valueA
                condition: sel
        """)
    ) == ["""lower(field1) LIKE 'valuea%'"""]

def test_sumologic_cip_startswith_any_query(sumologic_cip_backend : sumologicCIPBackend):
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field1|startswith:
                        - val1
                        - val2
                        - val3
                condition: sel
        """)
    ) == ["""//Category and Keyword Definition
_sourceCategory=/test_category/test_product

//Selection Query
| where field1 matches /^(val1|val2|val3).*$/i

//Display Fields
| fields field1"""]

def test_sumologic_cse_startswith_any_query(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field1|startswith:
                        - val1
                        - val2
                        - val3
                condition: sel
        """)
    ) == ["""lower(field1) RLIKE '^(val1|val2|val3).*$'"""]

def test_sumologic_cip_endswith_query(sumologic_cip_backend : sumologicCIPBackend):
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field1|endswith: valueA
                condition: sel
        """)
    ) == ["""//Category and Keyword Definition
_sourceCategory=/test_category/test_product

//Selection Query
| where toLowerCase(field1) matches "*valuea"

//Display Fields
| fields field1"""]

def test_sumologic_cse_endswith_query(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field1|endswith: valueA
                condition: sel
        """)
    ) == ["""lower(field1) LIKE '%valuea'"""]

def test_sumologic_cip_endswith_any_query(sumologic_cip_backend : sumologicCIPBackend):
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field1|endswith:
                        - val1
                        - val2
                        - val3
                condition: sel
        """)
    ) == ["""//Category and Keyword Definition
_sourceCategory=/test_category/test_product

//Selection Query
| where field1 matches /^.*(val1|val2|val3)$/i

//Display Fields
| fields field1"""]

def test_sumologic_cse_endswith_any_query(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field1|endswith:
                        - val1
                        - val2
                        - val3
                condition: sel
        """)
    ) == ["""lower(field1) RLIKE '^.*(val1|val2|val3)$'"""]

def test_sumologic_cip_windash_expression(sumologic_cip_backend : sumologicCIPBackend):
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml("""
        title: Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                field1|windash: '/a'
            condition: sel
        """)
    ) == ["""//Category and Keyword Definition
_sourceCategory=/test_category/test_product

//Selection Query
| where toLowerCase(field1) = "-a" OR toLowerCase(field1) = "/a"

//Display Fields
| fields field1"""]

def test_sumologic_cse_windash_expression(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
        title: Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                field1|windash: '/a'
            condition: sel
        """)
    ) == ["""lower(field1) = '-a' OR lower(field1) = '/a'"""]

def test_sumologic_cip_base64_expression(sumologic_cip_backend : sumologicCIPBackend):
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml("""
        title: Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                field1|base64: 'Malcolm'
            condition: sel
        """)
    ) == ["""//Category and Keyword Definition
_sourceCategory=/test_category/test_product

//Selection Query
| where toLowerCase(field1) = "twfsy29sbq=="

//Display Fields
| fields field1"""]

def test_sumologic_cse_base64_expression(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
        title: Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                field1|base64: 'Malcolm'
            condition: sel
        """)
    ) == ["""lower(field1) = 'twfsy29sbq=='"""]

def test_sumologic_cip_base64offset_expression(sumologic_cip_backend : sumologicCIPBackend):
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml("""
        title: Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                field1|base64offset: 'Portland, OR'
            condition: sel
        """)
    ) == ["""//Category and Keyword Definition
_sourceCategory=/test_category/test_product

//Selection Query
| where toLowerCase(field1) = "ug9ydgxhbmqsie9s" OR toLowerCase(field1) = "bvcnrsyw5klcbpu" OR toLowerCase(field1) = "qb3j0bgfuzcwgt1"

//Display Fields
| fields field1"""]

def test_sumologic_cse_base64offset_expression(sumologic_cse_backend : sumologicCSEBackend):
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
        title: Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                field1|base64offset: 'Portland, OR'
            condition: sel
        """)
    ) == ["""lower(field1) = 'ug9ydgxhbmqsie9s' OR lower(field1) = 'bvcnrsyw5klcbpu' OR lower(field1) = 'qb3j0bgfuzcwgt1'"""]

def test_sumologic_saved_search_output(sumologic_cip_backend : sumologicCIPBackend):
    """Test for CIP saved search output format."""
    assert sumologic_cip_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """),
        output_format = "saved_search"
    ) == ['{\n    "type": "SavedSearchWithScheduleSyncDefinition",\n    "name": "Test",\n    "search": {\n        "queryText": "//Category and Keyword Definition\\n_sourceCategory=/test_category/test_product\\n\\n//Selection Query\\n| where toLowerCase(fieldA) = \\"valuea\\" AND toLowerCase(fieldB) = \\"valueb\\"\\n\\n//Display Fields\\n| fields fieldA, fieldB",\n        "defaultTimeRange": "Last 60 Minutes",\n        "byReceiptTime": false,\n        "viewName": "",\n        "viewStartTime": "1970-01-01T00:00:00Z",\n        "queryParameters": [],\n        "parsingMode": "AutoParse"\n    },\n    "searchSchedule": null,\n    "description": ""\n}']

def test_sumologic_cse_query_output(sumologic_cse_backend : sumologicCSEBackend):
    """Test for CSE cse_query output format."""
    assert sumologic_cse_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """),
        output_format = "cse_rule"
    ) == ['{\n    "assetField": "device_hostname",\n    "category": "Unknown/Other",\n    "descriptionExpression": "",\n    "enabled": true,\n    "entitySelectors": [\n        {\n            "entityType": "_hostname",\n            "expression": "device_hostname"\n        }\n    ],\n    "expression": "lower(fieldA) = \'valuea\' AND lower(fieldB) = \'valueb\'",\n    "isPrototype": true,\n    "name": "Test",\n    "nameExpression": "Test",\n    "ruleType": "match",\n    "scoreMapping": {\n        "default": 0,\n        "field": null,\n        "mapping": null,\n        "type": "constant"\n    },\n    "summaryExpression": "",\n    "stream": "record",\n    "tags": [\n        "test_product",\n        "test_category"\n    ]\n}']
