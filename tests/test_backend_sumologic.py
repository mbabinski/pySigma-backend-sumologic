import pytest
from sigma.collection import SigmaCollection
from sigma.backends.sumologic import sumologicBackend

@pytest.fixture
def sumologic_backend():
    return sumologicBackend()

# TODO: implement tests for some basic queries and their expected results.
def test_sumologic_and_expression(sumologic_backend : sumologicBackend):
    assert sumologic_backend.convert(
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
    ) == ['<insert expected result here>']

def test_sumologic_or_expression(sumologic_backend : sumologicBackend):
    assert sumologic_backend.convert(
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
    ) == ['<insert expected result here>']

def test_sumologic_and_or_expression(sumologic_backend : sumologicBackend):
    assert sumologic_backend.convert(
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
    ) == ['<insert expected result here>']

def test_sumologic_or_and_expression(sumologic_backend : sumologicBackend):
    assert sumologic_backend.convert(
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
    ) == ['<insert expected result here>']

def test_sumologic_in_expression(sumologic_backend : sumologicBackend):
    assert sumologic_backend.convert(
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
                        - valueC*
                condition: sel
        """)
    ) == ['<insert expected result here>']

def test_sumologic_regex_query(sumologic_backend : sumologicBackend):
    assert sumologic_backend.convert(
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
    ) == ['<insert expected result here>']

def test_sumologic_cidr_query(sumologic_backend : sumologicBackend):
    assert sumologic_backend.convert(
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
    ) == ['<insert expected result here>']

def test_sumologic_field_name_with_whitespace(sumologic_backend : sumologicBackend):
    assert sumologic_backend.convert(
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
    ) == ['<insert expected result here>']

# TODO: implement tests for all backend features that don't belong to the base class defaults, e.g. features that were
# implemented with custom code, deferred expressions etc.



def test_sumologic_logsearch_output(sumologic_backend : sumologicBackend):
    """Test for output format logsearch."""
    # TODO: implement a test for the output format
    pass

def test_sumologic_cse_query_output(sumologic_backend : sumologicBackend):
    """Test for output format cse_query."""
    # TODO: implement a test for the output format
    pass


