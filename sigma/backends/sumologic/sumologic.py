import sigma
import re
import json
import sqlparse
from sigma.rule import SigmaRule, SigmaDetectionItem
from sigma.conversion.state import ConversionState
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression, ConditionValueExpression
from sigma.types import SigmaCompareExpression, SigmaString, SigmaNumber
from sigma.processing.pipeline import ProcessingPipeline
from sigma.pipelines.sumologic import sumologic_cip_pipeline, sumologic_cse_pipeline
from sigma.conversion.deferred import DeferredQueryExpression, DeferredTextQueryExpression
from typing import ClassVar, Dict, Tuple, Pattern, List, Any, Union
from sigma.backends.sumologic.parsing import parsing_statement_config

class SumoLogicSingleDeferredKeywordExpression(DeferredTextQueryExpression):
    template = '{op}"{value}"'
    operators = {
        True: "NOT ",
        False: "",
    }

    def finalize_expression(self) -> str:
        return self.template.format(op=self.operators[self.negated], value=self.value)

class SumoLogicMultiDeferredKeywordExpression(DeferredTextQueryExpression):
    template = '{op}{value}'
    operators = {
        True: "NOT ",
        False: "",
    }

    def finalize_expression(self) -> str:
        return self.template.format(op=self.operators[self.negated], value=self.value)

class sumologicCIPBackend(TextQueryBackend):
    """SumoLogic CIP Backend."""

    # add pipeline
    backend_processing_pipeline : ClassVar[ProcessingPipeline] = sumologic_cip_pipeline()

    # TOKEN DEFINITIONS

    # backend name
    name : ClassVar[str] = "Sumologic CIP Backend"

    # order of precedence
    precedence : ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    
    # grouping convention
    group_expression : ClassVar[str] = "({expr})"   # Expression for precedence override grouping as format string with {expr} placeholder

    # query tokens
    token_separator : str = " "     # separator inserted between all boolean operators
    or_token : ClassVar[str] = "OR"
    and_token : ClassVar[str] = "AND"
    not_token : ClassVar[str] = "!"
    keyword_not_token : ClassVar[str] = "NOT"
    not_eq_token : ClassVar[str] = "!="
    eq_token : ClassVar[str] = "="  # Token inserted between field and value (without separator)
    matches : ClassVar[str] = "matches"

    # field quoting definition
    field_quote : ClassVar[str] = "'"                               # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote_pattern : ClassVar[Pattern] = re.compile("^\\w+$")   # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation : ClassVar[bool] = True            # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).

    # escaping definition
    field_escape : ClassVar[str] = "\\"               # Character to escape particular parts defined in field_escape_pattern.
    field_escape_quote : ClassVar[bool] = True        # Escape quote string defined in field_quote
    field_escape_pattern : ClassVar[Pattern] = re.compile("\\s")   # All matches of this pattern are prepended with the string contained in field_escape.

    # to lower case expression (to make outputs case insensitive)
    to_lower_case_expression : ClassVar[str] = "toLowerCase({field})"

    # value definitions
    str_double_quote : ClassVar[str] = '"'
    str_single_quote : ClassVar[str] = "'"
    str_triple_quote : ClassVar[str] = '"""'
    str_quote       : ClassVar[str] = '"'     # string quoting character (added as escaping character)
    escape_char     : ClassVar[str] = "\\"    # Escaping character for special characrers inside string
    wildcard_multi  : ClassVar[str] = "*"     # Character used as multi-character wildcard
    wildcard_single : ClassVar[str] = "*"     # Character used as single-character wildcard
    wildcard_default : ClassVar[str] = "*"
    add_escaped     : ClassVar[str] = "\\"    # Characters quoted in addition to wildcards and string quote
    filter_chars    : ClassVar[str] = ""      # Characters filtered
    bool_values     : ClassVar[Dict[bool, str]] = {   # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    # regular expression definitions
    re_expression : ClassVar[str] = "{field} matches /{regex}/i"  # Regular expression query as format string with placeholders {field} and {regex}
    re_escape_char : ClassVar[str] = "\\"               # Character used for escaping in regular expressions
    re_escape : ClassVar[Tuple[str]] = ('"', '/')               # List of strings that are escaped

    # cidr expressions
    cidr_wildcard : ClassVar[str] = "*"    # Character used as single wildcard
    cidr_expression : ClassVar[str] = "compareCIDRPrefix({field}, {addr}, {prefix_length})"    # CIDR expression query as format string with placeholders {field} = {value}
    cidr_in_list_expression : ClassVar[str] = "{field} in ({value})"    # CIDR expression query as format string with placeholders {field} = in({list})

    # numeric comparison operators
    compare_op_expression : ClassVar[str] = "{field} {operator} {value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    # null, blank, and empty expressions
    field_null_expression : ClassVar[str] = "isNull({field})" # value is null
    field_blank_expression : ClassVar[str] = "isBlank({field})" # value is null, empty, or contains only whitespace characters
    field_empty_expression : ClassVar[str] = "isEmpty({field})" # value is an empty string containing no characters or whitespace

    # field value in list
    convert_or_as_in : ClassVar[bool] = True                     # Convert OR as in-expression
    convert_and_as_in : ClassVar[bool] = True                    # Convert AND as in-expression
    in_expressions_allow_wildcards : ClassVar[bool] = True       # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    field_in_list_expression : ClassVar[str] = "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    or_in_operator : ClassVar[str] = "in"               # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    list_separator : ClassVar[str] = ", "               # List element separator

    # not equals expression
    not_expression : ClassVar[str] = "!{expression}"
    keyword_not_expression : ClassVar[str] = "NOT ({expression})"

    # keyword search expressions
    unbound_value_str_expression : ClassVar[str] = "{value}"   # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression : ClassVar[str] = "{value}"   # Expression for number value not bound to a field as format string with placeholder {value}
    
    def get_quote_type(self, val):
        """Returns the shortest correct quote type (none, single, double, or trip) based on quote characters contained within an input value"""
        if type(val) != str:
            quote = ""
        elif '"' and "'" in val:
            quote = self.str_triple_quote
        elif '"' in val:
            quote = self.str_single_quote
        else:
            quote = self.str_double_quote

        return quote

    def generate_contains_any_exp(self, field, vals):
        values_string = "|".join(vals)
        return field + self.token_separator + self.matches + self.token_separator + "/^.*({}).*$/i".format(values_string)

    def generate_contains_all_exp(self, field, vals):
        values_string = "/^.*(?=.*" + ")(?=.*".join(vals) + ").*$/i"
        return field + self.token_separator + self.matches + self.token_separator + values_string

    def generate_startswith_any_exp(self, field, vals):
        values_string = "|".join(vals)
        return field + self.token_separator + self.matches + self.token_separator + "/^({}).*$/i".format(values_string)

    def generate_endswith_any_exp(self, field, vals):
        values_string = "|".join(vals)
        return field + self.token_separator + self.matches + self.token_separator + "/^.*({})$/i".format(values_string)

    def convert_condition_as_in_expression(self, cond : Union[ConditionOR, ConditionAND], state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field in value list conditions."""
        args = cond.args
        # retrieve field
        field=self.escape_and_quote_field(cond.args[0].field)
        # retrieve values and pre-process for use below
        vals = [str(arg.value.to_plain() or "") for arg in cond.args]
        test_val = vals[0]
        vals_no_wc = [val.rstrip(self.wildcard_multi).lstrip(self.wildcard_multi) for val in vals]
        escaped_vals = [re.escape(val).replace("/", "\\/") for val in vals_no_wc]
        vals_formatted2 = self.list_separator.join([self.get_quote_type(v) + v.lower() + self.get_quote_type(v) if isinstance(v, str) else str(v) for v in escaped_vals])
                
        # or-in condition
        if isinstance(cond, ConditionOR):
            # contains any
            if test_val.startswith(self.wildcard_single) and test_val.endswith(self.wildcard_single):
                result = self.generate_contains_any_exp(field, escaped_vals)
            # startswith any
            elif test_val.endswith(self.wildcard_single) and not test_val.startswith(self.wildcard_single):
                result = self.generate_startswith_any_exp(field, escaped_vals)
            # endswith any
            elif test_val.startswith(self.wildcard_single) and not test_val.endswith(self.wildcard_single):
                result = self.generate_endswith_any_exp(field, escaped_vals)
            # in
            else:
                if any(isinstance(arg.value, SigmaString) for arg in args):
                    field=self.to_lower_case_expression.format(field=self.escape_and_quote_field(cond.args[0].field))
                result = self.field_in_list_expression.format(field=field, op=self.or_in_operator, list=vals_formatted2)
        else:
            # contains all
            result = self.generate_contains_all_exp(field, escaped_vals)

        return result

    def convert_condition_and(self, cond : ConditionAND, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of AND conditions."""
        try:
            if self.token_separator == self.and_token:
                joiner = self.and_token
            else:
                joiner = self.token_separator + self.and_token + self.token_separator

            result = joiner.join((
                     converted
                     for converted in (
                         self.convert_condition(arg, state) if self.compare_precedence(cond, arg)
                         else self.convert_condition_group(arg, state)
                         for arg in cond.args
                     )
                     if converted is not None and not isinstance(converted, DeferredQueryExpression)
                 ))

            if isinstance(cond.args[0], ConditionValueExpression):
                try:
                    vals = [self.convert_value_str(arg.value, state) for arg in cond.args]
                except:
                    vals = [self.str_quote + str(arg.value) + self.str_quote for arg in cond.args]
                result = joiner.join(vals)
                return SumoLogicMultiDeferredKeywordExpression(state, "", self.group_expression.format(expr=result))
            else:
                if result.endswith(joiner):
                    result = result.rstrip(joiner)
                return result
        except TypeError:       # pragma: no cover
            raise NotImplementedError("Operator 'and' not supported by the backend")

    def convert_condition_or(self, cond : ConditionOR, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of OR conditions."""
        try:
            if self.token_separator == self.or_token:   # don't repeat the same thing triple times if separator equals or token
                joiner = self.or_token
            else:
                joiner = self.token_separator + self.or_token + self.token_separator

            result = joiner.join((
                     converted
                     for converted in (
                         self.convert_condition(arg, state) if self.compare_precedence(cond, arg)
                         else self.convert_condition_group(arg, state)
                         for arg in cond.args
                     )
                     if converted is not None and not isinstance(converted, DeferredQueryExpression)
                 ))
            if isinstance(cond.args[0], ConditionValueExpression):
                try:
                    vals = [self.convert_value_str(arg.value, state) for arg in cond.args]
                except:
                    vals = [self.str_quote + str(arg.value) + self.str_quote for arg in cond.args]
                result = joiner.join(vals)
                return SumoLogicMultiDeferredKeywordExpression(state, "", self.group_expression.format(expr=result))
            else:
                if result.endswith(joiner):
                    result = result.rstrip(joiner)
                return result
        except TypeError:       # pragma: no cover
            raise NotImplementedError("Operator 'or' not supported by the backend")
    
    def convert_condition_field_eq_val_str(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions"""
        field = cond.field
        test_val = cond.value.to_plain().lower()
        val = self.convert_value_str(cond.value, state).lower()
        # contains
        if test_val.startswith(self.wildcard_multi) and test_val.endswith(self.wildcard_multi):
            result = self.to_lower_case_expression.format(field=cond.field) + self.token_separator + self.matches + self.token_separator + val
        # startswith or endswith
        elif test_val.endswith(self.wildcard_multi) or test_val.startswith(self.wildcard_multi):
            result = self.to_lower_case_expression.format(field=cond.field) + self.token_separator + self.matches + self.token_separator + val
        # plain equals
        elif test_val.strip() == "":
            result = self.field_blank_expression.format(field=cond.field)
        else:
            result = self.to_lower_case_expression.format(field=cond.field) + self.token_separator + self.eq_token + self.token_separator + val

        return result

    def convert_condition_field_eq_val_num(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = number value expressions"""
        try:
            return self.escape_and_quote_field(cond.field)+ self.token_separator + self.eq_token + self.token_separator + str(cond.value)
        except TypeError:       # pragma: no cover
            raise NotImplementedError("Field equals numeric value expressions are not supported by the backend.")

    def convert_condition_field_eq_val_re(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field matches regular expression value expressions."""
        regexp = self.convert_value_re(cond.value, state)
        field = cond.field
        result = self.re_expression.format(
                 field=field,
                 regex=regexp
             )
        
        return result

    def convert_condition_not(self, cond : ConditionNOT, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of NOT conditions."""
        arg = cond.args[0]
        try:
            if arg.__class__ in self.precedence:        # group if AND or OR condition is negated
                if isinstance(arg.args[0], ConditionValueExpression):
                    expr = self.convert_condition(arg, state)
                    return expr.negate()
                else:
                    return self.not_token + self.convert_condition_group(arg, state)
            elif isinstance(arg, ConditionFieldEqualsValueExpression):
                raw_val = cond.args[0].value
                if isinstance(raw_val, SigmaString):
                    test_val = raw_val.to_plain().lower()
                    val = self.convert_value_str(raw_val, state).lower()
                    # set field value
                    if type(val) == str:
                        field = self.to_lower_case_expression.format(field=arg.field)
                        val = val.lower()
                    else:
                        field = arg.field
                    # field is not blank or empty
                    if test_val.strip() == "":
                        result = self.not_token + self.field_blank_expression.format(field=arg.field)
                    # field does not start with, end with, or contain
                    elif raw_val[0] == self.wildcard_multi or raw_val[-1] == self.wildcard_multi:
                        exp = field + self.token_separator + self.matches + self.token_separator + val
                        result = self.not_expression.format(expression=exp)
                    else:
                        # does not equal
                        result = field + self.token_separator + self.not_eq_token + self.token_separator + val
                    return result
                elif isinstance(raw_val, SigmaNumber):
                    field = arg.field
                    return field + self.token_separator + self.not_eq_token + self.token_separator + str(raw_val)
                elif isinstance(raw_val, SigmaCompareExpression):
                    expr = self.convert_condition_group(arg, state)
                    if isinstance(expr, DeferredQueryExpression):      # negate deferred expression and pass it to parent
                        return expr.negate()
                    else:                                             # convert negated expression to string
                        return self.not_token + expr
                else:
                    expr = self.convert_condition(arg, state)
                    if isinstance(expr, DeferredQueryExpression):      # negate deferred expression and pass it to parent
                        return expr.negate()
                    else:                                             # convert negated expression to string
                        return self.not_token + expr
            else:
                expr = self.convert_condition(arg, state)
                if isinstance(expr, DeferredQueryExpression):      # negate deferred expression and pass it to parent
                    return expr.negate()
                else:                                             # convert negated expression to string
                    return self.not_token + expr
        except TypeError:       # pragma: no cover
            raise NotImplementedError("Operator 'not' not supported by the backend")

    def convert_condition_field_eq_val_cidr(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field matches CIDR value expressions."""
        cidr : SigmaCIDRExpression = cond.value
        addr = self.str_quote + str(cidr.network.network_address) + self.str_quote
        prefix_length = self.str_quote + str(cidr.network.prefixlen) + self.str_quote
        return self.cidr_expression.format(field=cond.field, addr=addr, prefix_length=prefix_length)

    def convert_condition_val_str(self, cond : ConditionValueExpression, state : "sigma.conversion.state.ConversionState") -> SumoLogicSingleDeferredKeywordExpression:
        """Conversion of value-only strings."""
        if isinstance(cond.parent, SigmaDetectionItem):
            return SumoLogicSingleDeferredKeywordExpression(state, "", cond.value).postprocess(None, cond)

    def convert_condition_val_num(self, cond : ConditionValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only numbers."""
        return self.unbound_value_num_expression.format(value=cond.value)

    def get_source_category(self, rule: SigmaRule, state: ConversionState) -> Any:
        """Create source category definition based on taxonomy https://github.com/SigmaHQ/sigma-specification/blob/main/Taxonomy_1_3_1.md"""
        # extract logsource components
        category = rule.logsource.category
        product = rule.logsource.product
        service = rule.logsource.service

        # add a cloud category if missing
        if not category and product in [
            "aws",
            "azure",
            "gcp",
            "google_workspace",
            "m365",
            "okta",
            "onelogin"
        ]:
            category = "cloudinfrastructure"

        # add an OS category
        if product in [
            "windows",
            "linux",
            "macos"
        ]:
            # set sysmon as service
            if product != "macos" and category in [
                "network_connection",
                "process_creation",
                "clipboard_capture",
                "create_remote_thread",
                "create_stream_hash",
                "dns_query",
                "file_change",
                "file_delete",
                "file_event",
                "image_load",
                "network_connection",
                "pipe_created",
                "process_access",
                "process_tampering",
                "process_termination",
                "raw_access_thread",
                "registry_add",
                "registry_delete",
                "registry_event",
                "registry_rename",
                "registry_set",
                "sysmon_error",
                "sysmon_status",
                "wmi_event"
            ]:
                service = "sysmon"
            category = "os"

        # add network category
        if category in ["dns", "firewall", "proxy", "webserver"]:
            product = category
            category = "network"
        if product == "zeek":
            category = "network"

        components = [category, product, service]
        populated_components = [item for item in components if item]
        result = "/" + "/".join(populated_components)
        
        return result

    def get_all_fields_from_rule(self, rule: SigmaRule) -> list:
        """Lists all fields (both the fields attribute and the fields used in selection queries) so they can be displayed in the query"""
        fields = []
        rule_dict = rule.to_dict()
        if "fields" in rule_dict.keys():
            fields.extend(rule_dict["fields"])

        selections = [item[1] for item in rule_dict["detection"].items() if isinstance(item[1], dict)]
        for selection in selections:
            keys = list(selection.keys())
            for key in keys:
                fields.append(key.split("|")[0])

        unique_fields = list(set(fields))

        return unique_fields

    def get_all_fields_from_rule_new(self, rule: SigmaRule) -> dict:
        """Lists all fields (both the fields attribute and the fields used in selection queries) so they can be displayed in the query"""
        detection_fields = list(set(re.findall("(?<=field=)\'(.*?)'", str(rule.detection.detections))))
        reference_fields = rule.fields
        result = {
            "detection_fields": detection_fields,
            "reference_fields": rule.fields
        }

        return result

    def get_parsing_statements(self, rule: SigmaRule) -> list:
        "Lists all applicable parsing statements that should be added to the output query"
        parsing_statements = []
        rule_fields = self.get_all_fields_from_rule_new(rule)["detection_fields"]
        field_mappings = [item for item in rule.applied_processing_items if item.endswith("fieldmapping")]
        for fm in field_mappings:
            parsing_statements_dict = parsing_statement_config[fm]
            for field in rule_fields:
                if field in parsing_statements_dict.keys():
                    parsing_statements.append(parsing_statements_dict[field])

        if len(parsing_statements) > 0:
            return sorted(list(set(parsing_statements)))
        else:
            return None
        

    def finalize_query(self, rule : SigmaRule, query : Union[str, DeferredQueryExpression], index : int, state : ConversionState, output_format : str) -> Union[str, DeferredQueryExpression]:
        """
        Finalize query by appending deferred query parts to the main conversion result as specified
        with deferred_start and deferred_separator.
        """
        rule_fields = sorted(self.get_all_fields_from_rule_new(rule)["detection_fields"])
        source_category = self.get_source_category(rule, state)
        parsing_statements = self.get_parsing_statements(rule)
        # add scope/keywords
        scope = "//Category and Keyword Definition\n_sourceCategory={source_category}".format(source_category=source_category)
        if state.has_deferred():
            for exp in state.deferred:
                scope += self.token_separator + exp.finalize_expression()
            # reset conversion state
            state = ConversionState(deferred=[], processing_state={})

        # add parsing statements
        if parsing_statements:
            parsing_section = "\n\n//Parsing Statements\n" + "\n".join(parsing_statements)
        else:
            parsing_section = ""

        # add query
        if query != "" and isinstance(query, str):
            where_clause = "\n\n//Selection Query\n| where " + query
        else:
            where_clause = ""

        # add display fields in table format
        fields = "\n\n//Display Fields\n| fields " + ", ".join(rule_fields) if rule_fields else ""

        finalized_query = scope + parsing_section + where_clause + fields

        return super().finalize_query(rule, finalized_query, index, state, output_format)

    def finalize_query_saved_search(self, rule : SigmaRule, query : Union[str, DeferredQueryExpression], index : int, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        name = rule.title
        query_text = query
        description = rule.description if rule.description else ""
        saved_search = {
            "type": "SavedSearchWithScheduleSyncDefinition",
            "name": name,
            "search": {
                "queryText": query_text,
                "defaultTimeRange": "Last 60 Minutes",
		"byReceiptTime": False,
		"viewName": "",
		"viewStartTime": "1970-01-01T00:00:00Z",
		"queryParameters": [],
		"parsingMode": "AutoParse"
            },
            "searchSchedule": None,
            "description": description
        }

        result = json.dumps(saved_search, indent=4)

        return result
    
    def finalize_output_saved_search(self, queries: List[str]) -> List[str]:
        return self.finalize_output_default(queries)
    

class sumologicCSEBackend(TextQueryBackend):
    """SumoLogic CSE Backend."""

    # add pipeline
    backend_processing_pipeline : ClassVar[ProcessingPipeline] = sumologic_cse_pipeline()

    # TOKEN DEFINITIONS

    # backend name
    name : ClassVar[str] = "Sumologic CSE Backend"

    # order of precedence
    precedence : ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)

    # grouping convention
    group_expression : ClassVar[str] = "({expr})"   # Expression for precedence override grouping as format string with {expr} placeholder

    # query tokens
    token_separator : str = " "     # separator inserted between all boolean operators
    or_token : ClassVar[str] = "OR"
    and_token : ClassVar[str] = "AND"
    not_token : ClassVar[str] = "NOT"
    keyword_not_token : ClassVar[str] = "NOT"
    not_eq_token : ClassVar[str] = "<>"
    eq_token : ClassVar[str] = "="
    like : ClassVar[str] = "LIKE"
    rlike : ClassVar[str] = "RLIKE"

    # field quoting definition
    field_quote : ClassVar[str] = "'"                               # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote_pattern : ClassVar[Pattern] = re.compile("^\\w+$")   # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation : ClassVar[bool] = True            # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).

    # escaping definition
    field_escape : ClassVar[str] = "\\"               # Character to escape particular parts defined in field_escape_pattern.
    field_escape_quote : ClassVar[bool] = True        # Escape quote string defined in field_quote
    field_escape_pattern : ClassVar[Pattern] = re.compile("\\s")   # All matches of this pattern are prepended with the string contained in field_escape.

    # to lower case expression (to make outputs case insensitive)
    to_lower_case_expression : ClassVar[str] = "lower({field})"

    # value definitions
    str_double_quote : ClassVar[str] = '"'
    str_single_quote : ClassVar[str] = "'"
    str_triple_quote : ClassVar[str] = '"""'
    str_quote       : ClassVar[str] = "'"     # string quoting character (added as escaping character)
    escape_char     : ClassVar[str] = "\\"    # Escaping character for special characrers inside string
    wildcard_multi  : ClassVar[str] = "%"     # Character used as multi-character wildcard
    wildcard_single : ClassVar[str] = "_"     # Character used as single-character wildcard
    wildcard_default : ClassVar[str] = "*"
    add_escaped     : ClassVar[str] = "\\"    # Characters quoted in addition to wildcards and string quote
    filter_chars    : ClassVar[str] = ""      # Characters filtered
    bool_values     : ClassVar[Dict[bool, str]] = {   # Values to which boolean values are mapped.
        True: "True",
        False: "False",
    }

    # regular expression definitions
    re_expression : ClassVar[str] = "{field} RLIKE '{regex}'"  # Regular expression query as format string with placeholders {field} and {regex}
    re_escape_char : ClassVar[str] = "\\"               # Character used for escaping in regular expressions
    re_escape : ClassVar[Tuple[str]] = ('"', '/')               # List of strings that are escaped

    # cidr expressions
    cidr_wildcard : ClassVar[str] = "*"    # Character used as single wildcard
    cidr_expression : ClassVar[str] = "compareCIDRPrefix({field}, {addr}, {prefix_length})"    # CIDR expression query as format string with placeholders {field} = {value}
    cidr_in_list_expression : ClassVar[str] = "{field} in ({value})"    # CIDR expression query as format string with placeholders {field} = in({list})

    # numeric comparison operators
    compare_op_expression : ClassVar[str] = "{field} {operator} {value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    # null, blank, and empty expressions
    field_null_expression : ClassVar[str] = "isNull({field})" # value is null
    field_blank_expression : ClassVar[str] = "isBlank({field})" # value is null, empty, or contains only whitespace characters
    field_empty_expression : ClassVar[str] = "isEmpty({field})" # value is an empty string containing no characters or whitespace

    # field value in list
    convert_or_as_in : ClassVar[bool] = True                     # Convert OR as in-expression
    convert_and_as_in : ClassVar[bool] = True                    # Convert AND as in-expression
    in_expressions_allow_wildcards : ClassVar[bool] = True       # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    field_in_list_expression : ClassVar[str] = "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    or_in_operator : ClassVar[str] = "IN"               # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    list_separator : ClassVar[str] = ", "               # List element separator

    # not equals expression
    not_expression : ClassVar[str] = "!({expression})"
    keyword_not_expression : ClassVar[str] = "NOT ({expression})"

    # keyword search expressions
    unbound_value_str_expression : ClassVar[str] = "_raw LIKE '%{value}%'"     # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression : ClassVar[str] = "_raw LIKE '%{value}%'"   # Expression for number value not bound to a field as format string with placeholder {value}

    def get_quote_type(self, val):
            """Returns the shortest correct quote type (none, single, double, or trip) based on quote characters contained within an input value"""
            if type(val) != str:
                quote = ""
            elif '"' and "'" in val:
                quote = self.str_triple_quote
            elif '"' in val:
                quote = self.str_single_quote
            else:
                quote = self.str_double_quote

            return quote
    
    def generate_contains_any_exp(self, field, vals):
        values_string = "|".join(vals).lower()
        field = self.to_lower_case_expression.format(field=field)
        return field + self.token_separator + self.rlike + self.token_separator + "'^.*({}).*$'".format(values_string)

    def generate_contains_all_exp(self, field, vals):
        values_string = "'^.*(?=.*" + ")(?=.*".join(vals) + ").*$'".lower()
        field = self.to_lower_case_expression.format(field=field)
        return field + self.token_separator + self.rlike + self.token_separator + values_string

    def generate_startswith_any_exp(self, field, vals):
        values_string = "|".join(vals).lower()
        field = self.to_lower_case_expression.format(field=field)
        return field + self.token_separator + self.rlike + self.token_separator + "'^({}).*$'".format(values_string)

    def generate_endswith_any_exp(self, field, vals):
        values_string = "|".join(vals).lower()
        field = self.to_lower_case_expression.format(field=field)
        return field + self.token_separator + self.rlike + self.token_separator + "'^.*({})$'".format(values_string)

    def convert_condition_field_eq_val_str(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions"""
        #print(cond.parent.modifiers[0])
        field = cond.field
        test_val = cond.value.to_plain().lower()
        val = self.convert_value_str(cond.value, state).lower()
        val = self.str_quote + test_val.replace(self.wildcard_default, self.wildcard_multi) + self.str_quote
        # contains
        if test_val.startswith(self.wildcard_default) and test_val.endswith(self.wildcard_default):
            result = self.to_lower_case_expression.format(field=cond.field) + self.token_separator + self.like + self.token_separator + val
        # startswith or endswith
        elif test_val.endswith(self.wildcard_default) or test_val.startswith(self.wildcard_default):
            result = self.to_lower_case_expression.format(field=cond.field) + self.token_separator + self.like + self.token_separator + val
        # blank
        elif test_val.strip() == "":
            result = self.field_blank_expression.format(field=cond.field)
        # plain equals
        else:
            result = self.to_lower_case_expression.format(field=cond.field) + self.token_separator + self.eq_token + self.token_separator + val

        return result

    def convert_condition_field_eq_val_num(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = number value expressions"""
        try:
            return cond.field + self.token_separator + self.eq_token + self.token_separator + str(cond.value)
            #return self.escape_and_quote_field(cond.field)+ self.token_separator + self.eq_token + self.token_separator + str(cond.value)
        except TypeError:       # pragma: no cover
            raise NotImplementedError("Field equals numeric value expressions are not supported by the backend.")

    def convert_condition_field_eq_val_re(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field matches regular expression value expressions."""
        regexp = self.convert_value_re(cond.value, state).replace("A-Z", "a-z")
        field = cond.field
        result = self.re_expression.format(
                 field=self.to_lower_case_expression.format(field=cond.field),
                 regex=regexp
             )
        
        return result

    def convert_condition_as_in_expression(self, cond : Union[ConditionOR, ConditionAND], state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field in value list conditions."""
        args = cond.args
        # retrieve field
        field=cond.args[0].field
        # retrieve values and pre-process for use below
        vals = [str(arg.value.to_plain() or "") for arg in cond.args]
        vals2 = [arg.value.to_plain() for arg in cond.args]
        test_val = vals[0]
        test_val2 = vals2[0]
        vals_no_wc = [val.rstrip(self.wildcard_default).lstrip(self.wildcard_default) for val in vals]
        escaped_vals = [re.escape(val).replace("/", "\\/") for val in vals_no_wc]
        vals_formatted2 = self.list_separator.join([self.str_quote + v.lower() + self.str_quote if isinstance(v, str) else str(v) for v in vals_no_wc])
                
        # or-in condition
        if isinstance(cond, ConditionOR):
            # contains any
            if test_val.startswith(self.wildcard_default) and test_val.endswith(self.wildcard_default):
                result = self.generate_contains_any_exp(field, escaped_vals)
            # startswith any
            elif test_val.endswith(self.wildcard_default) and not test_val.startswith(self.wildcard_default):
                result = self.generate_startswith_any_exp(field, escaped_vals)
            # endswith any
            elif test_val.startswith(self.wildcard_default) and not test_val.endswith(self.wildcard_default):
                result = self.generate_endswith_any_exp(field, escaped_vals)
            # in
            else:
                if any(isinstance(arg.value, SigmaString) for arg in args):
                    field=self.to_lower_case_expression.format(field=field)
                result = self.field_in_list_expression.format(field=field, op=self.or_in_operator, list=vals_formatted2)
        else:
            # contains all
            result = self.generate_contains_all_exp(field, escaped_vals)

        return result

    def convert_condition_field_eq_val_cidr(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field matches CIDR value expressions."""
        cidr : SigmaCIDRExpression = cond.value
        addr = self.str_quote + str(cidr.network.network_address) + self.str_quote
        prefix_length = self.str_quote + str(cidr.network.prefixlen) + self.str_quote
        return self.cidr_expression.format(field=cond.field, addr=addr, prefix_length=prefix_length)

    def convert_condition_val_str(self, cond : ConditionValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only strings."""
        return self.unbound_value_str_expression.format(value=cond.value)

    def finalize_query(self, rule : SigmaRule, query : Union[str, DeferredQueryExpression], index : int, state : ConversionState, output_format : str) -> Union[str, DeferredQueryExpression]:
        """
        Finalize query by appending deferred query parts to the main conversion result as specified
        with deferred_start and deferred_separator.
        """
        statement = sqlparse.split(query)[0]

        finalized_query = sqlparse.format(statement, reindent=True, wrap_after=False, keyword_case='upper')

        return super().finalize_query(rule, finalized_query, index, state, output_format)

    def finalize_query_cse_rule(self, rule : SigmaRule, query : Union[str, DeferredQueryExpression], index : int, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        tactics_mapping = {
            "reconnaissance": "_mitreAttackTactic:TA0043",
            "resource_development": "_mitreAttackTactic:TA0042",
            "initial_access": "_mitreAttackTactic:TA0001",
            "execution": "_mitreAttackTactic:TA0002",
            "persistence": "_mitreAttackTactic:TA0003",
            "privilege_escalation": "_mitreAttackTactic:TA0004",
            "defense_evasion": "_mitreAttackTactic:TA0005",
            "credential_access": "_mitreAttackTactic:TA0006",
            "discovery": "_mitreAttackTactic:TA0007",
            "lateral_movement": "_mitreAttackTactic:TA0008",
            "collection": "_mitreAttackTactic:TA0009",
            "exfiltration": "_mitreAttackTactic:TA0010",
            "command_and_control": "_mitreAttackTactic:TA0011",
            "impact": "_mitreAttackTactic:TA0040",
        }
        severity_mapping = {
            "informational": 0,
            "low": 2,
            "medium": 4,
            "high": 6,
            "critical": 8
        }
        # name and other rule elements
        name = rule.title
        description = rule.description + " " if rule.description else ""
        if rule.author and rule.date:
            desc = description + "Authored by " + rule.author + " on " + rule.date.strftime("%x") + "."
        else:
            desc = description
        if rule.level:
            severity_score = severity_mapping[rule.level.name.lower()]
        else:
            severity_score = 0
        # tags
        tags = []
        for tag in rule.tags:
            if tag.namespace == "attack":
                if tag.name in tactics_mapping.keys():
                    tags.append(tactics_mapping[tag.name])
                elif tag.name.lower().startswith("t"):
                    tags.append("_mitreAttackTechnique:" + tag.name.upper())
                else:
                    tags.append(tag.name)
            else:
                tags.append(tag.name)
        if rule.logsource.product:
            tags.append(rule.logsource.product)
        if rule.logsource.service:
            tags.append(rule.logsource.service)
        if rule.logsource.category:
            tags.append(rule.logsource.category)

        # define the rule   
        cse_rule = {
            "assetField": "device_hostname",
            "category": "Unknown/Other",
            "descriptionExpression": desc,
            "enabled": True,
            "entitySelectors": [{"entityType": "_hostname",
                                 "expression": "device_hostname"}],
            "expression": query,
            "isPrototype": True,
            "name": name,
            "nameExpression": name,
            "ruleType": "match",
            "scoreMapping": {"default": severity_score,
                             "field": None,
                             "mapping": None,
                             "type": "constant"},
            "summaryExpression": "",
            "stream": "record",
            "tags": tags
            }

        result = json.dumps(cse_rule, indent=4)

        return result
    
    def finalize_output_cse_rule(self, queries: List[str]) -> List[str]:
        return self.finalize_output_default(queries)
