![Tests](https://github.com/mbabinski/pySigma-backend-sumologic/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/mbabinski/1cb17bd73b455fc77d6f75b312fb71ae/raw/mbabinski-pySigma-backend-sumologic.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma SumoLogic Backend

This is the [SumoLogic](https://www.sumologic.com/) backend for pySigma,capable of converting Sigma rules into Continuous Intelligence Platform (CIP) [log search queries](https://help.sumologic.com/docs/search/get-started-with-search/search-basics/about-search-basics/#:~:text=Click%20%2B%20New%20button%20in%20the,Messages%20tab%20below%20the%20histogram.) and [Cloud SIEM Enterprise (CSE)](https://www.sumologic.com/solutions/cloud-siem-enterprise/) queries for the SumoLogic platform. It provides the package `sigma.backends.sumologic` with the `sumologicCIPBackend` and `sumoLogicCSEBackend` classes.
Further, it contains the following processing pipelines in `sigma.pipelines.sumologic`:
* `sumologic_cip_pipeline`: Performs field mapping, value transformations, and triggers rule failures when unsupported fields are present. Field names are mapped for clarity and to support correlation across log sources. 
* `sumologic_cse_pipeline`: erforms field mapping, value transformations, and triggers rule failures when unsupported fields are present. Field names are mapped to align with [CSE mappable fields](https://help.sumologic.com/docs/cse/schema/attributes-map-to-records/).

It supports the following output formats:
* CIP Backend
  * default: Provides queries for use in CIP log search.
  * saved_search: This output format creates properly-formatted JSON which can be imported as a saved search. It will add the proper object type, query text, a default "Last 60 Minutes" time range, and will set the Auto Parse option as explained [here](https://help.sumologic.com/docs/search/get-started-with-search/build-search/dynamic-parsing/#use-dynamic-parsing).
* CSE Backend
  * default: Provides queries for use in CSE rules.
  * cse_rule: This format provides JSON which can be imported as a new rule using the SumoLogic GUI or API. It will set the rule name, description, tags, and severity levels based on the source Sigma rule.

### Parsing
Additionally, the `sigma.backends.sumologic.parsing` file contains lookups that support the addition of [parsing statements](https://help.sumologic.com/docs/search/search-query-language/parse-operators/) to output CIP queries, which is required to perform the filtering/querying in the rules. Parsing statements may not be necessary if the user has implemented [Field Extraction Rules (FERs)](https://help.sumologic.com/docs/manage/field-extractions/); however, I added the parsing statements to make the output queries as useful in the near-term as possible. You may remove them if they are not needed.

### Maintenance and Support
This backend is currently maintained by:

* [Micah Babinski](https://github.com/mbabinski/)