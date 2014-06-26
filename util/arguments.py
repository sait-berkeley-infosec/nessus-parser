## module to parse arguments passed in on command line
import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(description='Process Nessus reports')
    parser.add_argument('filename', metavar='filename', type=str, nargs='?', default="",
            help="Nessus CSV file to parse.")
    parser.add_argument('--api', dest='use_api',
            action='store_true', help="Use the Nessus API instead of a CSV")
    parser.add_argument('--condense-java', dest='condense_java',
            action='store_true', help='combine all java-related vulns in to one category.')
    parser.add_argument('--condense-ms', dest='condense_ms',
            action='store_true', help='combine all microsoft-related vulns in to one category.')
    parser.add_argument('--select-adobe', dest='select_adobe', type=str,
            choices=['only', 'none'],
            help='output either ONLY Adobe vulnerabilities or NO Adobe vulnerabilities')
    parser.add_argument('--level', dest='level', type=str, 
            choices=['Critical', 'High', 'Medium', 'Low', 'None'],
            help='Show vulns of risk level <level>.')
    parser.add_argument('--filter-hostname', dest='hostname_regex', type=str,
            help='only show hostnames that match the regular expression <regex>. Suggested values: AEIO, SAS, etc. Keep things to one word, or be prepared to debug your regexes.')
    parser.add_argument('--filter-plugin', dest='plugin_list', type=str,
            help='only show the listed plugins. Separate desired plugins by commas, WITHOUT spaces. NOTE: this overrides the --level directive.')
    parser.add_argument('--filter-group', dest='group_file', type=str,
            help='read in regular expressions from the given file (one per line), and only process hosts that match one of them.')
    parser.add_argument('--create-tickets', dest='recipe_file', type=str,
            help='makes RT tickets for all hosts produced in the report.')
    parser.add_argument('--create-excel', dest='excel_file', type=str,
            help='creates an Excel file with the information produced by this script.')
    parser.add_argument('--numeric-ids', dest='numeric_ids', action='store_true',
            help='represent plugins by their ID, not their human-readable name')
    parser.add_argument('--use-exceptions', dest='exceptions_file', type=str,
            help='use a file with a list of hostnames and nessus plugin ids that we don\'t care about')
    parser.set_defaults(condense_java=False, condense_ms=False, level='Critical', numeric_ids=False)

    args = parser.parse_args()

    if args.filename and args.use_api:
        parser.error("The API option may not be used with a filename.")
    elif not args.filename and not args.use_api:
        parser.error("Must be given a source to load from.")

    return args
