#!/usr/bin/env python
## This script marshals the other parts of the parser

from util.reader import read, load, carve
from util.arguments import parse_arguments
import util.statistics as statistics
import time
import datetime

if __name__ == '__main__':
    args = parse_arguments()

    # load the data from either the api or a csv
    if args.filename:
        reports = [read(args.filename)]
    elif args.time:
        # Check the arg to make sure it's valid.
        try:
            start = time.mktime(time.strptime(args.time, "%d%m%Y"))
            end = datetime.datetime.fromtimestamp(start) + datetime.timedelta(hours=23, minutes=59)
            end = time.mktime(end.timetuple())
            reports = carve(start, end)
        except ValueError:
            print("Incorrect value for --time")
            exit(1)
    else:
        assert args.use_api
        reports = [load()]
        
    environ = {}

    # process options which set flags for other modules
    if args.numeric_ids:
        environ['numeric_ids'] = True
    else:
        environ['numeric_ids'] = False
    if args.level:
        environ['level'] = args.level

    for csv_data in reports:
        # process mutators, according to which ones were selected
        if args.condense_java:
            from mutators import condense_java
            condense_java.mutate(csv_data, environ)
        if args.condense_ms:
            from mutators import condense_ms
            condense_ms.mutate(csv_data, environ)
        if args.select_adobe:
            from mutators import select_adobe
            select_adobe.mutate(csv_data, args.select_adobe, environ)
        # level and plugin_list don't really make sense together,
        # so we ignore level if plugin_list is present
        if args.level and args.plugin_list == None:
            from mutators import level
            level.mutate(csv_data, args.level, environ)
        if args.hostname_regex:
            from mutators import hostname_regex
            hostname_regex.mutate(csv_data, args.hostname_regex, environ)
        if args.plugin_list:
            from mutators import plugin_list
            plugin_list.mutate(csv_data, args.plugin_list, environ)
        if args.group_file:
            from mutators import group_file
            group_file.mutate(csv_data, args.group_file, environ)
        if args.exceptions_file:
            from mutators import exceptions
            exceptions.mutate(csv_data, args.exceptions_file, environ)

        # print some statistics
        print
        print csv_data.name
        print "="*len(csv_data.name)
        print
        statistics.output(csv_data)

        # process output modules
        from output import text
        text.output(csv_data, environ)
        if args.recipe_file:
            from output import create_rt_tickets
            create_rt_tickets.output(csv_data, args.recipe_file, environ)
        if args.excel_file:
            from output import excel
            excel.output(csv_data, args.excel_file, environ)
