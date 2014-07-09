def output(csv_data, environ):
    vulns = csv_data.vuln_to_hosts
    sorted_vulns = sorted(vulns, key=csv_data.severity_to_key)
    for vuln in sorted_vulns:
        print "~~~~~", 
        if environ['numeric_ids']:
            print vuln,
        else:
            print csv_data.id_to_name[vuln], 
        print "(" + csv_data.id_to_severity[vuln] + ")",
        print "~~~~~"
        for host in vulns[vuln]:
            print host, "\t\t", csv_data.host_to_ip[host]
        print " "
