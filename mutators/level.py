def mutate(csv_data, level, environ):

    # Find all vulns that we don't care about, then remove them
    # from the set.
    unacceptable_vulns = set()
    for vuln in csv_data.vuln_to_hosts.keys():
        vulnLevel = csv_data.id_to_severity[vuln]
        if vulnLevel == 'None':
            unacceptable_vulns.add(vuln)
        elif level != 'All' and vulnLevel != level:
            unacceptable_vulns.add(vuln)

    for vuln in unacceptable_vulns:
        del csv_data.vuln_to_hosts[vuln]
    
    # rebuild host_to_vulns
    csv_data.rebuild_host_to_vulns() 
