## This part of the Nessus parser is intended to, given a filename,
## read it, parse the CSV, and then return a ScanData object with
## the following dictionaries
## 1. host_to_vulns, a dictionary from hostname -> set of plugin IDs
## 2. vuln_to_hosts, a dictionary from plugin ID -> set of hostnames
## 3. id_to_name, a dictionary from plugin ID -> human-friendly name
## 4. host_to_ip, a dictionary from hostname -> IP address
## 5. id_to_severity, a dictionary from plugin ID -> severity ('Critical', 'High', etc.)
import csv
import socket
from util.scandata import ScanData

# Plugin ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,Plugin Output

__author__ = "Maximilian Burkhardt, Lead Infosec 2012-2013, Samuel Zhu, InfoSec Engineer 2013, Arlan Jaska InfoSec Engineer 2014"

def load():
    vuln_to_hosts = {}
    id_to_name = {}
    host_to_ip = {}
    id_to_severity = {}
    risk = { '0': "None", '1': "Low", '2': "Medium", '3': "High", '4': "Critical" }

    import nessusapi.report, nessusinterface.session, nessusinterface.report
    while True:
        try:
            nessusinterface.session.authenticate()    
            break
        except nessusapi.session.AuthenticationError:
            print "Bad credentials."
    report = nessusinterface.report.select_report()
    
    hosts = nessusapi.report.list_hosts(report)
    for host in hosts:
        hostname = host['hostname']
        try:
            host_to_ip[hostname] = socket.getaddrinfo(hostname, 4444)[0][4][0]
        except:
            host_to_ip[hostname] = "IP N/A"
    
    vulns = nessusapi.report.list_vulns(report)
    for vuln in vulns:
        plugin_id = vuln['plugin_id']
        id_to_name[plugin_id] = vuln['plugin_name']
        id_to_severity[plugin_id] = risk[vuln['severity']]

        # add entry to vuln_to_hosts for this vuln
        vuln_to_hosts[plugin_id] = set()
        hosts = nessusapi.report.list_affected_hosts(report, plugin_id, vuln['severity'])
        for host in hosts:
            vuln_to_hosts[plugin_id].add(host['hostname'])
        
    scandata = ScanData({}, vuln_to_hosts, id_to_name, host_to_ip, id_to_severity)
    scandata.rebuild_host_to_vulns()
    return scandata


def read(filename): 
    PID = 0
    CVE = 1
    CVSS = 2
    RISK = 3
    HOST = 4
    PROTOCOL = 5
    PORT = 6
    NAME = 7
    SYNOPSIS = 8
    DESCRIPTION = 9
    SOLUTION = 10
    OUTPUT = 11

    host_to_vulns = {}
    vuln_to_hosts = {}
    id_to_name = {}
    host_to_ip = {}
    id_to_severity = {}

    try:
        with open(filename, 'rb') as csvfile:
            scanreader = csv.reader(csvfile, delimiter=",", quotechar="\"")
            for row in scanreader:
                # first get the IP address mapping (if not already discovered) and put it in host_to_ip
                if row[HOST] not in host_to_ip:
                    try:
                        host_to_ip[row[HOST]] = socket.getaddrinfo(row[HOST], 4444)[0][4][0]
                    except:
                        host_to_ip[row[HOST]] = "IP N/A"

                # create id_to_name entries if they don't already exist
                if row[PID] not in id_to_name:
                    id_to_name[row[PID]] = row[NAME]

                # create id_to_severity entries if they don't already exist
                if row[PID] not in id_to_severity:
                    id_to_severity[row[PID]] = row[RISK]

                # add entry to host_to_vulns for this host and this vuln
                if row[HOST] not in host_to_vulns:
                    host_to_vulns[row[HOST]] = set()
                host_to_vulns[row[HOST]].add(row[PID])

                # add entry to vuln_to_hosts for this host and this vuln
                if row[PID] not in vuln_to_hosts:
                    vuln_to_hosts[row[PID]] = set()
                vuln_to_hosts[row[PID]].add(row[HOST])

        return ScanData(host_to_vulns, vuln_to_hosts, id_to_name, host_to_ip, id_to_severity)
    except IOError:
        print "Error! CSV file was not successfully read."
        exit(1)
    except:
        print "An unknown error occurred during parsing!"
        exit(1)
