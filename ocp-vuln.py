#!/usr/local/bin/python3.9

import requests
import argparse

from vex import color
from vex import Vex
from vex import Openshift

openshift = Openshift()

# ---
# Retrive vex document for a CVE or a RHSA from confirgured api
# Return a Vex object
#
def get_vex_by_rhsa(advisory):
    try:
        vex = Vex(advisory)
        return vex
    except requests.exceptions.RequestException as e:
        if args.verbose:
            print(f"{advisory} | No VEX document found", e)
        return None

# --- get_all_cve_by_rhsa
# Retrive all OCP version and CVE from available data
# Output on screen CVE breakdown by OCP version
#
def get_all_cve_by_rhsa():
    for zstream, advisories in openshift.rhsa.items():
        print(f"{color.GREEN}Red Hat Openshift Container Platform {zstream}{color.END}")
        for target, advisory in advisories.items():
            if advisory != 'None' and 'RHSA' in advisory:
                vex_document = Vex(advisory)
                print(f"  {color.DARKCYAN}{vex_document.id}{color.END} ({target})")
                for vulnerability in vex_document.vulnerabilities:
                    cve = Vex(vulnerability)
                    highlight = color.END
                    if cve.threat_severity == 'Critical' or float(cve.cvss) >= 8.0:
                        highlight = color.RED
                    print(f"    - {cve.id:<20} {highlight}{cve.cvss:>5} {cve.threat_severity:<12}{color.END}|  {cve.title}")

# --- get_zstream_from_cve
# Retrive all OCP version fixing a particular CVE
# Return a list of z-stream
#
def get_zstream_from_cve(cve):
    matching_zstream = []
    for zstream, advisories in openshift.rhsa.items():
        for target, advisory in advisories.items():
            if 'RHSA' in advisory:
                vex_document = Vex(advisory)
                if vex_document:
                    for vulnerability in vex_document.vulnerabilities:
                        if vulnerability == cve:
                            matching_zstream.append(zstream)
    matching_zstream.sort(reverse = True)
    return matching_zstream

# ---
# Retrive all CVE fixed in between 2 OCP versions
# Return a list of z-stream
#
def get_cve_from_to(ocp_from, ocp_to=None):
    matching_cve = []
    if ocp_to:
        print(f"{color.GREEN}Red Hat Openshift Container Platform CVE from {ocp_from} to {ocp_to}{color.END}")
    else:
        ocp_to = ocp_from
        print(f"{color.GREEN}Red Hat Openshift Container Platform CVE for {ocp_from}{color.END}")
    
    from_xstream, from_ystream, from_zstream = ocp_from.split('.')
    to_xstream, to_ystream, to_zstream = ocp_to.split('.')
    for xstream in range(int(from_xstream), int(to_xstream)+1):
        for ystream in range(int(from_ystream), int(to_ystream)+1):
            for zstream in range(int(from_zstream), int(to_zstream)+1):
                advisory = str(xstream) + '.' + str(ystream) + '.' + str(zstream)
                if advisory in openshift.rhsa:
                    for target, advisory in openshift.rhsa[advisory].items():
                        if advisory != 'None' and 'RHSA' in advisory:
                            vex_document = Vex(advisory)
                            for vulnerability in vex_document.vulnerabilities:
                                if vulnerability not in matching_cve:
                                    matching_cve.append(vulnerability)
    return matching_cve

# --- main
#
def main():
    if args.cve:
        matching_zstream = get_zstream_from_cve(args.cve)
        if matching_zstream:
            print(f"Minimim Openshift version : {matching_zstream[0]}")
        else:
            print(f"{args.cve} is not fixed in any Openshift version") 
    elif args.list:
        get_all_cve_by_rhsa()
    elif args.rhsa:
        vex_document = get_vex_by_rhsa(args.rhsa)
        if vex_document:
            print(f"{color.DARKCYAN}{vex_document.id}{color.END} | {vex_document.title}")
            for vulnerability in vex_document.vulnerabilities:
                cve = Vex(vulnerability)
                highlight = color.END
                if cve.threat_severity == 'Critical' or float(cve.cvss) >= 8.0:
                    highlight = color.RED
                print(f"    - {cve.id:<20} {highlight}{cve.cvss:>5} {cve.threat_severity:<12}{color.END}|  {cve.title:<}")
        else:
            print(f"{args.rhsa} not found")
    elif args.start:
        matching_cve = get_cve_from_to(args.start, args.end)
        if matching_cve:
            for vulnerability in matching_cve:
                cve = Vex(vulnerability)
                highlight = color.END
                if cve.threat_severity == 'Critical' or float(cve.cvss) >= 8.0:
                    highlight = color.RED
                print(f"    - {cve.id:<20} {highlight}{cve.cvss:>5} {cve.threat_severity:<12}{color.END}|  {cve.title}")
        else:
            print(f"{args.start} or {args.end} not found")
    else:
        print("check help")


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('--cve', type=str, help="find z-stream fixing the cve")
    parser.add_argument('--rhsa', type=str, help="find cve fixed in a RHSA")
    parser.add_argument('--start', type=str, help="from test flag")
    parser.add_argument('--end', type=str, help="to test flag")
    parser.add_argument('--list', action="store_true", help="list cve by z-stream")
    parser.add_argument('--cache', action="store_true", help="use data on disk")
    parser.add_argument('--test', action="store_true", help="test flag")
    parser.add_argument('--verbose', action="store_true", help="[unused] increase output verbosity")
    args = parser.parse_args()

    main()

