#!/usr/local/bin/python3.9

import requests
import argparse
import json

from vex import color
from vex import Vex
from vex import Openshift

openshift = Openshift()

def get_vex_by_rhsa(advisory):
    try:
        vex = Vex(advisory)
        return vex
    except requests.exceptions.RequestException as e:
        if args.verbose:
            print(advisory + " | No VEX document found", e)
        return None

def get_all_cve_by_rhsa():
    for zstream, advisories in openshift.rhsa.items():
        print(f"{color.GREEN}Red Hat Openshift Container Platform {zstream}{color.END}")
        for target, advisory in advisories.items():
            if advisory != "None" and "RHSA" in advisory:
                vex_document = Vex(advisory)
                print(f"  {color.DARKCYAN}{vex_document.id}{color.END} ({target})")
                for vulnerability in vex_document.vulnerabilities:
                    cve = Vex(vulnerability)
                    highlight = color.END
                    if cve.threat_severity == 'Critical' or float(cve.cvss) >= 8.0:
                        highlight = color.RED
                    print(f"    - {cve.id:<20} {highlight}{cve.cvss:>5} {cve.threat_severity:<12}{color.END}|  {cve.title}")

def get_zstream_from_cve(cve):
    matching_zstream = []
    for zstream, advisories in openshift.rhsa.items():
        for target, advisory in advisories.items():
            if "RHSA" in advisory:
                vex_document = Vex(advisory)
                if vex_document:
                    for vulnerability in vex_document.vulnerabilities:
                        if vulnerability == cve:
                            matching_zstream.append(zstream)
    matching_zstream.sort(reverse = True)
    return matching_zstream

def main():
    if args.cve:
        matching_zstream = get_zstream_from_cve(args.cve)
        if len(matching_zstream) > 0:
            print("Minimim Openshift version : " + matching_zstream[0])
        else:
            print(args.cve + " is not fixed in any Openshift version") 
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
            print(args.rhsa + " not found")
    else:
        print("check help")


if __name__ == "__main__":

    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true", help="list cve by z-stream")
    parser.add_argument("--cve", type=str, help="find z-stream fixing the cve")
    parser.add_argument("--rhsa", type=str, help="find cve fixed in a RHSA")
    parser.add_argument("--cache", action="store_true", help="use data on disk")
    parser.add_argument("--test", action="store_true", help="test flag")
    parser.add_argument("--verbose", action="store_true", help="[unused] increase output verbosity")
    args = parser.parse_args()

    main()

