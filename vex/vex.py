import requests
from .source import security_url, cve_url, cve_api, rhsa_api

class Vex(object):
    """
    Class Vex
    """

    def __init__(self, advisory):
        advisory_part = advisory.lower().split('-')
        build_url = ""
        if advisory_part[0].lower() == "cve":
            build_url = cve_api
        elif advisory_part[0].lower() == "rhsa":
            build_url = rhsa_api
        try:
            headers = {"content-type": "application/json"}
            response = requests.get(build_url + "/" + advisory + ".json", headers=headers)
            response.raise_for_status()  # Raise an exception for 4xx and 5xx status codes
            data = response.json()  # Parse JSON response
        except requests.exceptions.RequestException as e:
            print(advisory + " | No VEX document found", e)
            exit(10)
        
        if advisory_part[0] == "rhsa":
            self.id = data["document"]["tracking"]["id"]
            self.title = data["document"]["title"]
            self.vulnerabilities = []
            for vulnerability in data["vulnerabilities"]:
                self.vulnerabilities.append(vulnerability['cve'])

        elif advisory_part[0] == 'cve':
            self.id = data['name']
            self.title = data['bugzilla']['description']
            if 'cvss3' in data:
                self.cvss = data['cvss3']['cvss3_base_score']
            if 'threat_severity' in data:
                self.threat_severity = data['threat_severity']


