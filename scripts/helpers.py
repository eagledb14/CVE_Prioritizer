#!/usr/bin python
# This file contains the functions that create the reports

import requests

from scripts.constants import EPSS_URL
from scripts.constants import NIST_BASE_URL

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.0.0"
__maintainer__ = "Mario Rojas"
__status__ = "Development"


def epss_check(cve_id):
    epss_url = EPSS_URL + f"?cve={cve_id}"
    epss_response = requests.get(epss_url)
    epss_status_code = epss_response.status_code

    if epss_status_code == 200:
        if epss_response.json().get("total") > 0:
            # print(f"{cve_id} is present in EPSS.")
            for cve in epss_response.json().get("data"):
                epss = cve.get("epss")
                percentile = int(float(cve.get("percentile"))*100)
                # print(f"EPSS: {epss}, {cve_id} is more likely to be exploited that {percentile}% of the known CVEs")
                return float(epss)
        else:
            # print(f"{cve_id} is not present in EPSS.")
            return False
    else:
        print("Error connecting to EPSS")


# Check NIST NVD for the CVE
def nist_check(cve_id):
    nvd_url = NIST_BASE_URL + f"?cveId={cve_id}"
    nvd_response = requests.get(nvd_url)
    nvd_status_code = nvd_response.status_code

    if nvd_status_code == 200:
        cisakev = False
        if nvd_response.json().get("totalResults") > 0:
            # print(f"{cve_id} is present in NIST NVD.")
            for unique_cve in nvd_response.json().get("vulnerabilities"):
                if unique_cve.get("cve").get("cisaExploitAdd"):
                    cisakev = True
                if unique_cve.get("cve").get("metrics").get("cvssMetricV31"):
                    for metric in unique_cve.get("cve").get("metrics").get("cvssMetricV31"):
                        version = "Ver 3.1"
                        cvss = metric.get("cvssData").get("baseScore")
                        severity = metric.get("cvssData").get("baseSeverity")
                        # print(f"CVSS {version}, BaseScore: {cvss}, Severity: {severity}")
                        return float(cvss), cisakev
                elif unique_cve.get("cve").get("metrics").get("cvssMetricV30"):
                    for metric in unique_cve.get("cve").get("metrics").get("cvssMetricV30"):
                        version = "Ver 3.0"
                        cvss = metric.get("cvssData").get("baseScore")
                        severity = metric.get("cvssData").get("baseSeverity")
                        # print(f"CVSS {version}, BaseScore: {cvss}, Severity: {severity}")
                        return float(cvss), cisakev
                elif unique_cve.get("cve").get("metrics").get("cvssMetricV2"):
                    for metric in unique_cve.get("cve").get("metrics").get("cvssMetricV2"):
                        version = "Ver 2.0"
                        cvss = metric.get("cvssData").get("baseScore")
                        severity = metric.get("cvssData").get("baseSeverity")
                        # print(f"CVSS {version}, BaseScore: {cvss}, Severity: {severity}")
                        return float(cvss), cisakev
        else:
            print(f"{cve_id} is not present in NIST NVD.")
            return False
    else:
        print("Error connecting to NVD")
