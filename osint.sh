#!/bin/bash

########
# Usage
#
# ./run.sh
# paste host into the "host" variable
# replace "google.com"
#
# If you want to include other hosts, add them to the "ips.txt" file
#
######

host="ncworks.gov"
touch ips.txt

shodan search --fields ip_str --limit 100 $host >> ips.txt || true

readarray -t ips < ips.txt

for ip in "${ips[@]}"; do
    echo $ip | xargs -n 1 shodan host | grep Vulnerabilities|  grep -oE 'CVE-[0-9]{4}-[0-9]{4,}'> cves.txt

    python3 cve_prioritizer.py -vf cves.txt -o "${ip}_cve_prioritizer_output.csv"
    # awk -F ',' 'NR==1{$0=toupper($0)} {OFS = ","; gsub("CVSS_", "", $5); gsub("CVSS_", "", $6); print $1,$2,$3,$4,$5,$6,$7,$9}' "${ip}_cve_prioritizer_output.csv" > "${ip}_cve_prioritizer_output_modified.csv"
    # rm "${ip}_cve_prioritizer_output.csv"
done
