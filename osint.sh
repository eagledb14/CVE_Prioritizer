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

host=""
touch ips.txt

shodan search --fields ip_str --limit 100 $host >> ips.txt 

readarray -t ips < ips.txt

touch cves.txt

for ip in "${ips[@]}"; do
    echo $ip | xargs -n 1 shodan host | grep Vulnerabilities|  grep -oE 'CVE-[0-9]{4}-[0-9]{4,}' > cves.txt

    if [ -s "$cves"]; then
        python3 cve_prioritizer.py -vf cves.txt -o "${ip}.csv"
    fi
done

rm cves.txt
