# WebSecOps
* Web Application Pentesting scripts

## http-nmap-brute.py
* used to feed a list of paths and ips parsed from a csv file created from the output of the http-auth.nse script for brute forcing using http-form-brute, http-brute, and http-default-accounts.nse scripts. Basically a wrapper for these to run across an environment and collect the results in a csv file. 
* Use nmap to get authentication pages on target hosts with http open

> nmap -oX authpages.xml --script http-auth \<targets\>

* output to CSV file with parse-nmap.ps1

> parse-nmap.ps1 authpages.xml -OutputDelimiter " " | where {$_.Ports -match "open"} | Export-Csv Http-Open-hosts.csv

* Run Python script

> http-nmap-brute.py Http-Open-Hosts.csv
