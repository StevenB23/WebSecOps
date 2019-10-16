# WebSecOps
* Web Application Pentesting scripts

## http-nmap-brute.py
* used to feed a list of paths and ips parsed from a csv file created from the output of the http-auth.nse script for brute forcing using http-form-brute, http-brute, and http-default-accounts.nse scripts. Basically a wrapper for these to run across an environment and collect the results in a csv file. 
* run "nmap -oX authpages.xml --script http-auth \<targets\>" to gather paths to http authentication pages. 
* output to CSV file with "parse-nmap.ps1 authpages.xml | export-csv telnet_hosts.csv"
