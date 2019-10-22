# WebSecOps
* Web Application Pentesting scripts

**Nmap one liner brute force forms and http basic authentication**
* exports xml file, sets the login page to "signin"
* if you use "brute.emptypass" argument it won't iterate through passwords at all even if passdb is supplied
> nmap -oX test.xml --script http-form-brute,http-brute --script-args http-form-brute.path=signin,
unpwdb.timelimit=0 -vvv -Pn -p 80 10.1.1.1 

## http-nmap-brute.py
* used to feed a list of paths and ips parsed from a csv file created from the output of the http-auth.nse script for brute forcing using http-form-brute, http-brute, and http-default-accounts.nse scripts. Basically a wrapper for these to run across an environment and collect the results in a csv file. 
* Use nmap to get authentication pages on target hosts with http open

> nmap -oX authpages.xml --script http-auth \<targets\>

* output to CSV file with parse-nmap.ps1

> parse-nmap.ps1 authpages.xml -OutputDelimiter " " | where {$_.Ports -match "open"} | Export-Csv Http-Open-hosts.csv

* Run Python script

> http-nmap-brute.py Http-Open-Hosts.csv
