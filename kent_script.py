# IMPORT NECESSARY PYTHON MODULES
import requests
import json
import csv
import time
import getpass
from datetime import datetime
""" 
IMPORTANT:    If the execution fails with a 'KeyError: access_token' message,
              this means that either the UN, PW, or Management address is/are not correct
"""
un = input('Enter user name: ')
pw = getpass.getpass('Enter your password: ')
mgmt = input('Enter Management Server name or IP: ')
print('\nAuthenticating... \n\nPlease wait...')
# Specify Management Server's Address, replace <mgmt_address>
mgmt_url = 'https://' + mgmt + '/api/v3.0/'
# Specify Management Server's Credentials, replace <user_name> and <password>
creds = {'username': un, 'password': pw}
# Set Header values
headers = {'content-type': 'application/json'}
# Create POST Request
r = requests.post(mgmt_url + 'authenticate', data=json.dumps(creds), headers=headers, verify=False)
# Obtain token directly from r
token = r.json()['access_token']
# Append values to Header
headers = {'content-type': 'application/json', 'Authorization': 'Bearer ' + token}
# Set Pagesize
pagesize = 1000
# 200 Response is to be expected at this point
# print(r)
# Determine if loop iteration will continue
continue_iterating = True
page = 1
# Set Column Names for CSV File
fieldnames = [
    #'_id',
    'display_name',
    'os_display_name',
    'ip_address',
    'agent_version',
    'last_seen',
    'first_seen'
]
# Write on CSV file
print('\nWriting on file...')
print('\tThis process may take a few seconds or minutes depending on the number of Assets in the environment...')
with open('assets_xprt.csv', 'w', newline='\n') as csvfile:
    writer = csv.DictWriter(csvfile, delimiter=',', fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()  # Add a header line for the csv
    while continue_iterating:
        settings = {
            'sort': '-display_name',
            'offset': (page - 1) * pagesize,
            'limit': pagesize
        }
        # This is were we run the function
        r = requests.get(mgmt_url + 'assets', headers=headers, params=settings, verify=False)
        # 200 Response is to be expected at this point
        # print(r) # This pulls the entire json
        r = r.json()
        # print(r) # This is where we assign the values of the keys in the dictionary
        for d in r['objects']:
            # Proceed to write on the file only if the device's status is ON.
            # Machines with OFF and DELETED status will not be written. Unless modified in code.
            if d['status'] == 'on':
                d['display_name'] = d['name']
                d['ip_address'] = d['ip_addresses']
                if 'guest_agent_details' in d:
                    d['agent_version'] = d['guest_agent_details'].get('agent_version')
                    d['os_display_name'] = d['guest_agent_details']['os_details'].get('os_display_name')
                d['first_seen'] = datetime.fromtimestamp(d['first_seen'] / 1000).strftime('%Y-%m-%d %H:%M:%S')
                d['last_seen'] = datetime.fromtimestamp(d['last_seen'] / 1000).strftime('%Y-%m-%d %H:%M:%S')
                # Write on file
                writer.writerow(d)
        # If all records have been written, stop the writing loop
        if r['to'] >= r['total_count']:
            continue_iterating = False
        time.sleep(1)
        page = page + 1  
print('Report has been created!')