import requests
import json
import csv
from datetime import datetime
import time

#from gwinnett_api_req import *

#THIS WILL GET YOU YOUR API TOKEN
mgmt_url = "https://34.68.229.243/api/v3.0/"
creds= {"username": "gc-api", "password": "GuardiCore123$"}
headers = {'content-type': 'application/json'}
r = requests.post(mgmt_url + "authenticate", data=json.dumps(creds), headers=headers, verify=False)
token= r.json()['access_token']
from_time_human = datetime(2020,6,11)
to_time_human = datetime(2020,6,13)
headers = {'content-type': 'application/json', 'Authorization':'Bearer '+ token}
pagesize = 5000
#========================

continue_iterating = True
page = 1

#THIS PART DOES THE EXPORT TO CSV By using the fieldnames values as dictionary keys to look through the API to create HEADERS in the CSV

fieldnames=[
    "source_ip",
    "source_hostname",
    "destination_ip",
    "destination_hostname",
    "destination_port",
    "policy_ruleset",
    "policy_verdict",
    "connection_type"]

with open("network_logs.csv", "w", newline="\n") as csvfile:
    writer = csv.DictWriter(csvfile, delimiter=",", fieldnames = fieldnames, extrasaction='ignore')
    writer.writeheader()  #Add a new header line for csv


#THIS IS THE PARAMETERS WHEN CALLING THE URL
    while continue_iterating:
      settings= {
      "from_time" : int(from_time_human.timestamp()*1000),
      "to_time" : int(to_time_human.timestamp()*1000),
      "any_side": "labels:0a229960-412c-4cde-ba8e-cf5c82b52ee8",
      "destination": "address_classification:Internet",
      "sort" : "-slot_start_time",
      "offset": (page-1)*pagesize,
      "limit": pagesize
      }


#THIS IS WHERE WE RUN THE FUNCTION
      r = requests.get(mgmt_url + "connections", headers=headers, params=settings, verify=False)
      print(r)  #This should show a 200 OK
      r=r.json()  #This pulls the entire json  
      print(r)
      

#THIS IS Where we change the values of the keys in dictionary to fit the header that the csv has and is looking for       
      for d in r['objects']: 
        d['slot_start_time'] = datetime.fromtimestamp(d['slot_start_time']/1000).strftime('%Y-%m-%d %H:%M:%S')
        if 'source' in d:
            d['source_hostname']=d['source']['vm'].pop('name')         #change source name key that it looks for from source to source:vm:name so i can just pull the hostname out 
        else:                                                          #this is for unknown sources
            None
        if 'destination'in d:
            d['destination_hostname']=d['destination']['vm'].pop('name')      #for non-internet filter it will look for the name key in vm key in destination in objects
        elif 'destination_domain' in d:       #for internet filter, it will look for this key in objects
            d['destination_hostname']=d['destination_domain']        
        else:                  #this is if destination is something that is external and dns doesn't know
            None
        writer.writerow(d)
      
      if r['to'] >= r['total_count']:
          continue_iterating = False
      time.sleep(1)
      page = page + 1

