#!/bin/python

import json
import requests
from crowdstrike import *
from secrets import *
from requests.structures import CaseInsensitiveDict
 
hostname = input("Hostname: ")
action = input("Select an action by number: \n1: Enable NetLogon\n2: Stop Netlogon\n3: Start Netlogon\n4: Disable Netlogon\n> ")

def execute_command(action): 
    device_id = get_device(hostname)
    access_token = get_token()
    session_id = start_session(device_id)
    command_request_url = api_baseurl + command_url

    if action == "1":
        script = "enable-netlogon.ps1"
    elif action == "2":
        script = "stop-netlogon.ps1"
    elif action == "3":
        script = "start-netlogon.ps1"
    elif action == "4":
        script = "disable-netlogon.ps1"
    else:
        print("Please enter a valid selection.")
    
    headers = CaseInsensitiveDict()
    headers["accept"] = "application/json"
    headers["Content-Type"] = "application/json"
    headers["authorization"] = "bearer " + access_token
    
    data = '{  "base_command": "runscript",  "command_string": "runscript -CloudFile=%s",  "device_id": "string",  "id": 0,  "persist": true,  "session_id": "%s"}' % (script, session_id)
    
    print(data)
    resp = requests.post(command_request_url, headers=headers, data=data)


execute_command(action)


