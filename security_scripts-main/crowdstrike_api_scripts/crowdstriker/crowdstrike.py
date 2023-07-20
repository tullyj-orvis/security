import json
import time
import requests
from secrets import *
from requests.structures import CaseInsensitiveDict 
from os import system, name

api_baseurl = "https://api.crowdstrike.com"
token_url = "/oauth2/token"
session_url ="/real-time-response/entities/sessions/v1"
command_url ="/real-time-response/entities/admin-command/v1"
batch_command_url="/real-time-response/combined/batch-admin-command/v1?timeout=30&timeout_duration=30s&host_timeout_duration=19s"
devices_url ="/devices/queries/devices/v1?filter="
contain_host_url ="/devices/entities/devices-actions/v2?action_name="
get_detections_url ="/detects/aggregates/detects/GET/v1"
get_file_url ="/real-time-response/combined/batch-get-command/v1?timeout=30&timeout_duration=30s"
get_batch_id_url="/real-time-response/combined/batch-init-sessions/v1"
batch_session_url="/real-time-response/combined/batch-init-session/v1?timeout=30&timeout_duration=30s"


def get_token():
    token_request_url = api_baseurl + token_url

    headers = CaseInsensitiveDict()
    headers["accept"] = "application/json"
    headers["Content-Type"] = "application/x-www-form-urlencoded"

    data = "client_id=" + client_id + "&client_secret=" + client_secret


    resp = requests.post(token_request_url, verify=False, headers=headers, data=data)

    resp_json = resp.json()

    return resp_json['access_token']


def start_session(device_id):

    access_token = get_token()

    session_request_url = api_baseurl + session_url

    headers = CaseInsensitiveDict()
    headers["accept"] = "application/json"
    headers["Content-Type"] = "application/json"
    headers["authorization"] = "bearer " + access_token

    data = '{  "device_id": "%s",  "origin": "string",  "queue_offline": true}' % device_id

    resp = requests.post(session_request_url, verify=False, headers=headers, data=data)

    resp_json = resp.json()

    return resp_json['resources'][0]['session_id']

def start_batch_session(device_id):

    access_token = get_token()

    batch_session_request_url = api_baseurl + batch_session_url
    
    headers = CaseInsensitiveDict()
    headers["accept"] = "application/json"
    headers["Content-Type"] = "application/json"
    headers["authorization"] = "bearer " + access_token
    
    data = '{  "existing_batch_id": "",  "host_ids": [    "%s"  ],  "queue_offline": true}' % device_id
    
    
    print(data)
    resp = requests.post(batch_session_request_url, headers=headers, data=data)

    resp_json = resp.json()
    return resp_json

    #return resp_json['resources'][device_id]['session_id']

def get_device(hostname):
    access_token = get_token()

    devices_request_url = api_baseurl + devices_url + "hostname%3A%5B'" + hostname + "'%5D"

    headers = CaseInsensitiveDict()
    headers["accept"] = "application/json"
    headers["authorization"] = "bearer " + access_token

    resp = requests.get(devices_request_url, verify=False, headers=headers)
    
    resp_json = resp.json()

    return resp_json['resources'][0]

def contain_host(host_id, selection):

    access_token = get_token()

    contain_host_request_url = api_baseurl + contain_host_url + selection
    
    headers = CaseInsensitiveDict()
    headers["accept"] = "application/json"
    headers["Content-Type"] = "application/json"
    headers["authorization"] = "bearer " + access_token
    
    data = '{  "action_parameters": [    {      "name": "%s",      "value": ""    }  ],  "ids": [    "%s"  ]}' % (selection, host_id)
    
    
    resp = requests.post(contain_host_request_url, verify=False, headers=headers, data=data)
    

def get_detections():

    access_token = get_token()
    get_detections_request_url = api_baseurl + "/detects/queries/detects/v1?limit=5&sort=first_behavior%7Cdesc"

    headers = CaseInsensitiveDict()
    headers["accept"] = "application/json"
    headers["authorization"] = "bearer " + access_token

    resp = requests.get(get_detections_request_url, verify=False, headers=headers)
    resp_json = resp.json()
    
    return resp_json

def get_detection_details(detection_id):
    get_detection_details_request_url = api_baseurl + "/detects/entities/summaries/GET/v1"

    access_token = get_token()

    headers = CaseInsensitiveDict()
    headers["accept"] = "application/json"
    headers["Content-Type"] = "application/json"
    headers["authorization"] = "bearer " + access_token

    data = '{  "ids": [    "%s"  ]}' % detection_id
    
    resp = requests.post(get_detection_details_request_url, verify=False, headers=headers, data=data)

    resp_json = resp.json()

    return resp_json   

def test_run_script(script, batch_id):
    
    access_token = get_token()

    headers = {
        'accept': 'application/json',
        'authorization':  'bearer %s' % (access_token)
        # Already added when you pass json= but not when you pass data=
        # 'Content-Type': 'application/json',
    }

    params = {
        'timeout': '30',
        'timeout_duration': '30s',
        'host_timeout_duration': '30s',
    }

    json_data = {
        'base_command': 'runsccript',
        'batch_id': '%s' % (batch_id),
        'command_string': 'runscript -CloudFile=%s' % (script),
        'optional_hosts': [
            '',
        ],
        'persist_all': True,
    }

    resp = requests.post('https://api.crowdstrike.com/real-time-response/combined/batch-admin-command/v1', params=params, headers=headers, json=json_data)
    print(resp)

def batch_run_script(script, batch_id):

    access_token = get_token()
    full_url = api_baseurl + batch_command_url
   
    headers = CaseInsensitiveDict()
    headers["accept"] = "application/json"
    headers["Content-Type"] = "application/json"
    headers["authorization"] = "bearer " + access_token
    

    #data = '{  "base_command": "runscript",  "batch_id": "%s",  "command_string": "runscript -CloudFile=%s",  "optional_hosts": [    ""    ],  "persist_all": true}' % (batch_id, script)
    data = "{  \"base_command\": \"runscript\",  \"batch_id\": \"%s\",  \"command_string\": \"runscript -CloudFile=%s\",  \"optional_hosts\": [      ],  \"persist_all\": true}" % (batch_id, script)
    print(data)

    #time.sleep(21)
    print(full_url)
    print(headers)
    resp = requests.post(full_url, verify=False, headers=headers, data=data) 
    print(resp)
    
def run_script(script, session_id):

    access_token = get_token()
    #session_id = start_session(device_id)
    command_request_url = api_baseurl + command_url 

    headers = CaseInsensitiveDict()
    headers["accept"] = "application/json"
    headers["Content-Type"] = "application/json"
    headers["authorization"] = "bearer " + access_token

    data = '{  "base_command": "runscript",  "command_string": "runscript -CloudFile=%s",  "device_id": "string",  "id": 0,  "persist": true,  "session_id": "%s"}' % (script, session_id)

    resp = requests.post(command_request_url, verify=False, headers=headers, data=data) 

def get_file(filename, batch_id, device_id):

    access_token = get_token()
    get_file_request_url = api_baseurl + get_file_url
   
    headers = CaseInsensitiveDict()
    headers["accept"] = "application/json"
    headers["Content-Type"] = "application/json"
    headers["authorization"] = "bearer " + access_token
    
    data = '{  "batch_id": "%s",  "file_path": "%s",  "optional_hosts": [    "%s"  ]}' % (batch_id, filename, device_id) 
    
    resp = requests.post(get_file_request_url, verify=False, headers=headers, data=data)
    resp_json = resp.json()
    return resp_json
    

def get_sha(batch_get_cmd_id, device_id):
    access_token = get_token()

    get_sha_request_url = "https://api.crowdstrike.com/real-time-response/combined/batch-get-command/v1?timeout=30&timeout_duration=30s&batch_get_cmd_req_id=%s" % batch_get_cmd_id

    headers = CaseInsensitiveDict()
    headers["accept"] = "application/json"
    headers["authorization"] = "bearer " + access_token
    
    resp = requests.get(get_sha_request_url, headers=headers)
    
    resp_json = resp.json()
    #return resp_json["resources"][device_id]["sha256"]
    return resp_json["resources"]

def download_file(session_id, sha, hostname, filename):
    access_token = get_token()
    #filename = "%s_netlogon.7z" % hostname
    request_filename = filename.split("/")[-1:]
    request_filename = str(request_filename[0])
    download_filename = hostname + "_" + request_filename + ".7z"
    url = "https://api.crowdstrike.com/real-time-response/entities/extracted-file-contents/v1?session_id=%s&sha256=%s&filename=netlogarino" % (session_id, sha)
    
    headers = CaseInsensitiveDict()
    headers["accept"] = "application/x-7z-compressed"
    headers["authorization"] = "bearer " + access_token
    
    
    resp = requests.get(url, headers=headers, stream=True)

    with open(download_filename, 'wb') as file:
        chunk_size=128
        for chunk in resp.iter_content(chunk_size=chunk_size):
            file.write(chunk)



def get_batch_id():

    access_token = get_token()
    get_batch_id_request_url = api_baseurl + get_batch_id_url

    headers = CaseInsensitiveDict()
    headers["accept"] = "application/json"
    headers["Content-Type"] = "application/json"
    headers["authorization"] = "bearer " + access_token


    resp = requests.post(get_batch_id_request_url, verify=False, headers=headers)

    print(resp.text)    

 
def clear_screen():

    # It is for MacOS and Linux(here, os.name is 'posix')
    if name == 'posix':
        _ = system('clear')
    else:
        # It is for Windows platfrom
        _ = system('cls')

