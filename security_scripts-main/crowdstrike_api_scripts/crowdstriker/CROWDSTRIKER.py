#!/bin/python

import json
import requests
import time
import pprint 
import warnings
from crowdstrike import *
from secrets import *
from requests.structures import CaseInsensitiveDict
from os import system, name
from termcolor import colored
banner = r"""
                    
         _____ _____   ______          _______   _____ _______ _____  _____ _  ________ _____  
       /  ____|  __ \ / __ \ \        / /  __ \ / ____|__   __|  __ \|_   _| |/ /  ____|  __ \ 
       | |    | |__) | |  | \ \  /\  / /| |  | | (___    | |  | |__) | | | | ' /| |__  | |__) |
       | |    |  _  /| |  | |\ \/  \/ / | |  | |\___ \   | |  |  _  /  | | |  < |  __| |  _  / 
       | |____| | \ \| |__| | \  /\  /  | |__| |____) |  | |  | | \ \ _| |_| . \| |____| | \ \ 
        \_____|_|  \_\\____/   \/  \/   |_____/|_____/   |_|  |_|  \_\_____|_|\_\______|_|  \_\
                                                                                                         
                                                                                                 
        """

def token():
    access_token = get_token()
    clear_screen()
    print(banner)
    print("Access Token: \n")
    print(access_token)
    input("\n\nPress any key to return to main menu.")
    main()

def network_contain():
    clear_screen()
    print(banner)
    hostname = input("Hostname: ")
    host_id = get_device(hostname)
    action = input("Select an action by number: \n1: Network Contain Host\n2: Lift Network Containment on Host\n> ") 

    if action == "1":
        selection = "contain"
        contain_host(host_id, selection)
        print("%s has been network contained." % hostname)
    elif action == "2":
        selection = "lift_containment"
        contain_host(host_id, selection)
        print("%s has been lifted from network containment." % hostname)
    else:
        print("Please select a valid option.")

    input("\n\nPress any key to return to main menu.")
    main()

def download_file_from_host(): 
    clear_screen()
    print(banner)
    resources = {}
    hostname = input("Hostname: ")
    filename = input("Full path and filename for file to download from %s.\nUse forward slashes ( / ) for all operating systems.\n> " % hostname)
    print("Initializing session on %s...\n" % hostname)
    device_id = get_device(hostname)
    access_token = get_token()
    resp_json = start_batch_session(device_id)
    batch_id = resp_json['batch_id']
    session_id = resp_json['resources'][device_id]['session_id']
    command_request_url = api_baseurl + command_url

    print("Sending request...")
    get_file_resp = get_file(filename, batch_id, device_id)
    batch_get_cmd_id = get_file_resp["batch_get_cmd_req_id"]
    dots = ""
    while not resources:
        clear_screen()
        print(banner)
        print("Sending request..." + dots)
        resources = get_sha(batch_get_cmd_id, device_id)
        dots += "."
    sha = resources[device_id]["sha256"]
    session_id = resources[device_id]["session_id"]
    print("Downloading %s...\n" % (filename))
    download_file(session_id, sha, hostname, filename)
    
    input("Press any key to return to main menu.")
    main()


def modify_netlogon(): 
    filename = "C:/windows/debug/netlogon.log"
    resources = {}
    hostname = input("Hostname: ")
    clear_screen()
    print(banner)
    print("Initializing session on %s...\n" % hostname)
    device_id = get_device(hostname)
    access_token = get_token()
    resp_json = start_batch_session(device_id)
    batch_id = resp_json['batch_id']
    session_id = resp_json['resources'][device_id]['session_id']
    command_request_url = api_baseurl + command_url
    action = input("Select an action by number: \n1: Enable NetLogon\n2: Stop Netlogon\n3: Start Netlogon\n4: Disable Netlogon\n5: Get Netlogon logfile\n> ")

    if action == "1":
        script = "enable-netlogon.ps1"
        print("Enabling NetLogon on %s...\n" % hostname)
        run_script(script, session_id)
        print("NetLogon enabled on %s.\n" % hostname)

    elif action == "2":
        script = "stop-netlogon.ps1"
        print("Stopping NetLogon on %s...\n" % hostname)
        run_script(script, session_id)
        print("NetLogon stopped on %s.\n" % hostname)

    elif action == "3":
        script = "start-netlogon.ps1"
        print("Starting NetLogon on %s...\n" % hostname)
        run_script(script, session_id)
        print("NetLogon started on %s.\n" % hostname)

    elif action == "4":
        script = "disable-netlogon.ps1"
        print("Disabling NetLogon on %s...\n" % hostname)
        run_script(script, session_id)
        print("NetLogon disabled on %s.\n" % hostname)

    elif action == "5":
        clear_screen()
        print(banner)
        print("Sending request...")
        get_file_resp = get_file(filename, batch_id, device_id)
        batch_get_cmd_id = get_file_resp["batch_get_cmd_req_id"]
        dots = ""
        while not resources:
            clear_screen()
            print(banner)
            print("Sending request..." + dots)
            resources = get_sha(batch_get_cmd_id, device_id)
            dots += "."
        sha = resources[device_id]["sha256"]
        session_id = resources[device_id]["session_id"]
        print("Downloading %s_netlogon.7z...\n" % hostname)
        download_file(session_id, sha, hostname)

    else:
        print("Please enter a valid selection.")
    
    input("Press any key to return to main menu.")
    main()


def detections():
    clear_screen()
    banner = r"""
  _      _______      ________                _      ______ _____ _______ _____
 | |    |_   _\ \    / /  ____|         /\   | |    |  ____|  __ \__   __/ ____|
 | |      | |  \ \  / /| |__           /  \  | |    | |__  | |__) | | | | (___
 | |      | |   \ \/ / |  __|         / /\ \ | |    |  __| |  _  /  | |  \___ \
 | |____ _| |_   \  /  | |____       / ____ \| |____| |____| | \ \  | |  ____) |
 |______|_____|   \/   |______|     /_/    \_\______|______|_|  \_\ |_| |_____/

"""
    print(banner)
    detections_json = get_detections()
    while(True):    
        output = ""
        for i in detections_json["resources"]:
            detection_details = get_detection_details(i)
            ctg = detection_details["resources"][0]["behaviors"][0]["control_graph_id"]
            ctg = ctg.split(":")
            timestamp = detection_details["resources"][0]["behaviors"][0]["timestamp"]
            cmd = detection_details["resources"][0]["behaviors"][0]["cmdline"]
            filename = detection_details["resources"][0]["behaviors"][0]["filename"]
            severity = detection_details["resources"][0]["max_severity_displayname"]
            hostname = detection_details["resources"][0]["device"]["hostname"]
            assigned_to = detection_details["resources"][0]["assigned_to_name"]
            description = detection_details["resources"][0]["behaviors"][0]["description"]
            scenario = detection_details["resources"][0]["behaviors"][0]["scenario"]
            tactic = detection_details["resources"][0]["behaviors"][0]["tactic"]
            status = detection_details["resources"][0]["status"]
            timestamp = timestamp.split("T")
            if status == "open" or status == "reopened":
                status = colored(status, 'red')

            if severity == "Low":
                severity = colored(severity, 'green')
            elif severity == "Medium":
                severity = colored(severity, 'yellow', attrs=['bold'])
            elif severity == "High":
                severity = colored(severity, 'red', attrs=['bold'])
            elif severity == "Critical":
                severity = colored(severity, 'red', attrs=['bold', 'blink'])

            output += r"""
Time: %s
Severity:  %s
Hostname: %s
Assigned To: %s
Description: %s
Filename: %s
Command Line: %s
Scenario: %s
Tactic: %s
Status: %s
URL: https://falcon.crowdstrike.com/activity/detections/detail/%s/%s
""" % (timestamp, severity, hostname, assigned_to, colored(description, 'cyan'), filename, cmd, scenario, tactic, status, ctg[1], ctg[2])
        clear_screen()
        print(banner)
        print(output)

        time.sleep(11)




def main():
    clear_screen()
    print(r"""
                    
         _____ _____   ______          _______   _____ _______ _____  _____ _  ________ _____  
       /  ____|  __ \ / __ \ \        / /  __ \ / ____|__   __|  __ \|_   _| |/ /  ____|  __ \ 
       | |    | |__) | |  | \ \  /\  / /| |  | | (___    | |  | |__) | | | | ' /| |__  | |__) |
       | |    |  _  /| |  | |\ \/  \/ / | |  | |\___ \   | |  |  _  /  | | |  < |  __| |  _  / 
       | |____| | \ \| |__| | \  /\  /  | |__| |____) |  | |  | | \ \ _| |_| . \| |____| | \ \ 
        \_____|_|  \_\\____/   \/  \/   |_____/|_____/   |_|  |_|  \_\_____|_|\_\______|_|  \_\
                                                                                                         
                                                                                                 
        """)
    
    selection = input("Select an option by number: \n1: Alerts\n2: Netlogon\n3: Get Access Token\n4: Download file from host\n5: Control host network containment\n> ")
    
    if selection == "1":
        detections()
    elif selection == "2":
        modify_netlogon()
    elif selection == "3":
        token()
    elif selection == "4":
        download_file_from_host()
    elif selection == "5":
        network_contain()

#Change this to more specific SSL warning on windows workstations
warnings.filterwarnings("ignore")
main()
