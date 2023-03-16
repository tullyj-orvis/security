#!/bin/python

import requests
from secrets import *

url = "https://qualysapi.qg2.apps.qualys.com/msp/report_template_list.php"

payload={}
headers = {
  'X-Requested-With': 'QualysPostman',
  'Authorization': 'Basic %s' % creds
}

response = requests.request("POST", url, headers=headers, data=payload)

print(response.text)
