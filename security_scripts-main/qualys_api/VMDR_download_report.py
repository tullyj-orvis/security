#!/bin/python
from secrets import *
import requests

url = "https://qualysapi.qg2.apps.qualys.com/api/2.0/fo/report/"

payload={'action': 'fetch',
'id': '12112896'}

headers = {
  'X-Requested-With': 'QualysPostman',
  'Authorization': 'Basic %s' % creds
}

response = requests.request("POST", url, headers=headers, data=payload)

print(response.text)

