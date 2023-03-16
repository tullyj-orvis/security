#!/bin/python
import requests
from secrets import *

url = "https://qualysapi.qg2.apps.qualys.com/api/2.0/fo/report/"

payload={'action': 'launch',
        'template_id': '2442452',
        'report_title': 'API - Host Based Findings [TEST]',
        'output_format': 'xml'}

headers = {
          'X-Requested-With': 'QualysTest',
            'Authorization': 'Basic %s' % creds
            }

response = requests.request("POST", url, headers=headers, data=payload)

print(response.text)
