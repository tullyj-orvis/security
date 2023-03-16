#!/bin/python
import requests
from secrets import *

url = "https://qualysapi.qg2.apps.qualys.com/qps/rest/3.0/count/was/finding"

xml = """<ServiceRequest>
<filters>
    <Criteria field="webApp.name" operator="EQUALS">Members WAS</Criteria>
</filters>
</ServiceRequest>"""

files={}
headers = {
  'Authorization': 'Basic %s' % creds,
  'Content-Type': 'text/xml'
}

response = requests.request("POST", url, headers=headers, data=xml, files=files)

print(response.text)

