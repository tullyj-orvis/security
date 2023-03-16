#!/bin/python

import requests
from secrets import *
import xml.etree.ElementTree as ET

report_title = input("Report Title: ")
url = "https://qualysapi.qg2.apps.qualys.com/msp/report_template_list.php"


payload={}
headers = {
  'X-Requested-With': 'QualysPostman',
  'Authorization': 'Basic %s' % creds
}

response = requests.request("POST", url, headers=headers, data=payload)

with open('test.xml', 'wb') as f:
    f.write(response.content)



tree = ET.parse('./test.xml')   # import xml from
root = tree.getroot()  

reports_list = []

for item in root.findall('./REPORT_TEMPLATE'):    # find all projects node
    reports = {}              # dictionary to store content of each projects
    reports_global = item.attrib
    reports.update(reports_global) # make reports_global the first key of the dict
    for child in item:
      reports[child.tag] = child.text
    reports_list.append(reports)
report = next(item for item in reports_list if item["TITLE"] == "%s" % report_title)
print(report["ID"])
