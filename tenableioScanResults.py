#!/usr/bin/env python3

import sys,os,getopt
import traceback
import io
import os
import fcntl
import json
import time
import csv
import requests
from random import randrange
from datetime import datetime
from tenable.io import TenableIO

from six import PY2

if PY2:
    get_unicode_string = unicode
else:
    get_unicode_string = str


import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, './ds-integration')
from DefenseStorm import DefenseStorm

class integration(object):

    payload = {
        "format": "csv",
        "reportContents": {
            "csvColumns": {
                "id": True,
                "cve": True,
                "cvss": True,
                "risk": True,
                "hostname": True,
                "protocol": True,
                "port": True,
                "plugin_name": True,
                "synopsis": True,
                "description": True,
                "solution": True,
                "see_also": True,
                "plugin_output": False,
                "stig_severity": True,
                "cvss3_base_score": True,
                "cvss_temporal_score": True,
                "cvss3_temporal_score": True,
                "risk_factor": True,
                "references": True,
                "plugin_information": True,
                "exploitable_with": True
            }
        },
        "extraFilters": {
            "host_ids": [],
            "plugin_ids": []
        }
    }

    def get_scan(self, scan_id, outfile, out_format = 'nessus'):
        outfile = outfile + '.' + out_format
        URL = self.url + "/scans/" + str(scan_id) + "/export"
        this_payload = self.payload
        this_payload['format'] = out_format
        r = requests.post(url = URL, headers=self.headers, data = json.dumps(self.payload), verify = False)
        jsonData = r.json()
        scanFile = str(jsonData['file'])
        scanToken = str(jsonData['token'])
        status = "loading"
        while status != 'ready':
            URL = self.url + "/scans/" +str(scan_id) + "/export/" + scanFile + "/status"
            t = requests.get(url = URL, headers=self.headers, verify = False)
            data = t.json()
            if data['status'] == 'ready':
                status = data['status']
            else:
                time.sleep(int(self.sleep_period))
        URL = self.url + "/scans/" + str(scan_id) + "/export/" + scanFile + "/download"
        d = requests.get(url = URL, headers=self.headers, verify = False)
        f = open(outfile, 'wb').write(d.content)

    def get_scan_download_list(self, folders):
        scan_download_list = []
        for folder in folders:
            for item in self.scan_list:
                if item['folder'] == folder['name']:
                    scan_list = self.get_scan_list(str(folder['id']))
                    if scan_list != None:
                        for scan in scan_list:
                            if scan['status'] == 'completed':
                                scan_download_list.append({'folder': folder['name'], 'id':scan['id'], 'name':scan['name'], 'last_modification_date':scan['last_modification_date']})
                                self.ds.log("INFO", "Collecting Scans from folder " + folder['name'] + '(' + str(folder['id']) + '): ' + scan['name'] + '(' + str(scan['id']) + ') - ' + (datetime.utcfromtimestamp(int(scan['last_modification_date']))).strftime('%Y-%m-%d %H%M%S'))
                    else:
                        self.ds.log("INFO", "Collecting Scans from folder " + folder['name'] + '(' + str(folder['id']) + '): ' + 'None')
        return scan_download_list


    def send_scan_to_grid(self, filename):
        event_list = []
        with open(filename, 'r') as f:
            dicted = csv.DictReader(f)
            vulns = list(dicted)
            for entry in vulns:
                for key in entry:
                    if entry[key] == "":
                        entry[key] = "None"
                entry['message'] = 'Scan Result - ' + entry['Synopsis']
                entry['hostname'] = 'tenable.io'
                self.ds.writeJSONEvent(entry)

    def nessus_main(self): 

        # Get JDBC Config info
        try:
            self.state_dir = self.ds.config_get('tenable', 'state_dir')
            self.days_ago = self.ds.config_get('tenable', 'days_ago')
            self.last_run = self.ds.get_state(self.state_dir)
            access_key = self.ds.config_get('tenable', 'access_key')
            secret_key = self.ds.config_get('tenable', 'secret_key')
            self.tio = TenableIO(access_key = access_key, secret_key = secret_key)
            self.time_format = "%Y-%m-%d %H:%M:%S"

            current_time = time.time()

            if self.last_run == None:
                self.ds.log("INFO", "No previous state.  Collecting logs for last " + str(self.days_ago) + " days")
                self.last_run = current_time - ( 60 * 60 * 24 * int(self.days_ago))
            self.current_run = current_time
        except Exception as e:
                traceback.print_exc()
                self.ds.log("ERROR", "Failed to get required configurations")
                self.ds.log('ERROR', "Exception {0}".format(str(e)))
                return

        scan_list = self.tio.scans.list(last_modified=datetime.fromtimestamp(self.last_run))
        for scan in scan_list:
            details = self.tio.scans.results(scan['id'])
            completed = [h for h in details.get('history', list())
                if h.get('status') == 'completed']
            if len(completed) > 0:
                history = completed[0]
                filename = (scan['name'] + '-' + (datetime.utcfromtimestamp(history['last_modification_date'])).strftime('%Y-%m-%d %H:%M:%S') + 'Z').replace(' ', '_')
                with open(filename + '.csv', 'wb') as report_file:
                    self.tio.scans.export(scan['id'], format='csv', fobj=report_file)
                #with open(filename + '.nessus', 'wb') as report_file:
                    #self.tio.scans.export(scan['id'], format='nessus', fobj=report_file)
                self.send_scan_to_grid(filename=filename+".csv")
                os.remove(filename+".csv")

        self.ds.set_state(self.state_dir, self.current_run)
        self.ds.log('INFO', "Done Sending Notifications")


    def run(self):
        try:
            pid_file = self.ds.config_get('tenable', 'pid_file')
            fp = io.open(pid_file, 'w')
            try:
                fcntl.lockf(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except IOError:
                self.ds.log('ERROR', "An instance of this integration is already running")
                # another instance is running
                sys.exit(0)
            self.nessus_main()
        except Exception as e:
            traceback.print_exc()
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return
    
    def usage(self):
        print
        print (os.path.basename(__file__))
        print
        print ('  No Options: Run a normal cycle')
        print
        print ('  -t    Testing mode.  Do all the work but do not send events to GRID via ')
        print ('        syslog Local7.  Instead write the events to file \'output.TIMESTAMP\'')
        print ('        in the current directory')
        print
        print ('  -l    Log to stdout instead of syslog Local6')
        print
    
    def __init__(self, argv):

        self.testing = False
        self.send_syslog = True
        self.ds = None
        self.conf_file = None

        self.conn_url = None
    
        try:
            opts, args = getopt.getopt(argv,"htnld:c:",["datedir="])
        except getopt.GetoptError:
            self.usage()
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                self.usage()
                sys.exit()
            elif opt in ("-t"):
                self.testing = True
            elif opt in ("-l"):
                self.send_syslog = False
            elif opt in ("-c"):
                self.conf_file = arg
    
        try:
            self.ds = DefenseStorm('tenableioScanResults', testing=self.testing, send_syslog = self.send_syslog, config_file = self.conf_file)
        except Exception as e:
            traceback.print_exc()
            try:
                self.ds.log('ERROR', 'ERROR: ' + str(e))
            except:
                pass


if __name__ == "__main__":
    i = integration(sys.argv[1:]) 
    i.run()
