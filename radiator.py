#!/usr/bin/python


from datetime import datetime
from jira import JIRA, JIRAError

import StringIO
import hashlib
import json
import os
import os.path
import re
import shutil
import sqlite3
import subprocess
import sys
import syslog
import tarfile
import tempfile
import time
import traceback

LOG_FILE = "radiator.log"

def get_jira_version_id(jira, version):
    ''' This returns the ID jira uses for the version passed in. If the version
        is not found in JIRA, it is added. '''
 
    project = jira.project("CRSH")
    versions = jira.project_versions(project)
 
    for entry in versions:
        if entry.name == version:
            return entry.id
 
    # New version, add it to JIRA
    version = jira.create_version(version, "CRSH")
    return version.id


def get_jira_issue_fields_data(log, jira, crashdumpinfo):
    ''' Get the fields dictionary to pass to JIRA when creating an issue. '''
     
    version_id = get_jira_version_id(jira, crashdumpinfo.jira_version)
  
    mac_addresses = list()
    ip_addresses = list()
  
    for interface in crashdumpinfo.interfaces:
        ip_addresses.append("{}: {}".format(interface['name'], interface['ip']))
        mac_addresses.append("{}: {}".format(interface['name'], interface['mac']))
 
    description_summary = "Processing crash dump for `{}`\n" \
                          "Dump for v{}\n" \
                          "Crashdump was created '{}'\n" \
                          "Crash reason: {}\n" \
                          "Panel owner: {}\n" \
                          "Panel's IPs:\n" \
                          "{}\n" \
                          "Upload time: {}\n" \
                          "MD5: {}\n" \
                          "\n" \
                          "_NOTE: Upload time is more accurate time of crash if panel's time is off_".format(crashdumpinfo.application,
                                                                                                             crashdumpinfo.version,
                                                                                                             crashdumpinfo.crashtime_filename,
                                                                                                             crashdumpinfo.reason,
                                                                                                             crashdumpinfo.panel_info['owner'],
                                                                                                             "\n".join(ip_addresses),
                                                                                                             crashdumpinfo.crashtime_uploadtime,
                                                                                                             crashdumpinfo.md5)
  
    return {
               'project': {'key': "CRSH"},
               'summary': "{} @ {}, MAC {}".format(crashdumpinfo.application, crashdumpinfo.reason, crashdumpinfo.primary_mac),
               'description': "*Dump summary:*\n" + \
                   description_summary + "\n" + \
                   "\n\n" + \
                   "*Traceability Information (do not edit):*\n" + \
                   "\n".join(mac_addresses) + "\n"\
                   "Panel SW Version: {}\n".format(crashdumpinfo.version),
               'issuetype': {'name': 'Bug'},
               'versions': [{'id': version_id}],
               'customfield_10900': crashdumpinfo.primary_mac,
           }


def open_jira_issue(log, jira, crashdumpinfo):
    ''' Open a JIRA issue. '''
    
    issue = jira.create_issue(fields=crashdumpinfo.jira_fields_info)
    log.write("Created issue: {}\n".format(issue.key))
    
    issue.update(reporter={'name': crashdumpinfo.panel_info['reporter']})
    issue.update(fields={'labels': crashdumpinfo.labels_to_apply})
  
    jira.add_comment(issue, "Crashed Thread\n\n{noformat}"+crashdumpinfo.crashed_thread+"{noformat}")

    if crashdumpinfo.reason == "SIGABRT" and len(crashdumpinfo.log_lines) > 0:
        comment = "Last {} lines from /{}:\n\n".format(TAIL_LINES_FROM_GC3LOG, "var/log/gc3.log")
        comment += "{noformat}"
        comment += crashdumpinfo.log_lines
        comment += "{noformat}"
        jira.add_comment(issue, comment)
  
    # Attach the various bits of data / files to JIRA issue
    attachments = [
        {'name': 'crashdump.txt', 'contents': crashdumpinfo.stackwalk},
        {'name': 'threadlist.html', 'contents': crashdumpinfo.threadlistHTML}
    ]

    error_occurred = False
    
    # Attach with try..except inside loop so we attempt to add
    # as many attachments as possible in the face of errors
    for attachment in attachments:
        try:
            log.write("Adding: {}\n".format(attachment['name']))
            attach_file = StringIO.StringIO(attachment['contents'])
            attachment = jira.add_attachment(issue, attachment=attach_file, filename=attachment['name'])
                
        except JIRAError as e:
            jira.add_comment(issue, str(e))
            error_occurred = True
    
    # Attach the crashdump archive
    try:
        with open(crashdumpinfo.dumpfilename, 'rb') as file_to_attach:
            jira.add_attachment(issue.key, file_to_attach)
            
    except JIRAError as e:
        jira.add_comment(issue, str(e))
        error_occurred = True

    # Deal with any errors that occurred
    if error_occurred:
        log.write("Error while adding attachments: {}\nIssue {}\n".format(crashdumpinfo,str(issue)))
        jira.transition_issue(issue, BAD_AUTO_CREATE_TRANSITION_ID)
        
    # Auto-withdraw issue
#    if crashdumpinfo.autowithdraw:
#        jira.transition_issue(issue, WITHDRAW_TRANSITION_ID)


if __name__ == '__main__':

    try:
        logfile = open(LOG_FILE, "a")
        logfile.write("=========== START: {} ==========\n".format(datetime.now()))

        jira = JIRA('https://2gig-technologies.atlassian.net', basic_auth=('jirabot', 'n0rt3ksc'))

        logfile.write("=========== END  : {} ==========\n".format(datetime.now()))

    except JIRAError as e:
        logfile.write("Error connecting to JIRA: {}\n".format(e))

    except IOError as e:
        syslog.syslog("jirabot: I/O error trying to open logfile ({0}): {1}".format(e.errno, e.strerror))
        sys.exit(1)
        
    except:
        logfile.write("Error:\n{}".format(traceback.format_exc()))

    finally:
        if logfile:
            logfile.close()

    sys.exit(0)
    
