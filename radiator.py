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

BAD_AUTO_CREATE_TRANSITION_ID = 141
BAD_DUMP_FILE_TRANSITION_ID = 201
WITHDRAW_TRANSITION_ID = 91
TAIL_LINES_FROM_GC3LOG = 20

DATABASE = '/var/lib/jirabot/panels.db'
CRASHDUMPPATHS = [
    "/home/users/jenkins/processing"
]
SUNSET_VERSION = "0.26.21"


class CrashDumpInfo:
    def __init__(self):
        self.application            = 'Unknown'
        self.dumpfilename           = 'Unknown'
        self.bad_crashdumps_dir     = ''
        self.version                = 'Unknown'
        self.jira_version           = 'Unknown'
        self.reason                 = 'Unknown'
        self.address                = 'Unknown'
        self.interfaces             = []
        self.labels_to_apply        = []
        self.crashtime_filename     = ''
        self.crashtime_uploadtime   = ''
        self.is_lame_duck           = False
        self.extract_folder         = ''
        self.is_eng_build           = False
        self.primary_mac            = ''
        self.eth_mac                = ''
        self.wifi_mac               = ''
        self.autowithdraw           = False
        self.md5                    = ''
        self.panel_info             = {}
        self.jira_fields_info       = {}
        self.log_lines              = ''
        self.stackwalk              = ''
        self.crashed_thread         = ''
        self.threadlistHTML         = ''

    def __str__(self):
        return "**CrashDumpInfo**\n" \
               "    application          : {}\n" \
               "    dumpfilename         : {}\n" \
               "    bad_crashdumps_dir   : {}\n" \
               "    version              : {}\n" \
               "    jira_version         : {}\n" \
               "    reason               : {}\n" \
               "    address              : {}\n" \
               "    interfaces           : {}\n" \
               "    labels_to_apply      : {}\n" \
               "    crashtime_filename   : {}\n" \
               "    crashtime_uploadtime : {}\n" \
               "    is_lame_duck         : {}\n" \
               "    extract_folder       : {}\n" \
               "    is_eng_build         : {}\n" \
               "    primary_mac          : {}\n" \
               "    eth_mac              : {}\n" \
               "    wifi_mac             : {}\n" \
               "    autowithdraw         : {}\n" \
               "    md5                  : {}\n" \
               "    panel_info           : {}\n" \
               "    jira_fields_info     : {}\n" \
               "    log_lines            : {}\n" \
               "    stackwalk            : {}\n" \
               "    crashed_thread       : {}\n" \
               "    threadlistHTML       : {}\n".format(self.application,
                                                        self.dumpfilename,
                                                        self.bad_crashdumps_dir,
                                                        self.version,
                                                        self.jira_version,
                                                        self.reason,
                                                        self.address,
                                                        self.interfaces,
                                                        self.labels_to_apply,
                                                        self.crashtime_filename,
                                                        self.crashtime_uploadtime,
                                                        self.is_lame_duck,
                                                        self.extract_folder,
                                                        self.is_eng_build,
                                                        self.primary_mac,
                                                        self.eth_mac,
                                                        self.wifi_mac,
                                                        self.autowithdraw,
                                                        self.md5,
                                                        self.panel_info,
                                                        self.jira_fields_info,
                                                        "YES" if len(self.log_lines) > 0 else "NO",
                                                        "YES" if len(self.stackwalk) > 0 else "NO",
                                                        "YES" if len(self.crashed_thread) > 0 else "NO",
                                                        "YES" if len(self.threadlistHTML) > 0 else "NO")



def get_panel_info_from_db(mac):
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM panel_info WHERE mac = ?", [mac])
    result = cursor.fetchone()
    connection.close()
    
    return result


def get_panel_info(mac):
    info = get_panel_info_from_db(mac)
    
    if info:
        return list(info)[1:]
    else:
        return None


def add_mac_to_panel(panel_id, mac, device_type):
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()
    
    cursor.execute(r'INSERT INTO "macs" (mac,deviceid,panelid) VALUES (?,?,?)', [mac, device_type, panel_id])
    connection.commit()
    connection.close()


def add_eth_mac_to_panel(panel_id, mac):    
    add_mac_to_panel(panel_id,mac,1)


def add_wifi_mac_to_panel(panel_id, mac):    
    add_mac_to_panel(panel_id,mac,2)


def add_panel_to_db(wifi_mac, eth_mac):
    ''' This adds panel and it's MACs to DB '''

    # Short circuit if no macs
    if not wifi_mac and not eth_mac:
        return

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    # Add panel to DB and get the panelid
    # YUCK - magic number for panels.ownerid in DB (should query these from DB on startup)
    cursor.execute(r'INSERT INTO "panels" (ownerid,paneldescr) VALUES(?,?)', [0, 'Added by jirabot'])
    cursor.execute(r'SELECT MAX(panelid) FROM panels')
    new_panel_id = cursor.fetchone()[0]

    # Close DB connection here to avoid "locked database" errors
    connection.commit()
    connection.close()

    # Add the panel's MACs to the DB
    # YUCK - magic numbers for devices.deviceid in DB (should query these from DB on startup)
    if wifi_mac:
        add_wifi_mac_to_panel(new_panel_id,wifi_mac)

    if eth_mac:
        add_eth_mac_to_panel(new_panel_id, eth_mac)


def get_panel_id_from_mac(mac):
    result = get_panel_info_from_db(mac)
    return result[1] if result else None


def update_db_with_panel_macs(wifi_mac, eth_mac):
    
    # Nothing to do if neither mac given
    if not wifi_mac and not eth_mac:
        return
    
    panel_id_from_wifi = get_panel_id_from_mac(wifi_mac)
    panel_id_from_eth = get_panel_id_from_mac(eth_mac)
    
    # Both macs exist in DB, nothing to update
    if panel_id_from_wifi and panel_id_from_eth:
        return
    
    # Neither mac exsits in DB, add panel and macs together
    if not panel_id_from_wifi and not panel_id_from_eth:
        add_panel_to_db(wifi_mac, eth_mac)
        
    # Add wifi mac if needed
    if wifi_mac and panel_id_from_eth:
        add_wifi_mac_to_panel(panel_id_from_eth, wifi_mac)
    
    # Add eth mac if needed
    if eth_mac and panel_id_from_wifi:
        add_eth_mac_to_panel(panel_id_from_wifi, eth_mac)


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


def set_jira_labels(log, crashdumpinfo):
  
    if re.search(r'\bbeta\b', crashdumpinfo.panel_info['group'], re.IGNORECASE):
        crashdumpinfo.labels_to_apply.append('BetaUser')
  
    if re.search(r'\bsoak\b', crashdumpinfo.panel_info['group'], re.IGNORECASE):
        crashdumpinfo.labels_to_apply.append('SoakPanel')


def update_panel_info(log, crashdumpinfo):

    update_db_with_panel_macs(crashdumpinfo.wifi_mac, crashdumpinfo.eth_mac)
    panel_info = get_panel_info(crashdumpinfo.primary_mac)
    
    if panel_info:
        crashdumpinfo.panel_info = { 'panelid' : panel_info[0],
                                     'owner'   : panel_info[1],
                                     'reporter': panel_info[2],
                                     'assignee': panel_info[3],
                                     'group'   : panel_info[4] }
    
    crashdumpinfo.jira_fields_info = get_jira_issue_fields_data(log, jira, crashdumpinfo)


def process_syslog(log, crashdumpinfo):
    ''' Grab the last X lines of the GC3 logfile. '''
    
    gc3_syslog = "{}/{}".format(crashdumpinfo.extract_folder, "var/log/gc3.log")
 
    # Older crashdumps don't have the gc3.log file (don't propogate exception)
    try:
        with open(gc3_syslog, 'r') as gc3_logfile:
            lines = gc3_logfile.readlines()
            lines = map(lambda s: s.strip(), lines)
        
        # Apply special JIRA label when deadlock error occurs
        if re.search(r'deadlock detected!', " ".join(lines), re.IGNORECASE):
            crashdumpinfo.labels_to_apply.append('Deadlock')
            
        crashdumpinfo.log_lines = "\n".join(lines[-TAIL_LINES_FROM_GC3LOG:])

    except IOError as e:
        log.write(str(e) + "\n")
        crashdumpinfo.log_lines = "GC3 log not available"
        
    except:
        pass
        

def process_stackwalk_into_html(log, crashdumpinfo):
    
    crashdumpinfo.reason    = re.search(r'^Crash reason:\s+(.*?)$', crashdumpinfo.stackwalk, re.MULTILINE).group(1)
    crashdumpinfo.address   = re.search(r'^Crash address:\s+(.*?)$', crashdumpinfo.stackwalk, re.MULTILINE).group(1)

    # Extract the info for each of the threads
    threads = re.findall(r'(Thread.*?)\n\n', crashdumpinfo.stackwalk, re.MULTILINE|re.DOTALL)

    # Get crashed thread info and generate HTML to be inserted later
    stackhtml = ''
    for threadinfo in threads:
        threadheader, threadid, is_crashed = re.search(r'^(Thread\s+(\d+)\s*?(\(crashed\))?)$', threadinfo, re.M).groups()
        threadcallstack = re.findall(r'^\s*\d+.*?$', threadinfo, re.MULTILINE)

        # Check if this is the thread that crashed
        if is_crashed:
            crashdumpinfo.crashed_thread = "{}\n{}".format(threadheader, "\n".join(threadcallstack))

        # Gather the backtraces for each thread into single hunk of HTML (to be inserted into larger HTML document later) 
        stackhtml += '<div style="overflow: hidden">\n' \
                     '<a style="float: left; width: 200px"  href="javascript:t(document.getElementById(\'t{t_id}\'))">{t_header}</a>\n' \
                     '<div style="float: left; margin-bottom: 2px">\n' \
                     '<div class="expanded">{callstack_line1}</div>\n' \
                     '<div class="closed" id="t{t_id}">\n{callstack_line2plus}\n' \
                     '<div style="height: 10px"></div>\n' \
                     '</div>\n' \
                     '</div>\n' \
                     '</div>\n'.format(t_id=threadid,
                                       t_header=threadheader,
                                       callstack_line1=threadcallstack[0],
                                       callstack_line2plus="\n".join(threadcallstack[1:]))

    crashdumpinfo.threadlistHTML = r"""
        <html><head>
        <style>
        a { font-family: monospace; }
        .closed, .expanded { font-family: monospace; margin: 0em; white-space: pre; }
        .closed { display: none; }
        .expanded { display: inline; }
        </style>
        <script type="text/javascript">function t(e){e.className = (e.className == 'closed')?'expanded':'closed';}</script>
        </head>
        <body>
        """ + stackhtml + """
        </body>
        </html>
        """


def process_panel_interfaces_info(log, crashdumpinfo):
    ''' Extracts the list of interfaces with their IPs and MACs of the panel from the IP info file '''
    ipinfofile = "{}/{}".format(crashdumpinfo.extract_folder, "tmp/ip_info.txt")

    with open(ipinfofile, 'r') as fp:
        sections = re.findall(r'.*?\n\n', fp.read(), re.M|re.S)

    # Get the IP addresses of various interfaces
    for section in sections:
        interface_name = re.search(r'^\w+', section, re.M).group(0)

        # Ignore the loopback (lo) and 6to4 tunnel interfaces (sit0)
        if interface_name == 'lo' or interface_name == 'sit0':
            continue

        interface = {'name': interface_name, 'ip': 'N/A', 'mac': 'N/A'}

        # Make sure we end up with a valid list (even if empty)
        regex = re.search(r'addr:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', section)
        if regex:
            interface['ip'] = regex.group(1)

        regex = re.search(r'HWaddr (\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2})', section)
        if regex:
            interface['mac'] = regex.group(1).replace(':', '')

        # Store macs for easier reference later
        if interface_name == 'wlan0':
            crashdumpinfo.wifi_mac = interface['mac']
        elif interface_name == 'eth0':
            crashdumpinfo.eth_mac = interface['mac']
            
        crashdumpinfo.interfaces.append(interface)

    # Simplify logic later by picking a primary mac here
    crashdumpinfo.primary_mac = crashdumpinfo.wifi_mac if crashdumpinfo.wifi_mac else crashdumpinfo.eth_mac


def process_minidump(log, crashdumpinfo):
    ''' Generates a stackwalk from a minidump and returns the fully-qualified
        path to the stackwalk file. If no minidump found, it returns None. '''

    minidumpdir = "{}/{}".format(crashdumpinfo.extract_folder, "tmp")

    for entry in os.listdir(minidumpdir):
        if os.path.splitext(entry)[1] != r'.dmp':
            continue

        # Found a minidump file, generate stackwalk
        minidump = "{}/{}".format(minidumpdir, entry)
        
        proc = subprocess.Popen(["minidump_stackwalk", minidump, "/usr/crashdump/symbols"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (output, err) = proc.communicate()
        
        if proc.returncode == 0:
            crashdumpinfo.stackwalk = output
            process_stackwalk_into_html(log, crashdumpinfo)
    
        else:
            raise Exception("Error generating stackwalk, output:\n{}".format(err))


def process_crash_build_version(log, crashdumpinfo):

    jsonfile = "{}/{}".format(crashdumpinfo.extract_folder, 'boot/gc3_versions.json')
    releasefile = "{}/{}".format(crashdumpinfo.extract_folder, 'boot/release.version')

    # Get version info from whichever version file is found
    if os.path.isfile(jsonfile):
        with open(jsonfile, 'r') as fp:
            data = json.load(fp)

        version = '.'.join([data['Major'], data['Minor'], data['Hotfix'], data['Application']])
        jira_version = '.'.join([data['Major'], data['Minor'], data['Hotfix']])

        # Treat all old builds as release builds
        is_eng_build = False

    elif os.path.isfile(releasefile):
        with open(releasefile, 'r') as fp:
            version = fp.readline().rstrip()
            jira_version = re.match(r'(\d+\.\d+\.\d+)', version).group(1)
            is_eng_build = fp.readline().rstrip() == 'ENG'

    else:
        log.write("WARNING: No version file found\n")
        return

    # Determine if we should auto-withdraw this crashdump (eg. old, unsupported version)
    log.write("Current version: {}\nSunset version : {}\n".format(jira_version, SUNSET_VERSION))
    for (withdraw, current) in zip(SUNSET_VERSION.split('.'), jira_version.split('.')):
        if int(current) <= int(withdraw):
            autowithdraw = True

    # Store data
    crashdumpinfo.autowithdraw = autowithdraw
    crashdumpinfo.version = version
    crashdumpinfo.jira_version = jira_version
    crashdumpinfo.is_eng_build = is_eng_build


def process_dumpfile_contents(log, crashdumpinfo):
    ''' Extract the files from the crashdump file and populate the data structure fields. '''

    extractdir = tempfile.mkdtemp()

    # Save current dir before changing to new dir
    original_dir = os.getcwd()
    os.chdir(extractdir)

    try:
        archive = tarfile.open(crashdumpinfo.dumpfilename)
        archive.extractall()

        crashdumpinfo.extract_folder = extractdir
        
        # Process contents...
        process_crash_build_version(log, crashdumpinfo)
        process_minidump(log, crashdumpinfo)
        process_panel_interfaces_info(log, crashdumpinfo)
        process_syslog(log, crashdumpinfo)

    except:
        crashdumpinfo.is_lame_duck = True
        raise

    finally:
        # Remove temporary directory and go back to original dir
        shutil.rmtree(crashdumpinfo.extract_folder, ignore_errors=True)
        os.chdir(original_dir)


def process_crashdump_metadata(log, crashdumpinfo):
    ''' Retuns the formatted creation time of the crashdump file on the local machine. '''
    
    dumpfiletime = time.ctime(os.path.getctime(crashdumpinfo.dumpfilename))
    crashdumpinfo.crashtime_uploadtime = datetime.strptime(dumpfiletime, "%a %b %d %H:%M:%S %Y")


def process_filename_metadata(log, crashdumpinfo):
    ''' Examines the filename and attempts to find crashing application name
        and the crash time. Attempts to handle non-standard filenames.
        
        NOTE: Expected filename format: <app>_<mac>_<date>T<time> '''
    
    directory, filename = os.path.split(crashdumpinfo.dumpfilename)
    
    # Strip off file extension
    filename, extension = filename.split('.', 1)
    
    fn_parts = filename.split('_')
    non_standard = len(fn_parts) != 3

    # Simplify other logic by guaranteeing this has at least 3 entries: app, mac, date+time
    while len(fn_parts) < 3:
        fn_parts.append(None)

    # Delete mac address (get it later from file included in crashdump)
    del fn_parts[1]
    
    # Extract as much metadata as possible
    if non_standard:
        log.write("WARNING: Non-standard filename - [{}]\n".format(filename))
        
        # Try to get at least app name. Bonus if we can get crash time too.
        app_name = fn_parts[0].split('-')[0]
        crash_time = fn_parts[1]

    else:
        app_name, crash_time = fn_parts[:2]

    # Get string version of date
    if crash_time:
        try:
            crash_time = datetime.strptime(crash_time, "%Y%m%dT%H%M%S")
        except Exception as e:
            log.write("WARNING: Invalid time\n{}\n".format(str(e)))
            crash_time = 'Unknown'
    else:
        crash_time = 'Unknown'

    # Store metadata
    crashdumpinfo.application = app_name
    crashdumpinfo.crashtime_filename = crash_time


def rename_dumpfile_instance(log, crashdumpinfo):
    ''' Renames instances of dumpfile (eg. <file>.tar.gz.1) '''

    (directory, filename) = os.path.split(crashdumpinfo.dumpfilename)
    regex = re.match(r'(?P<filename>.*?)\.(?P<extension>tar\.gz)(\.(?P<instance>\d+))?', filename).groupdict()

    # If no match or no instance match, nothing to do
    if not regex or not regex['instance']:
        return

    # Rename crashdump instances (eg. <filename>.tar.gz.1 -> <filename>_1.tar.gz)
    new_filename = "{}/{}_{}.{}".format(directory, regex['filename'], regex['instance'], regex['extension'])
    os.rename(crashdumpinfo.dumpfilename, new_filename)
    
    # Store crashdump filename
    crashdumpinfo.dumpfilename = new_filename


def process_crashdumpfile(log, jira, dumpfile, bad_crashdumps_dir):
    ''' Process crashdump file into a data structure to collect information for JIRA issues. '''

    log.write("Processing: {}\n".format(dumpfile))
    
    crashdumpinfo = CrashDumpInfo()
    crashdumpinfo.dumpfilename = dumpfile
    crashdumpinfo.bad_crashdumps_dir = bad_crashdumps_dir

    # Gather crashdump information
    try:
        # Hash the file to help ID duplicates
        crashdumpinfo.md5 = hashlib.md5(open(dumpfile, 'rb').read()).hexdigest()

        if re.search(r'\.\d+$', dumpfile):
            rename_dumpfile_instance(log, crashdumpinfo)

        process_filename_metadata(log, crashdumpinfo)
        process_crashdump_metadata(log, crashdumpinfo)
        process_dumpfile_contents(log, crashdumpinfo)
        update_panel_info(log, crashdumpinfo)
        
        open_jira_issue(log, jira, crashdumpinfo)

        # Remove the crashdump file
        try:
            os.remove(crashdumpinfo.dumpfilename)
            
        except OSError as e:
            log.write("I/O error trying to delete dumpfile {}? ({}): {}.\nMoving to {}".format(crashdumpinfo.dumpfilename, e.errno, e.strerror, crashdumpinfo.bad_crashdumps_dir))
            try:
                os.rename(crashdumpinfo.dumpfilename, "{}/{}".format(crashdumpinfo.bad_crashdumps_dir, crashdumpinfo.dumpfilename))

            except:
                logfile.write("Please manually remove {}\n".format(crashdumpinfo.dumpfilename))
        
        logfile.write("DONE\n\n")

    except:
        crashdumpinfo.is_lame_duck = True
        log.write("Backtrace:\n{}\n".format(traceback.format_exc()))
        log.write("DEBUG:\n{}\n\n".format(crashdumpinfo))
        
    finally:
#         log.write("DEBUG:\n{}\n\n".format(crashdumpinfo))
        pass


def process_crashdump_directory(log, jira, directory):
    ''' Process crashdump files found in given directory. '''

    if not os.path.isdir(directory):
        log.write("Invalid directory: {}\n".format(directory))
        return

    log.write("Processing directory: {}\n".format(directory))
    bad_crashdumps_dir = "{}/{}".format(directory,"bad_files") 
    if not os.path.isdir(bad_crashdumps_dir):
        os.mkdir(bad_crashdumps_dir)
    
    for entry in os.listdir(directory):
        
        if not os.path.isfile("{}/{}".format(directory,entry)):
            continue

        # Process files ending in .tar.gz or .tar.gz.<x> (where <x> is number)
        if re.search(r'\.tar.gz(\.\d+)?$', entry):
            fq_dumpfilename = "{}/{}".format(directory, entry)
            process_crashdumpfile(log, jira, fq_dumpfilename, bad_crashdumps_dir)

        # Ignore dot-files
        elif re.match(r'^\.', entry):
            pass

        else:
            log.write("Not crashdump: {}\n".format(entry))


def process_crashdumps(log, jira):

    log.write("Crashdump paths: {}\n".format(CRASHDUMPPATHS))
    
    for directory in CRASHDUMPPATHS:
        process_crashdump_directory(log, jira, directory)


if __name__ == '__main__':

    try:
        logfile = open("jirabot.log", "a")
        logfile.write("=========== START: {} ==========\n".format(datetime.now()))

        jira = JIRA('https://2gig-technologies.atlassian.net', basic_auth=('jirabot', 'n0rt3ksc'))
        process_crashdumps(logfile, jira)

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
    
