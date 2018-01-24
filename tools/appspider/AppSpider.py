#!/usr/bin/env python

"""AppSpider.py: CLI for AppSpider."""

__author__      = "Aaron Weaver"
__copyright__   = "Copyright 2017, Aaron Weaver"

import argparse
import os
import PyAppSpider
import zipfile
import time
import sys
import uuid

authOK = False

#Look at possibly adding URL to support once client multi-url's
def current_scan_in_progress(url=None):
    scan_in_progress = False
    scans =  appspider.get_scans()
    print "Checking to see if a scan is running for this client: " + client

    if scans.is_success():
        for scan in scans.json()["Scans"]:
            if appspider.get_scan_status_text(scan["Status"]) == "Running":
                scan_in_progress = True
                exit

    return scan_in_progress

#Initiates a scan based on a profile and then polls until completion
def scan_poll(appspider, config, output_file):

    #Avoid running multiple scans if a prior scan has not completed
    if current_scan_in_progress():
        print "\nScan already running exiting.\n"
        quit()

    scan_id = None
    scan_status =  appspider.run_scan(configName=config)
    scan_status_flag = False
    scan_has_report_flag = False

    if scan_status.is_success():
        scan_id = scan_status.json()["Scan"]["Id"]
        print "Scan queued. ID is: " + scan_id

        #Check to see if scan is complete, poll until finished
        while scan_status_flag == False:
            time.sleep(2)
            sys.stdout.write(".")
            sys.stdout.flush()
            scan_status =  appspider.is_scan_finished(scan_id).json()
            scan_status_flag = scan_status["Result"]
            if scan_status_flag:
                print "\nCompleted Scan!"

        #Check for report
        while scan_has_report_flag == False:
            time.sleep(2)
            sys.stdout.write(".")
            sys.stdout.flush()
            scan_status =  appspider.scan_has_report(scan_id).json()
            scan_has_report_flag = scan_status["Result"]
            if scan_has_report_flag:
                print "\nReport exists in AppSpider, downloading report."
                targetFile = os.path.basename(output_file)
                targetDirectory = os.path.dirname(output_file)
                zipfilename = "AppSpider_" + str(uuid.uuid4()) + ".zip"
                zip_download(appspider, scan_id, os.path.join(targetDirectory,zipfilename))
                unzip_extract_delete(appspider, scan_id, targetDirectory, zipfilename, output_file)

def zip_download(appspider, scan_id, zipName):
    print "Downloading the zip file."
    #Retrieve the zip file
    vulnerabilities =  appspider.get_report_zip(scan_id)
    #Save the file
    print "Zip filename: " + zipName
    appspider.save_file(vulnerabilities.binary(), zipName)

def unzip_extract_delete(appspider, scan_id, destination, zipName, targetFile):
    archive = zipfile.ZipFile(os.path.join(destination, zipName))
    archive.extract('VulnerabilitiesSummary.xml', destination)
    print "Removing Zip File: " + os.path.join(destination, zipName)
    #Remove the zip file
    os.remove(os.path.join(destination, zipName))
    #Rename the findings file to the user specified filename
    print "Renaming VulnerabilitiesSummary.xml: " + os.path.join(destination, 'VulnerabilitiesSummary.xml')
    os.rename(os.path.join(destination, 'VulnerabilitiesSummary.xml'), targetFile)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='AppSpider API Client.', prefix_chars='--')

    parser.add_argument('--url', help='AppSpider URL.', default=None)
    parser.add_argument('--username', help='AppSpider username.', default=None)
    parser.add_argument('--password', help='AppSpider password.', default=None)
    parser.add_argument('--admin-username', help='AppSpider admin username. (Used for global admin features)', default=None)
    parser.add_argument('--admin-password', help='AppSpider admin password. (Used for global admin features)', default=None)
    parser.add_argument('--client', help='Client name.', default=None)
    parser.add_argument('--engine-group', help='Engine group for scanning.', default=None)
    parser.add_argument('--proxy', help='Proxy for client to use for requests.', default=None)

    #AppSpider specific Functions
    parser.add_argument('--scans', help='Retrieve the scans status.', default=False, action='store_true')
    parser.add_argument('--configs', help='Retrieves all the scan configurations.', default=False, action='store_true')
    parser.add_argument('--vulns', help='Retrieves all the vulnerabilites for the specified client.', default=False, action='store_true')
    parser.add_argument('--vulns-summary', help='Gets VulnerabilitiesSummary.xml for the scan.  Requires a scan id and output file.', default=False, action='store_true')
    parser.add_argument('--scan-id', help='Scan id for the specified client.', default=None)
    parser.add_argument('--output-file', help='Name of the output file.', default=None)
    parser.add_argument('--report-zip', help='Retrieves the zip report file.  Requires a scan id and output file.', default=False, action='store_true')
    parser.add_argument('--zip-extract-summary', help='Destination for the VulnerabilitiesSummary.xml and then delete the zip file.', default=None)
    parser.add_argument('--crawled-links', help='Retrieves the crawled links. Requires a scan id and output file.', default=False, action='store_true')
    parser.add_argument('--run-scan', help='Runs the scan with the specified scan name.', default=None)
    parser.add_argument('--run-scan-poll', help='Runs the scan with the specified config and polls to completion.', default=None)
    parser.add_argument('--create-config', help='Creates a scan configuration', default=None, action='store_true')
    parser.add_argument('--create-run', help='Creates a scan configuration', default=None, action='store_true')
    parser.add_argument('--create-engine-group', help='Engine group for a scan configuration', default=None)
    parser.add_argument('--create-name', help='Config name', default=None)
    parser.add_argument('--create-xml', help='XML configuration for scan', default=None)
    parser.add_argument('--create-seed-url', help='Starting URL for scan', default=None)
    parser.add_argument('--create-constraint-url', help='Include url constraint, example: http://www.yoursite.com/*', default=None)
    parser.add_argument('--create-custom-header', help='Custom Header (API Token in header for example)', default=None)
    parser.add_argument('--engines', help='Lists the engines configured in AppSpider Enterprise', default=False, action='store_true')
    parser.add_argument('--engine-groups', help='Lists the engine groups configured in AppSpider Enterprise', default=False, action='store_true')

    arguments = parser.parse_args()

    #Environment by default override if specified in command line args
    url = arguments.url if arguments.url is not None else os.environ.get('APPSPIDER_URL')
    username = arguments.username if arguments.username is not None else os.environ.get('APPSPIDER_USERNAME')
    password = arguments.password if arguments.password is not None else os.environ.get('APPSPIDER_PASSWORD')
    admin_username = arguments.username if arguments.username is not None else os.environ.get('APPSPIDER_ADMIN_USERNAME')
    admin_password = arguments.password if arguments.password is not None else os.environ.get('APPSPIDER_ADMIN_PASSWORD')
    client = arguments.client if arguments.client is not None else os.environ.get('APPSPIDER_CLIENT')
    engine_group = arguments.engine_group if arguments.engine_group is not None else os.environ.get('APPSPIDER_ENGINE_GROUP')
    proxy = arguments.proxy if arguments.proxy is not None else os.environ.get('APPSPIDER_PROXY')

    #Validate all parameters have been supplied for login
    if url == None or username == None or password == None:
        print "Please specify the AppSpider URL, username and password for login.\n"
        quit()

    proxies = None
    if proxy is not None:
        proxies = {
          'http': proxy,
          'https': proxy,
        }

    #Authenticate
    appspider = PyAppSpider.PyAppSpider(url, debug=False, proxies=proxies, verify_ssl=False)
    admin_appspider = PyAppSpider.PyAppSpider(url, debug=False, proxies=proxies, verify_ssl=False)
    authenticated = appspider.authenticate(username, password)

    #If admin credentials are specified
    if admin_username is not None:
        admin_authenticated = admin_appspider.authenticate(admin_username, admin_password)

    if appspider.loginCode == 1: #Single client
        authOK = True
    elif appspider.loginCode == 2 and client is None: #Multi client
        print "The following clients are available to this user:"

        for spiderClient in appspider.clients:
            print spiderClient

        print "\nRe-run the utility with the --client parameter use one of the client name specified in the list above. Alternatively set the APPSPIDER_CLIENT environment variable.\n"
    elif appspider.loginCode == 2 and client is not None: #Multi client specified
        #Authenticate and find the client guid
        authenticated = appspider.authenticate(username, password)
        clientId = None
        for spiderClient in appspider.clients:
            if client == spiderClient:
                clientId = appspider.clients[client]
        if clientId is not None:
            authenticated = appspider.authenticate(username, password, clientId)

            if appspider.loginCode == 1:
                authOK = True
        else:
            print "Invalid Client Name"
            print authenticated.data_json(pretty=True)
    else:
        print "Authentication problem: " + authenticated.error()

    #Authenticated, let's do something fun
    if authOK == True:
        #Retrieve the scans and status
        if arguments.scans:
            scans =  appspider.get_scans()
            print "Scan status for client: " + client

            if scans.is_success():
                for scan in scans.json()["Scans"]:
                    print "Status: " +  appspider.get_scan_status_text(scan["Status"])
                    print "Scan ID: " + scan["Id"]
                    for target in scan["Targets"]:
                        print "URL: " + target["Host"]
                    print "Started: " + scan["StartTime"]

                    if scan["CompletionTime"] is not None:
                        print "Completed: " + scan["CompletionTime"]
                    else:
                        print "Not Completed"
                    print
            else:
                print "No scans found"
        #Retrieve vulnerablities
        elif arguments.vulns:
            vulnerabilities =  appspider.get_vulnerabilities()
            print "Retrieving vulnerablities for client: " + client
            if vulnerabilities.is_success():
                print "Total Count: " + str(vulnerabilities.json()["TotalCount"])
                for vulnerability in vulnerabilities.json()["Findings"]:
                    print "Vuln Type: " + vulnerability["VulnType"]
                    print "Vuln Type: " + vulnerability["VulnUrl"]
                    print "Vuln Type: " + vulnerability["Description"]
                    print
            else:
                print "No vulnerabilities found"
        elif arguments.vulns_summary:
            if arguments.scan_id is not None and arguments.output_file is not None:
                vulnerabilities =  appspider.get_vulnerabilities_summary(arguments.scan_id)
                print "Retrieving vulnerablities for client: " + client
                appspider.save_file(vulnerabilities.binary(), arguments.output_file)
            else:
                print "Scan id or out file needed."
        elif arguments.report_zip:
            if arguments.report_zip is not None and arguments.output_file is not None:
                zip_download(appspider, arguments.scan_id, zipName=arguments.output_file)
                print "Retrieving Zip file for client: " + client
                if arguments.zip_extract_summary is not None:
                    unzip_extract_delete(appspider, arguments.scan_id, '', zipName=arguments.output_file)
            else:
                print "Scan id or out file needed."
        elif arguments.crawled_links:
            if arguments.crawled_links is not None and arguments.output_file is not None:
                vulnerabilities =  appspider.get_crawled_links(arguments.scan_id)
                print "Retrieving crawled links file for client: " + client
                appspider.save_file(vulnerabilities.binary(), arguments.output_file)
            else:
                print "Scan id or out file needed."
        #Get the current configurations
        elif arguments.configs:
            print "Retrieving client config:\n"
            configs =  appspider.get_configs()
            print "Configurations for client: " + client

            if configs.is_success():
                for config in configs.json()["Configs"]:
                    print "Config Name: " +  config["Name"]
        #Run a scan
        elif arguments.run_scan is not None:
            print "Attempting to run a scan\n"
            scan_status =  appspider.run_scan(configName=arguments.run_scan)
            if scan_status.is_success():
                print "Scan queued. ID is: " + scan_status.json()["Scan"]["Id"]
        #Run a scan
        elif arguments.run_scan_poll is not None:
            print "Scanning target config, polling and downloading report."
            scan_poll(appspider, arguments.run_scan_poll, arguments.output_file)
        #Create a scan config
        elif arguments.create_config is not None:
            print "Creating a scan config\n"
            if arguments.create_xml is not None:
                #Find the guid fromt the scanner group name
                groupId = None
                groups = admin_appspider.admin_get_all_engine_groups()

                if groups.is_success():
                    for groups in groups.json()["EngineGroups"]:
                        if groups["Name"] == arguments.create_engine_group:
                            groupId = groups["Id"]

                seed_urls = []
                seed_url = {}

                if arguments.create_seed_url is not None:
                    seed_url['url'] = arguments.create_seed_url
                    seed_urls.append(seed_url)

                scope_constraints = []
                scope_constraint = {}
                if arguments.create_constraint_url is not None:
                    scope_constraint['url'] = arguments.create_constraint_url
                    scope_constraints.append(scope_constraint)

                custom_headers = []
                custom_header = {}
                if arguments.create_custom_header is not None:
                    custom_header['custom_header'] = arguments.create_custom_header
                    custom_headers.append(custom_header)

                #Save config
                if groupId is not None:
                    save_config = appspider.save_config(arguments.create_xml, arguments.create_name, groupId, clientId, seed_urls=seed_urls, scope_constraints = scope_constraints, custom_headers=custom_headers)

                    if save_config.is_success():
                        print "Saved succesfully"
                        if arguments.create_run is not None:
                            scan_status =  appspider.run_scan(configName=arguments.create_name)
                            if scan_status.is_success():
                                print "Scan queued. ID is: " + scan_status.json()["Scan"]["Id"]
                    else:
                        print "Config did not save, please review the message below."
                        print save_config.data_json(pretty=True)
                else:
                    print "Group not found. Please verify the group name:"
                    print groups.data_json(pretty=True)
            else:
                print "XML file required to create a config. Re-run and specify the XML file exported from AppSpider. (--create_xml)"

        #List Engines configured
        elif arguments.engines:
            print "Listing engines configured in AppSpider.\n"
            if admin_appspider.loginCode == 1:
                print admin_appspider.admin_get_engines().data_json(pretty=True)
            else:
                print "Not authenticated as an administrator."
        #Admin: List Engines Groups configured
        elif arguments.engine_groups:
            print "Listing engines groups configured in AppSpider.\n"
            if admin_appspider.loginCode == 1:
                groups = admin_appspider.admin_get_all_engine_groups()
                print "Engine Groups configured on AppSpider:"
                if groups.is_success():
                    for groups in groups.json()["EngineGroups"]:
                        print "Group Name: " +  groups["Name"]
        else:
            print "No action specified or action not found.\n"
