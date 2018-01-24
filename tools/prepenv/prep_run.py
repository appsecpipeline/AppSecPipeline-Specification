"""
Example written by Aaron Weaver <aaron.weaver@owasp.org>
as part of the OWASP DefectDojo and OWASP AppSec Pipeline Security projects

Description: CI/CD example for DefectDojo
"""
from defectdojo_api import defectdojo
from datetime import datetime, timedelta
import os, sys
import argparse
import time
import junit_xml_output
import shutil
import yaml

DEBUG = True

test_cases = []

def junit(toolName, file):

    junit_xml = junit_xml_output.JunitXml(toolName, test_cases, total_tests=None, total_failures=None)
    with open(file, 'w') as file:
        print "\nWriting Junit test file: junit_dojo.xml"
        file.write(junit_xml.dump())

def dojo_connection(host, api_key, user, proxy=None):

    if proxy is not None:
        proxies = {
          'http': 'http://' + proxy,
          'https': 'http://' + proxy,
        }
        print proxy
        # Instantiate the DefectDojo api wrapper
        dd = defectdojo.DefectDojoAPI(host, api_key, user, proxies=proxies, verify_ssl=False, timeout=360, debug=True)
    else:
        dd = defectdojo.DefectDojoAPI(host, api_key, user, verify_ssl=False, timeout=360, debug=False)

    return dd

def return_engagement(dd, product_id, user, build_id=None):
    engagement_id = None
    #Specify the product id
    product_id = product_id
    user_id = None
    start_date = datetime.now()
    end_date = start_date+timedelta(days=1)

    users = dd.list_users(user)

    if users.success == False:
        print "Error in listing users: " + users.message
        print "Exiting...\n"
        sys.exit()
    else:
        user_id = users.data["objects"][0]["id"]

    engagementText = "CI/CD Integration"
    if build_id is not None:
        engagementText = engagementText + " - Build #" + build_id

    engagement_id = dd.create_engagement(engagementText, product_id, str(user_id),
    "In Progress", start_date.strftime("%Y-%m-%d"), end_date.strftime("%Y-%m-%d"))

    print "Engagement ID created: " + str(engagement_id)

    return str(engagement_id)

def process_findings(dd, engagement_id, dir, build=None):
    test_ids = []
    for root, dirs, files in os.walk(dir):
        for name in files:
            file = os.path.join(os.getcwd(),root, name)
            if "processed" not in str(file) and "error" not in str(file):
                #Test for file extension
                if file.lower().endswith(('.json', '.csv','.txt','.js', '.xml')):
                    test_id = processFiles(dd, engagement_id, file)

                    if test_id is not None:
                        if str(test_id).isdigit():
                            test_ids.append(str(test_id))
                else:
                    print "Skipped file, extension not supported: " + file + "\n"
    return ','.join(test_ids)

def moveFile(file, success):
    path = os.path.dirname(file)
    name = os.path.basename(file)
    dest = None

    #folder for processed files
    processFolder = os.path.join(path,"processed")
    if not os.path.exists(processFolder):
        os.mkdir(processFolder)

    #folder for error file
    errorFolder = os.path.join(path,"error")
    if not os.path.exists(errorFolder):
        os.mkdir(errorFolder)

    if success == True:
        dest = os.path.join(path,processFolder,name)
    else:
        dest = os.path.join(path,errorFolder,name)

    shutil.move(file, dest)

def processFiles(dd, engagement_id, file, scanner=None, build=None):
    upload_scan = None
    scannerName = None
    path=os.path.dirname(file)
    name = os.path.basename(file)
    tool = os.path.basename(path)
    tool = tool.lower()

    test_id = None
    date = datetime.now()
    dojoDate = date.strftime("%Y-%m-%d")

    #Tools without an importer in Dojo; attempted to import as generic
    if "generic" in name:
        scanner = "Generic Findings Import"
        print "Uploading " + tool + " scan: " + file
        test_id = dd.upload_scan(engagement_id, scanner, file, "true", dojoDate, build)
        if test_id.success == False:
            print "An error occured while uploading the scan: " + test_id.message
            moveFile(file, False)
        else:
            print "Succesful upload, TestID: " + str(test_id) + "\n"
            moveFile(file, True)
    else:
        if tool == "burp":
            scannerName = "Burp Scan"
        elif tool == "nessus":
            scannerName = "Nessus Scan"
        elif tool == "nmap":
            scannerName = "Nmap Scan"
        elif tool == "nexpose":
            scannerName = "Nexpose Scan"
        elif tool == "veracode":
            scannerName = "Veracode Scan"
        elif tool == "checkmarx":
            scannerName = "Checkmarx Scan"
        elif tool == "zap":
            scannerName = "ZAP Scan"
        elif tool == "appspider":
            scannerName = "AppSpider Scan"
        elif tool == "arachni":
            scannerName = "Arachni Scan"
        elif tool == "vcg":
            scannerName = "VCG Scan"
        elif tool == "dependency-check":
            scannerName = "Dependency Check Scan"
        elif tool == "retirejs":
            scannerName = "Retire.js Scan"
        elif tool == "nodesecurity":
            scannerName = "Node Security Platform Scan"
        elif tool == "qualys":
            scannerName = "Qualys Scan"
        elif tool == "qualyswebapp":
            scannerName = "Qualys Webapp Scan"
        elif tool == "openvas":
            scannerName = "OpenVAS CSV"
        elif tool == "snyk":
            scannerName = "Snyk Scan"
        else:
            print "Tool not defined in dojo_ci_cd script: " + tool

        if scannerName is not None:
            print "Uploading " + scannerName + " scan: " + file
            test_id = dd.upload_scan(engagement_id, scannerName, file, "true", dojoDate, build)
            if test_id.success == False:
                print "An error occured while uploading the scan: " + test_id.message
                moveFile(file, False)
            else:
                print "Succesful upload, TestID: " + str(test_id)
                moveFile(file, True)

    return test_id

def create_findings(dd, engagement_id, scanner, file, build=None):
    # Upload the scanner export
    if engagement_id > 0:
        print "Uploading scanner data."
        date = datetime.now()

        upload_scan = dd.upload_scan(engagement_id, scanner, file, "true", date.strftime("%Y-%m-%d"), build=build)

        if upload_scan.success:
            test_id = upload_scan.id()
        else:
            print upload_scan.message
            quit()

def summary(dd, engagement_id, test_ids, max_critical=0, max_high=0, max_medium=0):
        findings = dd.list_findings(engagement_id_in=engagement_id, duplicate="false", active="true", verified="true")
        if findings.success:
            print"=============================================="
            print "Total Number of Vulnerabilities: " + str(findings.data["meta"]["total_count"])
            print"=============================================="
            print_findings(sum_severity(findings))
            print
        else:
            print "An error occurred: " + findings.message

        findings = dd.list_findings(test_id_in=test_ids, duplicate="true")

        if findings.success:
            print"=============================================="
            print "Total Number of Duplicate Findings: " + str(findings.data["meta"]["total_count"])
            print"=============================================="
            print_findings(sum_severity(findings))
            print
            """
            #Delay while de-dupes
            sys.stdout.write("Sleeping for 30 seconds to wait for dedupe celery process:")
            sys.stdout.flush()
            for i in range(15):
                time.sleep(2)
                sys.stdout.write(".")
                sys.stdout.flush()
            """
        else:
            print "An error occurred: " + findings.message

        findings = dd.list_findings(test_id_in=test_ids, duplicate="false", limit=500)

        if findings.success:
            if findings.count() > 0:
                for finding in findings.data["objects"]:
                    test_cases.append(junit_xml_output.TestCase(finding["title"] + " Severity: " + finding["severity"], finding["description"],"failure"))
                if not os.path.exists("reports"):
                    os.mkdir("reports")
                junit("DefectDojo", "reports/junit_dojo.xml")

            print"\n=============================================="
            print "Total Number of New Findings: " + str(findings.data["meta"]["total_count"])
            print"=============================================="
            sum_new_findings = sum_severity(findings)
            print_findings(sum_new_findings)
            print
            print"=============================================="

            strFail = None
            if max_critical is not None:
                if sum_new_findings[4] > max_critical:
                    strFail =  "Build Failed: Max Critical"
            if max_high is not None:
                if sum_new_findings[3] > max_high:
                    strFail = strFail +  " Max High"
            if max_medium is not None:
                if sum_new_findings[2] > max_medium:
                    strFail = strFail +  " Max Medium"
            if strFail is None:
                print "Build Passed!"
            else:
                print "Build Failed: " + strFail
            print"=============================================="
        else:
            print "An error occurred: " + findings.message

def sum_severity(findings):
    severity = [0,0,0,0,0]
    for finding in findings.data["objects"]:
        if finding["severity"] == "Critical":
            severity[4] = severity[4] + 1
        if finding["severity"] == "High":
            severity[3] = severity[3] + 1
        if finding["severity"] == "Medium":
            severity[2] = severity[2] + 1
        if finding["severity"] == "Low":
            severity[1] = severity[1] + 1
        if finding["severity"] == "Info":
            severity[0] = severity[0] + 1

    return severity

def print_findings(findings):
    print "Critical: " + str(findings[4])
    print "High: " + str(findings[3])
    print "Medium: " + str(findings[2])
    print "Low: " + str(findings[1])
    print "Info: " + str(findings[0])

class Main:
    if __name__ == "__main__":
        parser = argparse.ArgumentParser(description='CI/CD integration for DefectDojo')
        parser.add_argument('--host', help="Dojo Hostname", required=True)
        parser.add_argument('--api_key', help="API Key: user:guidvalue", required=True)
        parser.add_argument('--product', help="Dojo Product ID", required=True)
        parser.add_argument('--file', help="Scanner file", required=False)
        parser.add_argument('--dir', help="Scanner directory, needs to have the scanner name with the scan file in the folder. Ex: reports/nmap/nmap.csv", required=False, default="reports")
        parser.add_argument('--scanner', help="Type of scanner", required=False)
        parser.add_argument('--build_id', help="Build ID", required=False)
        parser.add_argument('--engagement', help="Engagement ID (optional)", required=False)
        parser.add_argument('--closeengagement', help="Close Engagement", required=False, action='store_true')
        parser.add_argument('--critical', help="Maximum new critical vulns to pass the build.", required=False)
        parser.add_argument('--high', help="Maximum new high vulns to pass the build.", required=False)
        parser.add_argument('--medium', help="Maximum new medium vulns to pass the build.", required=False)
        parser.add_argument('--proxy', help="Proxy, specify as host:port, ex: localhost:8080")

        #Parse arguments
        args = vars(parser.parse_args())
        host = args["host"]
        api_key = args["api_key"]

        product_id = args["product"]
        file = args["file"]
        dir = args["dir"]
        scanner = args["scanner"]
        engagement_id = args["engagement"]
        closeEngagement = args["closeengagement"]
        max_critical = args["critical"]
        max_high = args["high"]
        max_medium = args["medium"]
        build_id = args["build_id"]
        proxy = args["proxy"]

        if dir is not None:
            if ":" not in api_key:
                print "API Key not in the correct format, must be: <user>:<guid>"
                quit()
            apiParsed = api_key.split(':')
            user = apiParsed[0]
            api_key = apiParsed[1]
            dd = dojo_connection(host, api_key, user, proxy)
            engagement_id = return_engagement(dd, product_id, user, build_id=build_id)

            data = dict(
                DOJO_ENGAGEMENT_ID = engagement_id
            )

            yamlLoc = os.path.join(os.path.join(dir,"prepenv"),"appruntime.yaml")
            with open(yamlLoc, 'w') as outfile:
                yaml.dump(data, outfile, default_flow_style=False)

            #Close the engagement
            if closeEngagement == True:
                dd.close_engagement(engagement_id)

        else:
            print "No file or directory to scan specified."
