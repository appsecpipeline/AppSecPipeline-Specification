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
from urlparse import urlparse
import yaml

DEBUG = False

test_cases = []

import json
import requests

class Notify(object):
    """AppSecPipeline."""

    def __init__(self, slack_web_hook, channel, username, icon_emoji):
        self.slack_web_hook = slack_web_hook
        self.channel = channel
        self.username = username
        self.icon_emoji = icon_emoji

    def slackAlert(self, **kwargs):
        payload_json = json.dumps(kwargs)
        webhook_url = "https://hooks.slack.com/services/%s" % self.slack_web_hook
        try:
            response = requests.post(
                webhook_url, data=payload_json,
                headers={'Content-Type': 'application/json'}
            )
        except:
            print "Slack timeout..."

    def chatAlert(self, text, attachment):
        self.slackAlert(text=text, channel=self.channel, username=self.username, icon_emoji=self.icon_emoji, attachments=attachment)

    def chatPipelineStart(self, pipelineLaunchUID, source, pipelineTarget, profile):
        slackTxt = "Security Pipeline Scan *%s* using profile: *%s* \n*PipelineLaunch UID:* %s\n*Details*: %s\n" % (source, profile, pipelineLaunchUID, pipelineTarget)
        self.chatAlert("*Starting:* " + slackTxt)

    def chatPipelineTools(self, pipeline):
        self.chatAlert("*Tools that will be run:* ")
        appSecPipeline = ""
        toolName = None
        for tool in pipeline:
            toolData =  pipeline[tool]
            toolName = toolData['tool']
            appSecPipeline += toolName + ", "

        self.chatAlert(">>>*AppSecPipeline:* " + appSecPipeline[:-2])

        return toolName

    def chatPipelineIndividualTools(self, execute, toolName):
        text = "Executing"
        if execute == False:
            text = "Skipping"
        self.chatAlert(">>>*" + text + ":* " + toolName)

    def chatPipelineToolComplete(self, toolName):
        self.chatAlert(">>>*Completed Execution:* " + toolName)

    def chatPipelineComplete(self, pipelineLaunchUID):
        self.chatAlert("*Completed Pipeline Scan for PipelineLaunch UID:* " + pipelineLaunchUID)

    def chatPipelineMention(self, mention, text):
        self.chatAlert("*Attention Needed*: %s %s" % (mention, text))

    def scanSummary(self, build_report_link, open_report_link, product, status, comments, build, repo_url, tag, summary):
        title = None
        color = None
        if status == "pass":
            title = "Security Scan Passed!"
            color = "good"
        elif status == "warning":
            title = "Security Scan Passed with Warnings!"
            color = "warning"
        elif status == "fail":
            title = "Security Scan Failed!"
            color = "danger"

        notification = [{
                "title": title,
                "color": color,
                "footer": comments,
                #"title_link": report_link,
                "actions": [
                {
                  "type": "button",
                  "text": "Build Findings",
                  "url": build_report_link
                },
                {
                  "type": "button",
                  "text": "All Open Findings",
                  "url": open_report_link
                }
                ],
                "fields": [
                {
                    "title": "Critical",
                    "value": summary["critical"],
                    "short": 'true'
                },
                {
                    "title": "High",
                    "value": summary["high"],
                    "short": 'true'
                },
                {
                    "title": "Medium",
                    "value": summary["medium"],
                    "short": 'true'
                },
                {
                    "title": "Low",
                    "value": summary["low"],
                    "short": 'true'
                },
                {
                    "title": "Info",
                    "value": summary["info"],
                    "short": 'true'
                },
                {
                    "title": "Total",
                    "value": summary["total"],
                    "short": 'true'
                }],
            }]

        if build is not None:
            build = "Build #" + build + "\n"
        else:
            build = ""

        if repo_url is not None:
            repo_url = "Repo: " + repo_url + "\n"
        else:
            repo_url = ""

        if tag is not None:
            tag = "Tag: " + tag + "\n"
        else:
            tag = ""

        self.chatAlert("*Completed Security Scan for:* %s\n %s%s%s " % (product, build, repo_url, tag), notification)

class Config(object):
    """AppSecPipeline."""

    def __init__(self, masterYaml):
        self.masterYaml = masterYaml
        print masterYaml

    def getMasterConfig(self):
        yamlData = None
        if self.masterYaml is not None and os.path.exists(self.masterYaml):
            with open(self.masterYaml, 'r') as stream:
                try:
                    yamlData = yaml.safe_load(stream)
                except yaml.YAMLError as exc:
                    print(exc)
        return yamlData

    def getMasterToolMinimumVuln(self, tool_name, profile):
        min_severity = None
        masterYaml = self.getMasterConfig()

        if masterYaml:
            if profile in masterYaml["profiles"]:
                for tool in masterYaml["profiles"][profile]["pipeline"]:
                    if tool_name == tool["tool"]:
                        if "min-severity" in tool:
                            min_severity = tool["min-severity"]
                            break

            if min_severity == None:
                #Lookup global minimum configuration for importing findings
                if masterYaml:
                    if "min-severity" in masterYaml["global"]:
                        min_severity = masterYaml["global"]["min-severity"]

        if min_severity == None:
            min_severity = "Info"
        elif min_severity.lower() == "info":
            min_severity = "Info"
        elif min_severity.lower() == "low":
            min_severity = "Low"
        elif min_severity.lower() == "medium":
            min_severity = "Medium"
        elif min_severity.lower() == "high":
            min_severity = "High"
        elif min_severity.lower() == "critical":
            min_severity = "Critical"

        return min_severity

    def getMasterToolFailValues(self):
        masterYaml = self.getMasterConfig()
        max_critical = 1
        max_high = 2
        max_medium = 8

        if masterYaml:
            if "max-critical" in masterYaml["global"]:
                max_critical = masterYaml["global"]["max-critical"]
            if "max-high" in masterYaml["global"]:
                max_high = masterYaml["global"]["max-high"]
            if "max-medium" in masterYaml["global"]:
                max_medium = masterYaml["global"]["max-medium"]

        return max_critical, max_high, max_medium

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
        # Instantiate the DefectDojo api wrapper
        dd = defectdojo.DefectDojoAPI(host, api_key, user, proxies=proxies, verify_ssl=False, timeout=360, debug=True)
    else:
        dd = defectdojo.DefectDojoAPI(host, api_key, user, verify_ssl=False, timeout=360, debug=False)

    return dd

def get_user(dd):
    users = dd.list_users(dd.user)

    if users.success == False:
        print "Error in listing users: " + users.message
        print "Exiting...\n"
        sys.exit()
    else:
        user_id = users.data["objects"][0]["id"]

    return user_id

#Creates an engagement
def return_engagement(dd, product_id, user, build_id=None):
    engagement_id = None
    #Specify the product id
    product_id = product_id
    user_id = None
    start_date = datetime.now()
    end_date = start_date+timedelta(days=1)

    user_id = get_user(dd)

    engagementText = "CI/CD Integration"
    if build_id is not None:
        engagementText = engagementText + " - Build #" + build_id

    engagement_id = dd.create_engagement(engagementText, product_id, str(user_id),
    "In Progress", start_date.strftime("%Y-%m-%d"), end_date.strftime("%Y-%m-%d"))

    print "Engagement ID created: " + str(engagement_id)

    return engagement_id

def process_findings(dd, engagement_id, dir, build=None, tags=None, masterYaml=None, profile=None, product=None):
    test_ids = []
    for root, dirs, files in os.walk(dir):
        for name in files:
            file = os.path.join(os.getcwd(),root, name)
            if "processed" not in str(file) and "error" not in str(file):
                #Test for file extension
                if file.lower().endswith(('.json', '.csv','.txt','.js', '.xml')):
                    test_id = processFiles(dd, engagement_id, file, tags=tags, masterYaml=masterYaml, profile=profile, product=product)

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

def processCloc(dd, product_id, file):
    user_id = get_user(dd)
    #remove the langauges for the product
    dd.delete_all_languages_product(product_id)

    data = json.load(open(file))

    for language in data:
        if "header" not in language and "SUM" not in language:
            files   = data[language]['nFiles']
            code    = data[language]['code']
            blank   = data[language]['blank']
            comment = data[language]['comment']

            #create the language for the product
            dd.create_language(product_id, user_id, files, code, blank, comment, language_name=language)

def processWappalyzer(dd, product_id, file):
    user_id = get_user(dd)
    #remove the app analysis for the product
    dd.delete_all_app_analysis_product(product_id)

    data = json.load(open(file))
    for app in data["applications"]:
        name = app["name"]
        confidence = app["confidence"]
        version = app["version"]
        icon = app["icon"]
        website = app["website"]

        dd.create_app_analysis(product_id, user_id, name, confidence, version, icon, website)

def processFiles(dd, engagement_id, file, scanner=None, build=None, tags=None, masterYaml=None, profile=None, product=None):
    upload_scan = None
    scannerName = None
    path=os.path.dirname(file)
    name = os.path.basename(file)
    tool = os.path.basename(path)
    tool = tool.lower()

    test_id = None
    date = datetime.now()
    dojoDate = date.strftime("%Y-%m-%d")

    config = Config(masterYaml)
    minimum_severity = config.getMasterToolMinimumVuln(tool, profile)

    #Tools without an importer in Dojo; attempted to import as generic
    if "generic" in name:
        scanner = "Generic Findings Import"
        print "Uploading " + tool + " scan: " + file
        test_id = dd.upload_scan(engagement_id, scanner, file, "true", dojoDate, build=build, tags=tags, minimum_severity=minimum_severity)
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
        elif tool == "cloc":
            processCloc(dd, product, file)
        elif tool == "wappalyzer":
            processWappalyzer(dd, product, file)
        elif tool == "bandit":
            scannerName = "Bandit Scan"
        elif tool == "ssllabs":
            scannerName = "SSL Labs Scan"
        else:
            print "Tool not defined in dojo_ci_cd script: " + tool

        if scannerName is not None:
            print "Uploading " + scannerName + " scan: " + file
            test_id = dd.upload_scan(engagement_id, scannerName, file, "true", dojoDate, build=build, tags=tags, minimum_severity=minimum_severity)
            if test_id.success == False:
                print "An error occured while uploading the scan: " + test_id.message
                moveFile(file, False)
            else:
                print "Succesful upload, TestID: " + str(test_id)
                moveFile(file, True)

    return test_id

def summary_slack(dd, masterYaml, notify, profile, product, engagement_id, test_ids, build_id, repo_url, tags, max_critical, max_high, max_medium):

    config = Config(masterYaml)
    max_critical, max_high, max_medium = config.getMasterToolFailValues()

    summary = {}
    summary["critical"] = 0
    summary["high"] = 0
    summary["medium"] = 0
    summary["low"] = 0
    summary["info"] = 0
    summary["total"] = 0

    #Ensure tests found for this scan
    if test_ids is not "":

        findings = dd.list_findings(test_id_in=test_ids, duplicate="false", limit=1000)

        if findings.success:
            if findings.count() > 0:
                for finding in findings.data["objects"]:
                    test_cases.append(junit_xml_output.TestCase(finding["title"] + " Severity: " + finding["severity"], finding["description"],"failure"))
                #if not os.path.exists("reports"):
                #    os.mkdir("reports")
                #junit("DefectDojo", "reports/junit_dojo.xml")

            print"\n=============================================="
            print "Total Number of New Findings: " + str(findings.data["meta"]["total_count"])
            print"=============================================="

            for finding in findings.data["objects"]:
                if finding["severity"] == "Critical":
                    summary["critical"]  = summary["critical"]  + 1
                if finding["severity"] == "High":
                    summary["high"] = summary["high"] + 1
                if finding["severity"] == "Medium":
                    summary["medium"] = summary["medium"] + 1
                if finding["severity"] == "Low":
                    summary["low"] = summary["low"] + 1
                if finding["severity"] == "Info":
                    summary["info"] = summary["info"] + 1
                summary["total"] = summary["total"] + 1

            strFail = ""
            comments = None
            if max_critical is not None:
                if summary["critical"] >= max_critical:
                    comments =  "Build Failed: Max Critical "
            if max_high is not None:
                if summary["high"] >= max_high:
                    comments = comments +  " Max High "
            if max_medium is not None:
                if summary["medium"] >= max_medium:
                    comments = comments +  " Max Medium "
            if comments is None:
                print "Build Passed!"
                strFail = "pass"
            else:
                print "Build Failed: " + comments
                strFail = "fail"
        else:
            print "An error occurred: " + findings.message
    else:
        strFail = "pass"

    comments = "*Profile:* %s\n*Build Pass/Fail Criteria:* Max Critical: %s, Max High: %s, Max Medium: %s" % (profile, max_critical, max_high, max_medium)

    defectdojo_url = urlparse(dd.host)
    build_report_link = "%s://%s/engagement/%s" % (defectdojo_url.scheme, defectdojo_url.netloc, engagement_id)
    open_report_link = "%s://%s/finding/open?test__engagement__product=%s" % (defectdojo_url.scheme, defectdojo_url.netloc, product)
    product_name = None
    product  = dd.get_product(product)
    if product.success:
        product = product.data['name']

    notify.scanSummary(build_report_link, open_report_link, product, strFail, comments, build_id, repo_url, tags, summary)

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
                #if not os.path.exists("reports"):
                #    os.mkdir("reports")
                #junit("DefectDojo", "reports/junit_dojo.xml")

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
                    strFail =  "Build Failed: Max Critical: (" + str(max_critical) + ")"
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
        parser.add_argument('--tag', help="Tag the test with the branch or arbitrary tag.", required=False)
        parser.add_argument('--repo_url', help="Repo URL.", required=False)
        parser.add_argument('--slack_web_hook', help="Slack webhook token.", required=False)
        parser.add_argument('--slack_channel', help="Slack channel", required=False)
        parser.add_argument('--slack_user', help="Slack user.", required=False)
        parser.add_argument('--slack_icon', help="Slack icon.", required=False)
        parser.add_argument('--master_config', help="Master yaml configuration file.", required=False)
        parser.add_argument('--profile', help="Profile run from master yaml.", required=False)


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
        tag = args["tag"]
        repo_url = args["repo_url"]
        slack_web_hook = args["slack_web_hook"]
        slack_channel = args["slack_channel"]
        slack_user = args["slack_user"]
        slack_icon = args["slack_icon"]
        master_config = args["master_config"]
        profile = args["profile"]

        if dir is not None or file is not None:
            if ":" not in api_key:
                print "API Key not in the correct format, must be: <user>:<guid>"
                quit()
            apiParsed = api_key.split(':')
            user = apiParsed[0]
            api_key = apiParsed[1]
            dd = dojo_connection(host, api_key, user, proxy)

            if engagement_id is None:
                engagement_id = return_engagement(dd, product_id, user, build_id=build_id)

            test_ids = None
            if file is not None:
                if scanner is not None:
                    test_ids = processFiles(dd, engagement_id, file, scanner=scanner, tags=tag, masterYaml=master_config, profile=profile, product=product_id)
                else:
                    print "Scanner type must be specified for a file import. --scanner"
            else:
                test_ids = process_findings(dd, engagement_id, dir, build=build_id, tags=tag, masterYaml=master_config, profile=profile, product=product_id)

            #Close the engagement
            if closeEngagement == True:
                #Validate that there isn't a manual review Requested
                results = dd.list_tests(engagement_in=engagement_id)
                if results.success:
                    for test_type in results.data["objects"]:
                        if test_type["test_type"] == "Manual Code Review":
                            closeEngagement = False
                if closeEngagement:
                    dd.close_engagement(engagement_id)

            if slack_web_hook:
                notify = Notify(slack_web_hook, slack_channel, slack_user, slack_icon)
                summary_slack(dd, master_config, notify, profile, product_id, engagement_id, test_ids, build_id, repo_url, tag, max_critical, max_high, max_medium)

        else:
            print "No file or directory to scan specified."
