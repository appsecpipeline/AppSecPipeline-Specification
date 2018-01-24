#!/usr/bin/env python
import csv
from datetime import datetime
import json
import re
import argparse
import os

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    #Command line options
    parser.add_argument("-f", "--file", help="File to process", required=True)
    args = parser.parse_args()
    jsonFile = args.file

    def findingHeaderInfo(version):
        headerInfo = ""

        if "number" in version:
            headerInfo += "Version: %s\n" % version["number"]

        if "confidence" in version:
            headerInfo += "Confidence: %s\n" % version["confidence"]

        if "interesting_entries" in version:
            if len(version["interesting_entries"]) > 0:
                headerInfo += "Interesting Entries: \n"
                for entries in version["interesting_entries"]:
                    headerInfo += "%s\n" % entries

        return headerInfo

    def findingInfo(findingType, csvwriter, host, headerInfo, findings):
        datestring = datetime.strftime(datetime.now(), '%m/%d/%Y')

        for finding in findings:
            csvFinding = []
            findingData = ""
            refData = ""
            title = "WPScan: "
            severity = "Info"

            findingData += headerInfo
            title += "(%s) - " % findingType
            if findingType == "WP Finding":
                severity = "Medium"
            elif findingType == "Plugin":
                severity = "Low"

            if "title" in finding:
                title += "%s\n" % finding["title"]
                if "XSS" in title:
                    severity = "High"
                if "SQL" in title:
                    severity = "Critical"
            else:
                title += "%s\n" % finding["found_by"]

            findingData += "%s\n" % title

            if "fixed_in" in finding:
                findingData += "Fixed In: %s\n" % finding["fixed_in"]

            if "url" in finding:
                findingData += "URL: %s\n" % finding["url"]

            if "found_by" in finding:
                findingData += "Found by: %s\n" % finding["found_by"]

            if "confidence" in finding:
                findingData += "Confidence: %s\n" % finding["confidence"]

            if "interesting_entries" in finding:
                if len(finding["interesting_entries"]) > 0:
                    findingData += "Interesting Entries: \n"
                    for entries in finding["interesting_entries"]:
                        findingData += "%s\n" % entries

            if "comfirmed_by" in finding:
                if len(finding["confirmed_by"]) > 0:
                    findingData += "Confirmed By: \n"
                    for confirmed_by in finding["confirmed_by"]:
                        findingData += "%s\n" % confirmed_by

            if len(finding["references"]) > 0:
                #refData += "References: \n"
                for ref in finding["references"]:
                    refData += "%s:\n" % ref
                    for item in finding["references"][ref]:
                        refData += "%s\n" %  item

            ####### Individual fields ########
            #Date
            csvFinding.append(datestring)

            csvFinding.append(title)

            #CweId
            csvFinding.append("0")

            csvFinding.append(host)

            #Severity
            csvFinding.append(severity) #Nikto doesn't assign severity, default to low

            #Description
            csvFinding.append(findingData)

            #Mitigation
            csvFinding.append("")

            #Impact
            csvFinding.append("")

            #References
            csvFinding.append(refData)

            #Active
            csvFinding.append("True")

            #Verified
            csvFinding.append("True")

            #FalsePositive
            csvFinding.append("False")

            #Duplicate
            csvFinding.append("False")

            csvwriter.writerow(csvFinding)

    #Find only the base filname, save as csv
    base = os.path.basename(args.file)

    csv_output = open(os.path.join(os.path.dirname(args.file), "generic_" + os.path.splitext(base)[0] + ".csv"), 'w')
    csvwriter = csv.writer(csv_output)

    """
    Date: ::
    Date of the finding in mm/dd/yyyy format.
    Title: ::
    Title of the finding
    CweId: ::
    Cwe identifier, must be an integer value.
    Url: ::
    Url associated with the finding.
    Severity: ::
    Severity of the finding. Must be one of Info, Low, Medium, High, or Critical.
    Description: ::
    Description of the finding. Can be multiple lines if enclosed in double quotes.
    Mitigation: ::
    Possible Mitigations for the finding. Can be multiple lines if enclosed in double quotes.
    Impact: ::
    Detailed impact of the finding. Can be multiple lines if enclosed in double quotes.
    References: ::
    References associated with the finding. Can be multiple lines if enclosed in double quotes.
    Active: ::
    Indicator if the finding is active. Must be empty, True or False
    Verified: ::
    Indicator if the finding has been verified. Must be empty, True, or False
    FalsePositive: ::
    Indicator if the finding is a false positive. Must be empty, True, or False
    Duplicate: ::
    Indicator if the finding is a duplicate. Must be empty, True, or False
    """
    csvwriter.writerow(["Date","Title","CweId","Url","Severity","Description","Mitigation","Impact","References","Active","Verified","FalsePositive","Duplicate"])

    with open(jsonFile) as json_data:
        data = json.load(json_data)
        finding = []
        endpoint = data["target_url"]
        for item in data:
            if item == "interesting_findings":
                interesting_findings = data["interesting_findings"]
                findingInfo("Interesting Finding", csvwriter,endpoint, "", data["interesting_findings"])

            if data == "version":
                findingInfo("WP Finding", csvwriter,endpoint,findingHeaderInfo(data["version"]), data["version"]["vulnerabilities"])

            if item == "plugins":
                plugins = data[item]
                for plugin in plugins:
                    findingInfo("Plugin", csvwriter,endpoint, "", plugins[plugin]["vulnerabilities"])

    csv_output.close()
