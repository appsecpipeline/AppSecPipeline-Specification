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

    #Criticality rating
    #Grades: https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide
    #A - Info, B - Medium, C - High, D/F/M/T - Critical
    def getCriticalityRating(rating):
        criticality = "Info"
        if "A" in rating:
            criticality = "Info"
        elif "B" in rating:
            criticality = "Medium"
        elif "C" in rating:
            criticality = "High"
        elif "D" in rating or "F" in rating or "M" in rating or "T" in rating:
            criticality = "Critical"

        return criticality

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

    datestring = datetime.strftime(datetime.now(), '%m/%d/%Y')
    title = "SSLLabs Grade:"
    with open(jsonFile) as json_data:
        data = json.load(json_data)
        for host in data:
            for endpoints in host["endpoints"]:

                grade = endpoints["grade"]
                host = host["host"]
                title = "%s %s for %s " % (title, grade, host)
                cert = endpoints["details"]["cert"]
                description = "%s \n" % title
                description = "%sCertifcate Subject: %s\n" % (description, cert["subject"])
                description = "%sIssuer Subject: %s\n" % (description, cert["issuerSubject"])
                description = "%sSignature Algorithm: %s\n" % (description, cert["sigAlg"])

                cName = ""
                for commonNames in cert["commonNames"]:
                    cName = "%s %s \n" % (cName, commonNames)

                aName = ""
                for altNames in cert["altNames"]:
                    aName = "%s %s \n" % (aName, altNames)

                protoName = ""
                for protocols in endpoints["details"]["protocols"]:
                    protoName = "%s %s %s\n" % (protoName, protocols["name"], protocols["version"])

                description = "%s\nCommon Names:\n %s\nAlternate Names: \n%s\nProtocols: \n%s" % (description, cName, aName, protoName)

                finding = []

                #CSV format

                ####### Individual fields ########
                #Date
                finding.append(datestring)

                finding.append(title)

                #CweId
                finding.append("0")

                finding.append(host)

                #Severity
                finding.append(getCriticalityRating(grade)) #Nikto doesn't assign severity, default to low

                #Description
                #finding.append('"' + description + '"')
                finding.append(description)

                #Mitigation
                finding.append("")

                #Impact
                finding.append("")

                #References
                finding.append("")

                #Active
                finding.append("True")

                #Verified
                finding.append("True")

                #FalsePositive
                finding.append("False")

                #Duplicate
                finding.append("False")

                csvwriter.writerow(finding)

    csv_output.close()
