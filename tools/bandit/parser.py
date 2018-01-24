import csv
from datetime import datetime
import re
import argparse
import os

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
def generic_csv(date=None, title=None, cwe=None, url=None, severity=None, description=None, mitigation=None, impact=None, references=None, active="False", verified="False", falsepositive="False", duplicate="False"):

    finding = []
    datestring = datetime.strftime(datetime.now(), '%m/%d/%Y')

    #Date
    finding.append(datestring)

    #Title
    finding.append(title)

    #CweId
    finding.append(cwe)

    #Url
    finding.append(url)

    #Severity
    finding.append(severity)

    #Description
    finding.append(description)

    #Mitigation
    finding.append(mitigation)

    #Impact
    finding.append(impact)

    #References
    finding.append(references)

    #Active
    finding.append(active)

    #Verified
    finding.append(verified)

    #FalsePositive
    finding.append(falsepositive)

    #Duplicate
    finding.append(duplicate)

    return finding

def writeFirstRow(csvwriter):
    csvwriter.writerow(["Date","Title","CweId","Url","Severity","Description","Mitigation","Impact","References","Active","Verified","FalsePositive","Duplicate"])

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    #Command line options
    parser.add_argument("-f", "--file", help="File to process", required=True)
    args = parser.parse_args()

    """
    filename,test_name,test_id,issue_severity,issue_confidence,issue_text,line_number,line_range
    PyBitBucket.py,blacklist,B405,LOW,HIGH,"Using cElementTree to parse untrusted XML data is known to be vulnerable to XML attacks. Replace cElementTree with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.",6,"[6, 7, 8, 9]"
    """

    #Constants for column names
    FILENAME = 0
    TEST_NAME = 1
    ISSUE_SEVERITY = 3
    ISSUE_CONFIDENCE = 4
    ISSUE_TEXT = 5
    LINE_NUMBER = 6
    LINE_RANGE = 7

    #Find only the base filname, save as csv
    base = os.path.basename(args.file)
    csv_output = open(os.path.join(os.path.dirname(args.file), "generic_" + os.path.splitext(base)[0] + ".csv"), 'w')
    csvwriter = csv.writer(csv_output)

    with open(args.file, 'rb') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')
        writeFirstRow(csvwriter)
        first = True
        for row in reader:
            if first:
                first = False
            else:
                description = row[ISSUE_TEXT]
                description = description + " Filename: " + row[FILENAME]
                description = description + " Line number: " + row[LINE_NUMBER]
                description = description + " Line range: " + row[LINE_RANGE].strip("\n")
                description = description + " Issue Confidence: " + row[ISSUE_CONFIDENCE]
                csvwriter.writerow(generic_csv(title=row[TEST_NAME], severity=ISSUE_SEVERITY, description=description))
