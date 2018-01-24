#!/usr/bin/env python
import xml.etree.ElementTree as ET
import csv
from datetime import datetime
import re
import argparse
import os

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    #Command line options
    parser.add_argument("-f", "--file", help="File to process", required=True)
    args = parser.parse_args()

    #Parse the XML file
    tree = None
    try:
        #Open up the XML file from the nikto output
        tree = ET.parse(args.file)
        root = tree.getroot()
        scan = root.find('scandetails')
        datestring = datetime.strftime(datetime.now(), '%m/%d/%Y')

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

        for item in scan.findall('item'):
            finding = []

            #CSV format

            ####### Individual fields ########
            #Date
            finding.append(datestring)

            #Title
            titleText = None
            description = item.find("description").text
            #Cut the title down to the first sentence
            sentences = re.split(r'(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?)\s', description)
            if len(sentences) > 0:
                titleText = sentences[0][:900]
            else:
                titleText = description[:900]
            finding.append(titleText)

            #CweId
            finding.append("0")

            #Url
            ip = item.find("iplink").text
            #Remove the port numbers for 80/443
            ip = ip.replace(":80","")
            ip = ip.replace(":443","")

            finding.append(ip)

            #Severity
            finding.append("Low") #Nikto doesn't assign severity, default to low

            #Description
            finding.append(item.find("description").text)

            #Mitigation
            finding.append("")

            #Impact
            finding.append("")

            #References
            finding.append("")

            #Active
            finding.append("False")

            #Verified
            finding.append("False")

            #FalsePositive
            finding.append("False")

            #Duplicate
            finding.append("False")

            csvwriter.writerow(finding)

        csv_output.close()
    except:
        print "Nothing in report"
