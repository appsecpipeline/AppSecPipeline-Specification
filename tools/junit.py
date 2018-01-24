#!/usr/bin/env python
import xml.etree.ElementTree as ET
import csv
from datetime import datetime
import re
import argparse
import os
import junit_xml_output

test_cases = []

def junit(toolName, file):

    junit_xml = junit_xml_output.JunitXml(toolName, test_cases, total_tests=None, total_failures=None)
    with open(file, 'w') as file:
        print "Writing Junit test files"
        file.write(junit_xml.dump())

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    #Command line options
    parser.add_argument("-t", "--tool", help="Tool name", required=True)
    parser.add_argument("-f", "--file", help="File to process", required=True)
    args = parser.parse_args()

    test_cases = []
    TITLE = 1
    DESCRIPTION = 5
    base = os.path.basename(args.file)
    fileName = os.path.join(os.path.dirname(args.file), "generic_" + os.path.splitext(base)[0] + ".csv")
    csvToParse = fileName

    #Test for file
    if os.path.isfile("csvToParse"):
        with open(csvToParse, 'rb') as csvfile:
            reader = csv.reader(csvfile, delimiter=',')
            first = True
            for row in reader:
                if first:
                    first = False
                else:
                    #Output a junit test file, should lows/med be condsider a failure?
                    test_cases.append(junit_xml_output.TestCase(row[TITLE], row[DESCRIPTION],"failure"))

        junit(args.tool, os.path.join(os.path.dirname(args.file), "junit", "junit_" + os.path.splitext(base)[0] + ".xml"))
    else:
        print "File passed in doesn't exist."
