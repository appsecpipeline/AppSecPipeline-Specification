#!/usr/bin/env python

"""ScanProject.py: Scans a project given a source folder and Checkmarx project"""

__author__      = "Aaron Weaver"
__copyright__   = "Copyright 2018, Aaron Weaver"

import PyCheckmarx
import argparse


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('--project', help='Checkmarx Project ID for scanning', required=True)
	parser.add_argument('--source', help='Source code directory', required=True)
	parser.add_argument('--report', help='Name of report', required=True)
	parser.add_argument('--url', help='Checkmarx URL', required=True)
	parser.add_argument('--username', help='Checkmarx username', required=True)
	parser.add_argument('--password', help='Checkmarx password', required=True)
	args = parser.parse_args()

	pyC = PyCheckmarx.PyCheckmarx(args.username, args.password, args.url)
	runID = pyC.scanExistingProject(args.project, args.source)
	scanID, message = pyC.getStatusOfSingleScan(runID)

	#Check for re-scan as incremental changes require full re-scan
	if message == "FullScan":
		print "Re-submitting as full scan"
		runID = pyC.scanExistingProject(args.project, args.source, incremental=False)
		scanID, message = pyC.getStatusOfSingleScan(runID)

	if scanID is not None:
		pyC.getXMLReport(scanID, args.report)
	else:
		print "Review the scan logs, a scanID was not returned."

	print "Checkmarx complete"
