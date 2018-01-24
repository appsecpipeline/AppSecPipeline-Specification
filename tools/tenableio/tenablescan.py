#!/usr/bin/env python

"""tenablescan.py: Scans a hosts on tenable's cloud platform"""

__author__      = "Aaron Weaver"
__copyright__   = "Copyright 2018, Aaron Weaver"

import os
import argparse
from datetime import datetime
from time import time

from tenable_io.api.models import Scan
from tenable_io.api.scans import ScanExportRequest
from tenable_io.client import TenableIOClient
from tenable_io.exceptions import TenableIOApiException

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', help='Target IP', required=True)
    parser.add_argument('--report', help='Name of report', required=True)
    parser.add_argument('--access_key', help='Tenable API access key', required=True)
    parser.add_argument('--secret_key', help='Tenable API secret key', required=True)
    parser.add_argument('--scan_name', help='Scan Name', required=False, default="API Dynamic Scan")
    parser.add_argument('--template', help='Template to utilize.', required=False, default="basic")

    args = parser.parse_args()

    client = TenableIOClient(access_key=args.access_key, secret_key=args.secret_key)

    scan = client.scan_helper.create(
        name=args.scan_name,
        text_targets=args.target,
        template=args.template
    )

    nessus_file = args.report

    scan.launch().download(nessus_file, format=ScanExportRequest.FORMAT_NESSUS)
    scan.delete()
