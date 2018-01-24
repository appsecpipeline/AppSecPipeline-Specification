import re
from datetime import datetime
import subprocess
import shlex
import sys

def days_between(dateCompare):
    d1 = datetime.strptime(dateCompare, "%Y-%m-%d %H:%M:%S")
    return abs((datetime.now() - d1).seconds/60)

age = 0

uptime = subprocess.check_output(shlex.split("stat /proc/1/cmdline"))

for line in uptime.splitlines():
    dockerStartTime = re.search("Access\:\s(\d{1,4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})", line)

    if dockerStartTime:
      age = days_between(dockerStartTime.group(1))
      break

#Make configurable at some point, terminate if longer than 12 hours / 720
if age > 720:
    sys.exit(1)
