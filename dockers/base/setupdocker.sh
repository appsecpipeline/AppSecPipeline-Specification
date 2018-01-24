#Python dependency installs
pip install -U pyyaml
pip install -U requests
pip install -U junit_xml_output
pip install -U defectdojo_api
pip install -U cryptography

chmod +x /usr/bin/appsecpipeline/tools/launch.py
chmod +x /usr/bin/appsecpipeline/tools/junit.py

useradd -m -d /home/appsecpipeline appsecpipeline -u 1000
