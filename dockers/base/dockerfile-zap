FROM owasp/zap2docker-stable:2.7.0

# ASPTAG = appsecpipeline/zap:1.0

USER root

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y \
    build-essential \
    ca-certificates \
    python-pip \
    python2.7 \
    python2.7-dev

########## AppSecPipeline Install ##########
COPY tools /usr/bin/appsecpipeline/tools
ENV PATH="/usr/bin/appsecpipeline/tools:${PATH}"

#Python dependency installs
RUN pip install -U requests
RUN pip install -U junit_xml_output
RUN pip install -U defectdojo_api
RUN pip install -U cryptography
RUN pip install -U pyyaml

RUN chmod +x /usr/bin/appsecpipeline/tools/launch.py
RUN chmod +x /usr/bin/appsecpipeline/tools/junit.py

########## Zap Baseline Install ##########
#Override the baseline zap python script
COPY tools/zap/zap-baseline.py /zap/

RUN usermod -u 1000 zap
RUN groupmod -g 1000 zap

USER zap

ENTRYPOINT ["launch.py"]

HEALTHCHECK --interval=1m --retries=2 --timeout=5s CMD python /usr/bin/appsecpipeline/tools/health.py
