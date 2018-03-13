FROM node:9.4.0

# ASPTAG = appsecpipeline/node:1.0

USER root

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y \
    build-essential \
    ca-certificates \
    git \
    python-pip \
    python2.7 \
    python2.7-dev \
    && apt-get remove python-pip -y \
    && easy_install pip \
    && pip install -I pyOpenSSL \
    && usermod -u 2000 node \
    && groupmod -g 2000 node \
    && find / /proc -prune  -group 1000 -exec chgrp -h node {} \; \
    && find / /proc -prune -user 1000 -exec chown -h foo {} \;

########## AppSecPipeline Install ##########
COPY tools /usr/bin/appsecpipeline/tools
COPY dockers/base/setupdocker.sh /tmp
ENV PATH="/usr/bin/appsecpipeline/tools:${PATH}"
RUN sh /tmp/setupdocker.sh
RUN rm /tmp/setupdocker.sh

########## Retire.js Install ##########
RUN npm install -g retire

########## wappalyzer Install ##########
RUN npm install -g wappalyzer

########## Install Synk Install ##########
RUN npm install -g snyk

########## Change to appsecpipeline user ##########
USER appsecpipeline

ENTRYPOINT ["launch.py"]

HEALTHCHECK --interval=1m --retries=2 --timeout=5s CMD python /usr/bin/appsecpipeline/tools/health.py
