FROM ubuntu:16.04

# ASPTAG = appsecpipeline/base:1.4

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y \
    build-essential \
    ca-certificates \
    git \
    python-pip \
    python2.7 \
    python2.7-dev \
    csvtool \
    openjdk-9-jre-headless \
    nmap

########## AppSecPipeline Install ##########
COPY tools /usr/bin/appsecpipeline/tools
COPY dockers/base/setupdocker.sh /tmp
ENV PATH="/usr/bin/appsecpipeline/tools:${PATH}"
RUN sh /tmp/setupdocker.sh
RUN rm /tmp/setupdocker.sh

########## Change to appsecpipeline user ##########
USER appsecpipeline

ENTRYPOINT ["launch.py"]

HEALTHCHECK --interval=1m --retries=2 --timeout=5s CMD python /usr/bin/appsecpipeline/tools/health.py
