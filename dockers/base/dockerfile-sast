FROM ubuntu:16.04

# ASPTAG = appsecpipeline/sast:1.0

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
    openjdk-9-jre-headless \
    cloc \
    unzip \
    wget 

########## AppSecPipeline Install ##########
COPY tools /usr/bin/appsecpipeline/tools
COPY dockers/base/setupdocker.sh /tmp
ENV PATH="/usr/bin/appsecpipeline/tools:${PATH}"
RUN sh /tmp/setupdocker.sh
RUN rm /tmp/setupdocker.sh

########## Checkmarx Install ##########
RUN pip install -r /usr/bin/appsecpipeline/tools/checkmarx/requirements.txt

########## Bandit Install ##########
RUN pip install -U bandit

########## Dependency Checker Install ##########
RUN wget -O /tmp/dependency-check.zip https://bintray.com/jeremy-long/owasp/download_file?file_path=dependency-check-3.0.2-release.zip && \
    unzip /tmp/dependency-check.zip -d /usr/bin/ && \
    rm /tmp/dependency-check.zip

#Update the NVD local database for dependency checker
#RUN /usr/bin/dependency-check/bin/dependency-check.sh --updateonly

RUN chown -R appsecpipeline: /usr/bin/dependency-check

#Dependency check needs write permission on the data directory
#RUN chmod -R u=rwx /usr/bin/dependency-check/data

USER appsecpipeline

ENTRYPOINT ["launch.py"]

HEALTHCHECK --interval=1m --retries=2 --timeout=5s CMD python /usr/bin/appsecpipeline/tools/health.py
