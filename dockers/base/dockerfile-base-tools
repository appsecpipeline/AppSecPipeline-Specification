FROM ubuntu:16.04

# ASPTAG = appsecpipeline/base-tools:1.0

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
    nikto \
    unzip \
    nmap \
    wget

########## AppSecPipeline Install ##########
COPY tools /usr/bin/appsecpipeline/tools
COPY dockers/base/setupdocker.sh /tmp
ENV PATH="/usr/bin/appsecpipeline/tools:${PATH}"
RUN sh /tmp/setupdocker.sh
RUN rm /tmp/setupdocker.sh

########## Tenable Install ##########
RUN pip install -U tenable_io

########## Bandit Install ##########
RUN pip install -U bandit

########## Cloc Install ##########
ARG CLOCVER=1.74

RUN mkdir /tmp/cloc
RUN wget -qO- https://github.com/AlDanial/cloc/releases/download/${CLOCVER}/cloc-${CLOCVER}.tar.gz | tar xvz -C /tmp/cloc --strip-components=1
RUN cp /tmp/cloc/cloc /usr/bin/
RUN rm -R /tmp/cloc

########## Arachni Install ##########
#Install Arachni, packaged apt-get install Arachni doesn't work for some reason, hangs on BrowserCluster
ARG VERSION=1.5.1
ARG WEB_VERSION=0.5.12

RUN mkdir /usr/share/arachni && \
          wget -qO- https://github.com/Arachni/arachni/releases/download/v${VERSION}/arachni-${VERSION}-${WEB_VERSION}-linux-x86_64.tar.gz | tar xvz -C /usr/share/arachni --strip-components=1

RUN echo '#!/bin/bash\n\ncd /usr/share/arachni/bin/ && ./arachni "$@"' > /usr/bin/arachni
RUN echo '#!/bin/bash\n\ncd /usr/share/arachni/bin/ && ./arachni_reporter "$@"' > /usr/bin/arachni_reporter

RUN chmod +x /usr/bin/arachni
RUN chmod +x /usr/bin/arachni_reporter

#For Arachni to run properly the appsecpipeline user needs write permissions on component cache
RUN chown -R appsecpipeline: /usr/share/arachni/system/

########## SSLLabs Scanner Install ##########
ARG SSLLAB=1.4.0

RUN wget -qO- https://github.com/ssllabs/ssllabs-scan/releases/download/v${SSLLAB}/ssllabs-scan_${SSLLAB}-linux64.tgz | tar xvz -C /usr/bin --strip-components=1

########## Checkmarx Install ##########
RUN pip install -r /usr/bin/appsecpipeline/tools/checkmarx/requirements.txt

########## Change to appsecpipeline user ##########
USER appsecpipeline

ENTRYPOINT ["launch.py"]

HEALTHCHECK --interval=1m --retries=2 --timeout=5s CMD python /usr/bin/appsecpipeline/tools/health.py
