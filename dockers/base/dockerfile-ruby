FROM ruby:2.4

# ASPTAG = appsecpipeline/ruby:1.0

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y \
    build-essential \
    ca-certificates \
    git \
    python-pip \
    python2.7 \
    python2.7-dev

########## AppSecPipeline Install ##########
COPY tools /usr/bin/appsecpipeline/tools
COPY dockers/base/setupdocker.sh /tmp
ENV PATH="/usr/bin/appsecpipeline/tools:${PATH}"
RUN sh /tmp/setupdocker.sh
RUN rm /tmp/setupdocker.sh

########## AppSecPipeline Install ##########
ENV BRAKEMAN_VERSION=4.0
RUN gem install brakeman --version ${BRAKEMAN_VERSION} --no-format-exec

########## WPScan Install ##########
#RUN cd /tmp && git clone https://github.com/wpscanteam/wpscan-v3
#RUN cd /tmp/wpscan-v3 && bundle install && rake install && cd ../
RUN gem install wpscan

#Update WPScanner DB
RUN wpscan --update

########## Change to appsecpipeline user ##########
USER appsecpipeline

ENTRYPOINT ["launch.py"]

HEALTHCHECK --interval=1m --retries=2 --timeout=5s CMD python /usr/bin/appsecpipeline/tools/health.py
