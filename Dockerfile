# Copyright 2018 Netflix, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM alpine:latest
MAINTAINER Netflix Open Source Development <talent@netflix.com>

ENV SECURITY_MONKEY_VERSION=v1.0 \
    SECURITY_MONKEY_SETTINGS=/usr/local/src/security_monkey/env-config/config-docker.py

WORKDIR /usr/local/src/security_monkey
COPY requirements.txt /usr/local/src/security_monkey/

RUN echo "UTC" > /etc/timezone

RUN apk add --no-cache postgresql-libs libffi libxml2 xmlsec bash python2 py2-pip postgresql-client &&\
    apk add --no-cache --virtual build python2-dev build-base postgresql-dev libffi-dev libxml2-dev xmlsec-dev &&\
    pip install setuptools --upgrade && \
    pip install "urllib3[secure]" --upgrade && \
    pip install google-compute-engine && \
    pip install cloudaux\[gcp\] && \
    pip install cloudaux\[openstack\] && \
    pip install python-saml && \
    pip install -r requirements.txt && \
    apk del build
    
COPY . /usr/local/src/security_monkey
RUN pip install ."[onelogin]" && \
    /bin/mkdir -p /var/log/security_monkey/ && \
    touch /var/log/security_monkey/securitymonkey.log

EXPOSE 5000
