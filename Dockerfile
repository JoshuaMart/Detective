FROM ubuntu:22.04

ARG GO_VER=1.20.4

RUN apt-get update -qq && apt-get install -y ruby git ruby-dev nano wget curl libpcap-dev make gcc

## Install Go
RUN wget https://golang.org/dl/go$GO_VER\.linux-amd64.tar.gz && \
    tar -xf go$GO_VER\.linux-amd64.tar.gz -C /usr/local/ && \
    rm go$GO_VER\.linux-amd64.tar.gz

ENV PATH="${PATH}:/usr/local/go/bin/:/root/go/bin/"

## Install ProjectDiscovery Tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/notify/cmd/notify@latest && \
    go install github.com/projectdiscovery/alterx/cmd/alterx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

## Install Cero
RUN go install github.com/glebarez/cero@latest

## Install PureDNS
RUN go install -v github.com/d3mondev/puredns/v2@latest

## Install MassDNS
RUN git clone https://github.com/blechschmidt/massdns && \
    cd massdns && make && mv bin/massdns /usr/local/bin/

## Install VHostFinder
RUN go install -v github.com/wdahlenburg/VhostFinder@latest

WORKDIR /detective
COPY src .

## Install gems
RUN gem install bundler && bundle install

ENTRYPOINT ["ruby", "main.rb"]