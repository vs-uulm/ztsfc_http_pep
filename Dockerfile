FROM ubuntu:latest

ADD ./main /main

RUN mkdir /config
RUN mkdir /certs
RUN mkdir -p /etc/letsencrypt/live/
RUN mkdir -p /etc/letsencrypt/archive

EXPOSE 443

CMD /main
