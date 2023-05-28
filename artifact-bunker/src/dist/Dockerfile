FROM ubuntu:22.04

COPY archive_server project.cfg /opt/
COPY static /opt/static

RUN mkdir /project/ && chmod 0777 /project/
COPY project/* /project/
RUN echo "flug{FLAG WILL BE IN THIS FILE AND WILL LIKELY BE FAIRLY LENGTHY BUT YOU PROBABLY ALREADY KNEW THAT SO JUST WRITE A GOOD EXPLOIT OK}" > /project/flag.txt

RUN adduser --disabled-password --gecos "" user
RUN mkdir /data && chmod 0777 /data

USER user

WORKDIR /opt
EXPOSE 5555
CMD /opt/archive_server
