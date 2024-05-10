FROM openjdk:8u292-oraclelinux8
# author
MAINTAINER eangulee <cuixingfan@reddatetech.com>
VOLUME /tmp 
VOLUME /data

ADD icron-java-1.0-SNAPSHOT.jar /app.jar

ENV JVM_OPTION="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -XX:InitialRAMPercentage=75.0 -XX:MinRAMPercentage=75.0 -XX:MetaspaceSize=256m -XX:MaxMetaspaceSize=256m"
ENV AGENTS=""
ENV JVM_RUN_OPS=""

ADD runjar.sh run.sh
RUN chmod +x run.sh


RUN mkdir -p "/data/init" && \
		mkdir -p "/data/logs"

CMD ./run.sh

EXPOSE 8081
