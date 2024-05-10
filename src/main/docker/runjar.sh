#!/bin/sh

java ${JVM_OPTION}  ${AGENTS}  -Djava.security.egd=file:/dev/./urandom  \
     -jar ${JVM_RUN_OPS}   /app.jar