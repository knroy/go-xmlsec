# The interop image: Go, xmlsec1 1.3 and Apache Santuario, the two
# independent implementations the differential tests compare against.
#
# Alpine, because it ships xmlsec 1.3; 1.2, which Debian and Ubuntu package,
# does not implement XML Encryption 1.1 rsa-oaep. Built by tests/interop.sh.

FROM maven:3-eclipse-temurin-21 AS santuario
WORKDIR /h
COPY santuario/pom.xml santuario/Harness.java ./
RUN mvn -q dependency:copy-dependencies -DoutputDirectory=lib \
 && javac -cp 'lib/*' -d classes Harness.java

FROM golang:1.26-alpine
RUN apk add --no-cache xmlsec openjdk21-jre-headless
COPY --from=santuario /h/lib /opt/santuario/lib
COPY --from=santuario /h/classes /opt/santuario/classes
RUN printf '#!/bin/sh\nexec java -Dorg.apache.xml.security.ignoreLineBreaks=true -cp "/opt/santuario/classes:/opt/santuario/lib/*" Harness "$@"\n' \
      > /usr/local/bin/santuario \
 && chmod +x /usr/local/bin/santuario
