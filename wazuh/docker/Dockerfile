ARG IMAGE_NAME=debian
ARG IMAGE_TAG=stretch-slim
FROM ${IMAGE_NAME}:${IMAGE_TAG}
RUN apt update
RUN apt -y install curl apt-transport-https lsb-release gnupg procps
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
RUN echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
RUN apt update
RUN apt -y install wazuh-manager
RUN update-rc.d wazuh-manager defaults 95 10
COPY entrypoint.sh /docker-entrypoint.sh
RUN chmod o+x /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]
EXPOSE 514/tcp 514/udp 1514/tcp 1515/udp 1515/tcp 1516/tcp 55000/tcp
