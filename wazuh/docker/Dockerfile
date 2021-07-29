# Steps taken from https://documentation.wazuh.com/current/installation-guide/open-distro/distributed-deployment/step-by-step-installation/wazuh-cluster/wazuh_multi_node_cluster.html#wazuh-multi-node-cluster
ARG IMAGE_NAME=debian
ARG IMAGE_TAG=stretch-slim
FROM ${IMAGE_NAME}:${IMAGE_TAG}
RUN apt update
RUN apt -y install curl apt-transport-https lsb-release gnupg procps
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
RUN echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
RUN apt update
RUN apt -y install wazuh-manager filebeat
RUN curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/resources/4.1/open-distro/filebeat/7.x/filebeat_elastic_cluster.yml
RUN curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.1/extensions/elasticsearch/7.x/wazuh-template.json
RUN chmod go+r /etc/filebeat/wazuh-template.json
RUN curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.1.tar.gz | tar -xvz -C /usr/share/filebeat/module
RUN update-rc.d wazuh-manager defaults 95 10
RUN update-rc.d filebeat defaults 95 10
COPY entrypoint.sh /docker-entrypoint.sh
RUN chmod o+x /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]
EXPOSE 514/tcp 514/udp 1514/tcp 1515/udp 1515/tcp 1516/tcp 55000/tcp
