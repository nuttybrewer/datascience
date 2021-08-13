# Steps taken from https://documentation.wazuh.com/current/installation-guide/open-distro/distributed-deployment/step-by-step-installation/wazuh-cluster/wazuh_multi_node_cluster.html#wazuh-multi-node-cluster
ARG IMAGE_NAME=debian
ARG IMAGE_TAG=stretch-slim
FROM ${IMAGE_NAME}:${IMAGE_TAG}
RUN apt update
RUN apt -y install curl apt-transport-https lsb-release gnupg procps net-tools wget xmlstarlet
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
RUN echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
RUN wget https://github.com/mikefarah/yq/releases/download/v4.11.2/yq_linux_amd64.tar.gz -O - | tar xz && mv yq_linux_amd64 /usr/bin/yq
RUN apt update
RUN apt -y install wazuh-manager filebeat python3-pip
RUN python3 -m pip install boto3
RUN python3 -m pip install google-cloud-pubsub
RUN python3 -m pip install docker
# PIP installs build-essentials which we don't want bloating the image
RUN apt -y purge python3-pip && apt -y autoremove
# We get into weird situations with volume persistence, so we'll move the entire OSSEC install to /opt/ossec
# and from there "link it" in place.
RUN mv /var/ossec /opt/ossec && ln -s /opt/ossec /var/ossec 
ADD filebeat.yml /etc/filebeat/filebeat.yml
RUN curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.1/extensions/elasticsearch/7.x/wazuh-template.json
RUN chmod go+r /etc/filebeat/wazuh-template.json
RUN curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.1.tar.gz | tar -xvz -C /usr/share/filebeat/module
RUN update-rc.d wazuh-manager defaults 95 10
RUN update-rc.d filebeat defaults 95 10
ADD entrypoint.sh /docker-entrypoint.sh
RUN chmod o+x /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]
EXPOSE 514/tcp 514/udp 1514/tcp 1515/udp 1515/tcp 1516/tcp 55000/tcp
