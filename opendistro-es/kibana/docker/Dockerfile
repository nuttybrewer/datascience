ARG IMAGE_NAME=amazon/opendistro-for-elasticsearch-kibana
ARG IMAGE_TAG=1.13.2
FROM ${IMAGE_NAME}:${IMAGE_TAG}
USER kibana
RUN /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-4.1.5_7.10.2-1.zip && ls -alh /usr/share/kibana/data
USER root
RUN chown -R 1000:1000 /usr/share/kibana/data
RUN ls -alh /usr/share/kibana/data
USER kibana
