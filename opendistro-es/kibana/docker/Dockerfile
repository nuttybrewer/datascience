ARG IMAGE_NAME=amazon/opendistro-for-elasticsearch-kibana
ARG IMAGE_TAG=1.13.2
FROM ${IMAGE_NAME}:${IMAGE_TAG}
ADD entrypoint.sh /usr/share/kibana/docker-entrypoint.sh
RUN chmod 755 /usr/share/kibana/docker-entrypoint.sh
ENTRYPOINT ["/usr/share/kibana/docker-entrypoint.sh"]
