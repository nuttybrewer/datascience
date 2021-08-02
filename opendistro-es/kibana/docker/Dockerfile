ARG IMAGE_NAME=amazon/opendistro-for-elasticsearch-kibana
ARG IMAGE_TAG=1.13.2
FROM ${IMAGE_NAME}:${IMAGE_TAG}
USER 0
ADD --chown=1000:0 entrypoint.sh /usr/share/kibana/docker-entrypoint.sh
RUN chmod 755 /usr/share/kibana/docker-entrypoint.sh
USER 1000
ENTRYPOINT ["/usr/share/kibana/docker-entrypoint.sh"]
