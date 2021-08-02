ARG IMAGE_NAME=amazon/opendistro-for-elasticsearch-kibana
ARG IMAGE_TAG=1.13.2
FROM ${IMAGE_NAME}:${IMAGE_TAG}
USER 0
ADD --chown=1000:0 entrypoint.sh /docker-entrypoint.sh
RUN chmod o+x /usr/share/kibana/docker-entrypoint.sh
USER 1000
CMD ["/docker-entrypoint.sh"]
