ARG IMAGE_NAME=amazon/opendistro-for-elasticsearch-kibana
ARG IMAGE_TAG=1.13.2
FROM ${IMAGE_NAME}:${IMAGE_TAG}
USER 0
RUN yum install -y sudo
RUN usermod -a -G wheel kibana
ADD --chown=1000:0 entrypoint.sh /docker-entrypoint.sh
RUN chmod 0744 /docker-entrypoint.sh
USER 1000
CMD ["/docker-entrypoint.sh"]
