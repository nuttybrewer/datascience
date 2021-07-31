#!/bin/bash
echo "${WAZUH_CLUSTER_DISABLED}"
echo "${WAZUH_CLUSTER_NODE_TYPE}"
echo "${WAZUH_CLUSTER_MASTER}"
# echo "${WAZUH_CLUSTER_KEY}"
echo "${WAZUH_CLUSTER_NAME}"

# The configuration file isn't valid XML, we need to wrap it in root tags
XML_CONFIG=$(echo "<root>$(cat /var/ossec/etc/ossec.conf)</root>")

# Edit the configuration file for cluster variables
if [[ $WAZUH_CLUSTER_DISABLED -eq "no" ]]; then
  XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -u "/root/ossec_config/cluster/node_name" -v $(hostname))
  XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -u "/root/ossec_config/cluster/disabled" -v "no")
  XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -u "/root/ossec_config/cluster/key" -v "${WAZUH_CLUSTER_KEY:-changemechangemechangemechangeme}")
  if [[ $WAZUH_CLUSTER_NODE_TYPE -eq "master" ]]; then
    XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -u "/root/ossec_config/cluster/nodes/node" -v $(hostname))
    XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -u "/root/ossec_config/cluster/node_type" -v "master")
  else
    XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -u "/root/ossec_config/cluster/nodes/node" -v "${WAZUH_CLUSTER_MASTER}")
    XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -u "/root/ossec_config/cluster/node_type" -v "worker")
  fi

  # Output config file, strip the root elements first!
  echo $XML_CONFIG | tail -n +2 | head -n -1 > /var/ossec/etc/ossec.conf

  # Load up the config for the next batch of editing
  XML_CONFIG=$(echo "<root>$(cat /var/ossec/etc/ossec.conf)</root>")
fi

service wazuh-manager start
# Create self-sign certs if they don't exist for filebeat
if [[ ! -f "/etc/filebeat/certs/filebeat.pem" ]]; then
  if [[ ! -d "/etc/filebeat/certs" ]]; then
    mkdir /etc/filebeat/certs
  fi
  openssl req -nodes -x509 -newkey rsa:4096 -keyout /etc/filebeat/certs/filebeat-key.pem -out /etc/filebeat/certs/filebeat.pem -days 365 -subj "/CN=myfilebeatnode.internal/emailAddress=dev@example.internal"
  cp /etc/filebeat/certs/filebeat.pem /etc/filebeat/certs/root-ca.pem
  chmod 0600 /etc/filebeat/certs/*.pem
fi
service filebeat start

# Check that wazuh manager started properly
/var/ossec/bin/cluster_control -l

# Check that filebeat started properly
service filebeat status
filebeat test output

tail -F /var/ossec/logs/archives/archives.json
