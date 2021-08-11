#!/bin/bash
echo "Provided environment variables"
echo "WAZUH_CONFIG_USE_MOUNTED_VOLUME: ${WAZUH_CONFIG_USE_MOUNTED_VOLUME:-no}"
echo "WAZUH_CLUSTER_DISABLED: ${WAZUH_CLUSTER_DISABLED:-yes}"
echo "WAZUH_CLUSTER_NAME: ${WAZUH_CLUSTER_NAME:-wazuh}"
echo "WAZUH_CLUSTER_NODE_TYPE: ${WAZUH_CLUSTER_NODE_TYPE:-worker}"
echo "WAZUH_CLUSTER_MANAGER: ${WAZUH_CLUSTER_MANAGER:-localhost}"
echo "WAZUH_AUTHD_DISABLED: ${WAZUH_AUTHD_DISABLED:-yes}"
echo "WAZUH_AUTHD_AGENT_PASSPHRASE_DISABLED: ${WAZUH_AUTHD_AGENT_PASSPHRASE_DISABLED:-yes}"
echo "WAZUH_AUTHD_AGENT_CA_DISABLED: ${WAZUH_AUTHD_AGENT_CA_DISABLED:-yes}"
echo "WAZUH_AUTHD_AGENT_CA_PATH: ${WAZUH_AUTHD_AGENT_CA_PATH:-/var/ossec/etc/rootCA.pem}"
echo "FILEBEAT_CONFIG_USE_MOUNTED_VOLUME: ${FILEBEAT_CONFIG_USE_MOUNTED_VOLUME:-no}"
echo "FILEBEAT_ES_HOSTS: ${FILEBEAT_ES_HOSTS}"
echo "FILEBEAT_ES_SSL_VERIFICATION_MODE: ${FILEBEAT_ES_SSL_VERIFICATION_MODE:-certificate}"
echo "FILEBEAT_ES_USER: ${FILEBEAT_ES_USER}"

if [[ $WAZUH_CONFIG_USE_MOUNTED_VOLUME != "yes" ]]; then
  # The configuration file isn't valid XML, we need to wrap it in root tags
  XML_CONFIG=$(echo "<root>$(cat /var/ossec/etc/ossec.conf)</root>")

  # Edit the configuration file for cluster variables
  if [[ $WAZUH_CLUSTER_DISABLED == "no" ]]; then
    echo "Configuring wazuh cluster"
    XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -u "/root/ossec_config/cluster/node_name" -v $(hostname))
    XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -u "/root/ossec_config/cluster/disabled" -v "no")
    XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -u "/root/ossec_config/cluster/key" -v "${WAZUH_CLUSTER_KEY:-changemechangemechangemechangeme}")
    if [[ $WAZUH_CLUSTER_NODE_TYPE == "manager" ]]; then
      echo "Configuring node as a manager"
      XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -u "/root/ossec_config/cluster/nodes/node" -v $(hostname))
      XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -u "/root/ossec_config/cluster/node_type" -v "master")
    else
      echo "Configuring node as a worker to connect to ${WAZUH_CLUSTER_MANAGER}"
      XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -u "/root/ossec_config/cluster/nodes/node" -v "${WAZUH_CLUSTER_MANAGER}")
      XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -u "/root/ossec_config/cluster/node_type" -v "worker")
    fi
  else
    XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -u "/root/ossec_config/cluster/disabled" -v "yes")
  fi

  if [[ $WAZUH_AUTHD_DISABLED == "no" ]]; then
    echo "Turning on authd"
    XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -u "/root/ossec_config/auth/disabled" -v "no")
    if [[ $WAZUH_AUTHD_AGENT_PASSPHRASE_DISABLED == "no" ]];then
      XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -u "/root/ossec_config/auth/use_password" -v "yes")
    fi
    if [[ $WAZUH_AUTHD_AGENT_CA_DISABLED == "no" ]]; then
      echo "Turning on ssl_agent_ca check for authd"
      XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -i "/root/ossec_config/auth" -t elem -n "ssl_agent_ca" -v "${WAZUH_AUTHD_AGENT_CA_PATH:-/var/ossec/etc/rootCA.pem}")
    fi
  else
    XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -u "/root/ossec_config/cluster/disabled" -v "no")
  fi

  echo "${XML_CONFIG}" | xmlstarlet fo -o | tail -n +2 | head -n "-1" > /var/ossec/etc/ossec.conf
  XML_CONFIG=$(echo "<root>$(cat /var/ossec/etc/ossec.conf)</root>")
fi

service wazuh-manager start

# Create self-sign certs if they do not exist for filebeat
if [[ ! -d "/etc/filebeat/certs" ]]; then
  echo "Creating self-signed certs for Filebeat in default location"
  mkdir /etc/filebeat/certs
  openssl req -nodes -x509 -newkey rsa:4096 -keyout /etc/filebeat/certs/filebeat-key.pem -out /etc/filebeat/certs/filebeat.pem -days 365 -subj "/CN=myfilebeatnode.internal/emailAddress=dev@example.internal"
  cp /etc/filebeat/certs/filebeat.pem /etc/filebeat/certs/root-ca.pem
  chmod 0600 /etc/filebeat/certs/*.pem
fi

# Configure filebeats with environment variables
if [[ $FILEBEAT_CONFIG_USE_MOUNTED_VOLUME != "yes" ]]; then
  if [[ $FILEBEAT_ES_HOSTS ]]; then
    echo "Adding ${FILEBEAT_ES_HOSTS} to /etc/filebeat/filebeat.yml"
    yq eval -i '.output.elasticsearch.hosts = env(FILEBEAT_ES_HOSTS) | .output.elasticsearch.hosts[] style="double"' /etc/filebeat/filebeat.yml
    if [[ $FILEBEAT_ES_SSL_VERIFICATION_MODE ]]; then
      yq eval -i '.output.elasticsearch.ssl.["verification_mode"] = env(FILEBEAT_ES_SSL_VERIFICATION_MODE)' /etc/filebeat/filebeat.yml
    else
      yq eval -i '.output.elasticsearch.ssl.["verification_mode"] = "none"' /etc/filebeat/filebeat.yml
    fi
    if [[ $FILEBEAT_ES_USER ]]; then
      echo "Adding ${FILEBEAT_ES_USER} and password to /etc/filebeat/filebeat.yml"
      yq eval -i '.output.elasticsearch.username = env(FILEBEAT_ES_USER) | .output.elasticsearch.password = env(FILEBEAT_ES_PASS)' /etc/filebeat/filebeat.yml
    else
      echo "Removing output.elasticsearch.username and password from /etc/filebeat/filebeat.yml"
      yq eval -i 'del(.output.elasticsearch.username) | del(.output.elasticsearch.password)' /etc/filebeat/filebeat.yml
    fi
  fi
  chmod 644 /etc/filebeat/filebeat.yml
fi
service filebeat start

# Check that wazuh manager started properly
WAIT=10
echo "Checking that ossec-clusterd is running..."
sleep $WAIT
/var/ossec/bin/cluster_control -l


# Check that filebeat started properly
service filebeat status
filebeat test output

tail -F /var/ossec/logs/ossec.log
