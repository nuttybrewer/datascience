#!/bin/bash
echo "Provided environment variables"
echo "WAZUH_CONFIG_USE_MOUNTED_VOLUME: ${WAZUH_CONFIG_USE_MOUNTED_VOLUME:-no}"
echo "WAZUH_AGENT_DISABLED: ${WAZUH_AGENT_DISABLED:-yes}"
echo "WAZUH_AGENT_SERVICE_ADDRESS: ${WAZUH_AGENT_SERVICE_ADDRESS:-None}"
echo "WAZUH_AGENT_ENROLLMENT_DISABLED: ${WAZUH_AGENT_ENROLLMENT_DISABLED:-yes}"
echo "WAZUH_AGENT_ENROLLMENT_AGENT_NAME: ${WAZUH_AGENT_ENROLLMENT_AGENT_NAME:-$(hostname)}"
echo "WAZUH_AGENT_ENROLLMENT_MANAGER_ADDRESS: ${WAZUH_AGENT_ENROLLMENT_MANAGER_ADDRESS:-None}"
echo "WAZUH_AGENT_ENROLLMENT_CA_PATH: ${WAZUH_AGENT_ENROLLMENT_CA_PATH:-None}"
echo "WAZUH_AGENT_ENROLLMENT_KEY_PATH: ${WAZUH_AGENT_ENROLLMENT_KEY_PATH:-None}"
echo "WAZUH_AGENT_ENROLLMENT_CERT_PATH: ${WAZUH_AGENT_ENROLLMENT_CERT_PATH:-None}"

if [[ $WAZUH_CONFIG_USE_MOUNTED_VOLUME != "yes" ]]; then
  # The configuration file isn't valid XML, we need to wrap it in root tags
  XML_CONFIG=$(echo "<root>$(cat /var/ossec/etc/ossec.conf)</root>")

  if [[ $WAZUH_AGENT_DISABLED == "no" ]]; then
    echo "Configuring wazuh agent"
    XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -u "/root/ossec_config/client/server/address" -v "${WAZUH_AGENT_SERVICE_ADDRESS}")
    if [[ $WAZUH_AGENT_ENROLLMENT_DISABLED == "no" ]]; then
      XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -s "/root/ossec_config/client" -t elem -n "enrollment")
      XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -s "/root/ossec_config/client/enrollment" -t elem -n "enabled"  -v "yes")
      XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -s "/root/ossec_config/client/enrollment" -t elem -n "agent_name" -v "${WAZUH_AGENT_ENROLLMENT_AGENT_NAME:-$(hostname)}")
      XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -s "/root/ossec_config/client/enrollment" -t elem -n "manager_address" -v "${WAZUH_AGENT_ENROLLMENT_MANAGER_ADDRESS}")
      if [[ ! -z $WAZUH_AGENT_ENROLLMENT_CA_PATH ]]; then
        XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -s "/root/ossec_config/client/enrollment" -t elem -n "server_ca_path" -v "${WAZUH_AGENT_ENROLLMENT_CA_PATH}")
      fi
      if [[ ! -z $WAZUH_AGENT_ENROLLMENT_KEY_PATH ]]; then
        XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -s "/root/ossec_config/client/enrollment" -t elem -n "agent_key_path" -v "${WAZUH_AGENT_ENROLLMENT_KEY_PATH}")
      fi
      if [[ ! -z $WAZUH_AGENT_ENROLLMENT_CERT_PATH ]]; then
        XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -s "/root/ossec_config/client/enrollment" -t elem -n "agent_certificate_path" -v "${WAZUH_AGENT_ENROLLMENT_CERT_PATH}")
      fi
      if [[ ! -z $WAZUH_AGENT_ENROLLMENT_CRED_PATH ]]; then
        XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -s "/root/ossec_config/client/enrollment" -t elem -n "authorization_pass_path" -v "${WAZUH_AGENT_ENROLLMENT_CRED_PATH}")
      fi
    fi
  fi

  ###
  # Insert disabled wodles

  # AWS
  echo "Configuring Empty AWS Wodle"
  XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -s "/root/ossec_config[1]" -t elem -n "wodle_aws")
  XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -i "/root/ossec_config[1]/wodle_aws" -t attr -n "name" -v "aws-s3")
  XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -s "/root/ossec_config[1]/wodle_aws" -t elem -n "disabled" -v "yes")
  XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -s "/root/ossec_config[1]/wodle_aws" -t elem -n "bucket")
  XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -s "/root/ossec_config[1]/wodle_aws/bucket" -t elem -n "name" -v "mycustombucket.example")
  XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -s "/root/ossec_config[1]/wodle_aws/bucket" -t elem -n "type" -v "custom")
  XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -r "/root/ossec_config[1]/wodle_aws" -v "wodle")
  XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -s "/root/ossec_config[1]/wodle_aws" -t elem -n "service")
  XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -i "/root/ossec_config[1]/wodle_aws/service" -t attr -n "type" -v "cloudwatchlogs")
  echo $XML_CONFIG | xmlstarlet fo -o

  # Azure
  echo "Configuring empty Azure-logs Wodle"
  XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -s "/root/ossec_config[1]" -t elem -n "wodle_azure")
  XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -i "/root/ossec_config[1]/wodle_azure" -t attr -n "name" -v "azure-logs")
  XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -s "/root/ossec_config[1]/wodle_azure" -t elem -n "disabled" -v "yes")
  XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -r "/root/ossec_config[1]/wodle_azure" -v "wodle")

  # GCP
  echo "Configuring empty GCP plugin"
  XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -s "/root/ossec_config[1]" -t elem -n "gcp-pubsub")
  XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -s "/root/ossec_config[1]/gcp-pubsub" -t elem -n "enabled" -v "no")

  # Docker
  echo "Configuring empty docker-listener wodle"
  XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -s "/root/ossec_config[1]" -t elem -n "wodle_docker")
  XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -i "/root/ossec_config[1]/wodle_docker" -t attr -n "name" -v "docker-listener")
  XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -s "/root/ossec_config[1]/wodle_docker" -t elem -n "disabled" -v "yes")
  XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -r "/root/ossec_config[1]/wodle_docker" -v "wodle")

  # Insert disabled wodles
  ###

  echo "${XML_CONFIG}" | xmlstarlet fo -o | tail -n +2 | head -n "-1" > /var/ossec/etc/ossec.conf
  XML_CONFIG=$(echo "<root>$(cat /var/ossec/etc/ossec.conf)</root>")
fi

service wazuh-agent start

tail -F /var/ossec/logs/ossec.log
