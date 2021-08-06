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
echo "WAZUH_AGENT_ENROLLMENT_CRED_PATH: ${WAZUH_AGENT_ENROLLMENT_CRED_PATH:-/etc/authd.pass}"

if [[ $WAZUH_CONFIG_USE_MOUNTED_VOLUME != "yes" ]]; then
  # The configuration file isn't valid XML, we need to wrap it in root tags
  XML_CONFIG=$(echo "<root>$(cat /var/ossec/etc/ossec.conf)</root>")

  if [[ $WAZUH_AGENT_DISABLED == "no" ]]; then
    echo "Configuring wazuh agent"
    XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -i "/root/ossec_config" -t elem -n client)
    XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -i "/root/ossec_config/client" -t elem -n server)
    XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -i "/root/ossec_config/client/server" -t elem -n address -v "${WAZUH_AGENT_SERVICE_ADDRESS}")
    if [[ $WAZUH_AGENT_ENROLLMENT_DISABLED == "no" ]]; then
      XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -i "/root/ossec_config/client" -t elem -n enrollment)
      XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -i "/root/ossec_config/client/enrollment" -n "enabled" -t elem -v "yes")
      XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -i "/root/ossec_config/client/enrollment" -n "agent_name" -t elem -v "${WAZUH_AGENT_ENROLLMENT_AGENT_NAME:-$(hostname)}")
      XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -i "/root/ossec_config/client/enrollment" -n "manager_address" -t elem -v "${WAZUH_AGENT_ENROLLMENT_MANAGER_ADDRESS}")
      if [[ ! -z $WAZUH_AGENT_ENROLLMENT_CA_PATH ]]; then
        XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -i "/root/ossec_config/client/enrollment" -n "server_ca_path" -t elem -v "${WAZUH_AGENT_ENROLLMENT_CA_PATH}")
      fi
      if [[ ! -z $WAZUH_AGENT_ENROLLMENT_KEY_PATH ]]; then
        XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -i "/root/ossec_config/client/enrollment" -n "agent_key_path" -t elem -v "${WAZUH_AGENT_ENROLLMENT_KEY_PATH}")
      fi
      if [[ ! -z $WAZUH_AGENT_ENROLLMENT_CERT_PATH ]]; then
        XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -i "/root/ossec_config/client/enrollment" -n "agent_certification_path" -t elem -v "${WAZUH_AGENT_ENROLLMENT_CERT_PATH}")
      fi
      if [[ ! -z $WAZUH_AGENT_ENROLLMENT_CRED_PATH ]]; then
        XML_CONFIG=$(echo $XML_CONFIG | xmlstarlet ed -O -i "/root/ossec_config/client/enrollment" -n "authorization_pass_path" -t elem -v "${WAZUH_AGENT_ENROLLMENT_CRED_PATH}")
      fi
    fi
  fi
  # echo "${XML_CONFIG}" | xmlstarlet fo -o | tail -n +2 | head -n "-1" > /var/ossec/etc/ossec.conf
  XML_CONFIG=$(echo "<root>$(cat /var/ossec/etc/ossec.conf)</root>")
fi

service wazuh-manager start

tail -F /var/ossec/logs/ossec.log
