#!/bin/bash
echo "KIBANA_PLUGINS_SPACE_DELIMITED: ${KIBANA_PLUGINS_SPACE_DELIMITED:-None}"
if [[ ! -z "${KIBANA_PLUGINS_SPACE_DELIMITED}" ]]; then
  echo "Installing external kibana plugins..."
  IFS=' ' read -r -a PLUGINS <<< "${KIBANA_PLUGINS_SPACE_DELIMITED}"
  for PLUGIN in "${PLUGINS[@]}";do
    echo "Installing ${PLUGIN}"
  #   exec /usr/share/kibana/bin/kibana-plugin install "${PLUGIN}"
  done
  sudo -c "chown -R kibana:root /usr/share/kibana/data"
fi

if [[ -f "/var/run/wazuh.yml" ]]; then
  echo "Detected wazuh plugin confuration, copying into place"
  cp /var/run/wazuh.yml /usr/share/kibana/data/wazuh/config/wazuh.yml
  chown kibana:root /usr/share/kibana/data/wazuh/config/wazuh.yml
  chmod 644 /usr/share/kibana/data/wazuh/config/wazuh.yml
fi

/usr/local/bin/kibana-docker
