#!/bin/bash

# Install external plugins
echo "KIBANA_PLUGINS_SPACE_DELIMITED: ${KIBANA_PLUGINS_SPACE_DELIMITED:-None}"
if [[ ! -z "${KIBANA_PLUGINS_SPACE_DELIMITED}" ]]; then
  echo "Installing external kibana plugins..."
  IFS=' ' read -r -a PLUGINS <<< "${KIBANA_PLUGINS_SPACE_DELIMITED}"
  for PLUGIN in "${PLUGINS[@]}";do
    echo "Installing ${PLUGIN}"
    exec /usr/share/kibana/bin/kibana-plugin install "${PLUGIN}"
  done
fi

# Copy over know plugin configurations
if [[ -f "/var/run/wazuh.yml" ]]; then
  if [[ ! -d "/usr/share/kibana/data/wazuh/config" ]]; then
    echo "Creating config directory /usr/share/kibana/data/wazuh/config"
    mkdir -p "/usr/share/kibana/data/wazuh/config"
  fi
    echo "Detected wazuh plugin confuration, copying into place"
    cp /var/run/wazuh.yml /usr/share/kibana/data/wazuh/config/wazuh.yml
  else
    echo "Unable to copy over configuration, Wazuh plugin likely not installed correctly"
  fi
fi

# Run the original command file from amazon/ODFE-kibana docker image
/usr/local/bin/kibana-docker
