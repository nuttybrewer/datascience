#!/bin/bash
echo "KIBANA_PLUGINS_SPACE_DELIMITED: ${KIBANA_PLUGINS_SPACE_DELIMITED:-None}"
if [[ ! -z "${KIBANA_PLUGINS_SPACE_DELIMITED}" ]]; then
  echo "Installing external kibana plugins..."
  IFS=' ' read -r -a PLUGINS <<< "${KIBANA_PLUGINS_SPACE_DELIMITED}"
  for PLUGIN in "${PLUGINS[@]}";do
    echo "Installing ${PLUGIN}"
  #   exec /usr/share/kibana/bin/kibana-plugin install "${PLUGIN}"
  done
  chown -R kibana:root /usr/share/kibana/data
fi

/usr/local/bin/kibana-docker
