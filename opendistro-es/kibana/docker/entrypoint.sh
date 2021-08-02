#!/bin/bash
umask 0002

# if [[ -z "${KIBANA_PLUGINS_SPACE_DELIMITED}" ]]; then
#   IFS=' ' read -r -a PLUGINS <<< "${KIBANA_PLUGINS_SPACE_DELIMITED}"
#   for PLUGIN in "${PLUGINS[@]}";do
#     echo "Installing ${PLUGIN}"
#     exec /usr/share/kibana/bin/kibana-plugin install "${PLUGIN}"
#   done
# fi

/usr/local/bin/kibana-docker
