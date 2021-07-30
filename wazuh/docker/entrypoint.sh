#!/bin/bash
service wazuh-manager start
# Create self-sign certs if they don't exist for filebeat
if [[ ! -f "/etc/filebeat/certs/filebeat.pem"]]; then
  if [[ ! -d '/etc/filebeat/certs' ]]; then
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
