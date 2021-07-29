#!/bin/bash
service wazuh-manager start
service filebeat start

# Check that wazuh manager started properly
/var/ossec/bin/cluster_control -l
# Check that filebeat started properly
# filebeat test output
tail -F /var/ossec/logs/archives/archives.json
