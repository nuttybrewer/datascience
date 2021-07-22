#!/bin/bash
service wazuh-manager start
tail -F /var/ossec/logs/archives/archives.json
