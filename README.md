# Data Science tools/environment
Various DevOps build definitions used for other data management projects.

# Wazuh
Reference the [Wazuh Architecture](https://documentation.wazuh.com/current/getting-started/architecture.html) page for more details.

## Architecture
The helm chart launches the docker containers as depicted in this [diagram](https://documentation.wazuh.com/current/_images/deployment1.png) provided by the Wazuh project:
![Wazuh Architecture Image](https://documentation.wazuh.com/current/_images/deployment1.png)

\*The *master* pod has been renamed to **manager** for the sake of this project.

### Exceptions to this diagram:
The helm chart does not install the Kibana/ElasticSearch environment.

The *manager* pod does not accept Agent Endpoint connections (AuthD or Secure) and has for sole purpose to host the Wazuh API (TCP 55000) and the cluster management port (TCP1516).

The *Worker* pod(s) are responsible for Agent Endpoint connections (AuthD or Secure).

An optional *Agent* pod is available in case dedicated *Wodles* or pull-type actions (like GCP) would need to be performed by the cluster to acquire logs, although these may optionally be configured on the *manager* as well.

## Installation
Launching the chart with no arguments creates a wazuh cluster with a manager pod and two worker pods and exposes the authd and secure agent communications port under a k8s service using TCP only.

### Agent Enrollment and authentication
Note, in the default scenario, the agent enrollment must be keyed manually.

In order to enable agent auto-enrollment using a passphrase, set *wazuh.authd.agentPassphraseEnabled* to *true*. In this scenario, if *wazuh.authd.agentPassphrase* is specified, the chart will mount a k8s [secret](https://kubernetes.io/docs/reference/kubernetes-api/config-and-storage-resources/secret-v1/) that will inject the passphrase into the *worker* and *agent* pods. If *wazuh.authd.agentPasshphrase* is not provided, then the workers will use a random key and one must log into one of the *worker* pods in order to retrieve the value from */var/ossec/etc/authd.pass*.

In order to enable agent auto-enrollment using *X509* certificates, set *wazuh.authd.ssl_agent_ca_enabled* to *true*. This will automatically use the mounted TLS [secret](https://kubernetes.io/docs/reference/kubernetes-api/config-and-storage-resources/secret-v1/) cited [below](#TLS/SSL). Any agent presenting a certificate signed by the provided *rootCA.crt* will be accepted.

### Helm values.yaml overrides
| Yaml Path | default | Function |
|:--------- | ------- | -------- |
| wazuh.cluster.enabled | true | If *false* will only launch the manager pod with no environment variables|
| wazuh.authd.enabled| true | If *false* it disables the authd functionality on workers |
|wazuh.authd.agentPassphraseEnabled | false | If *true*, causes the workers and agent to use *authd.pass* file for auto-enrollment|
|wazuh.authd.agentPassphrase | \<undefined> | will mount file containing the provided passphrase into the *worker* and *agent* pods|
|wazuh.authd.ssl_agent_ca_enabled | false | if *true* will use the certificates provided by the mounted *release_name*-authd-certs.wazuh-authd-root-ca.pem secret to validate agent client certificates|

### TLS/SSL
Can be configured for each component by providing key/cert/cachain as an **Opaque** k8s [secret](https://kubernetes.io/docs/reference/kubernetes-api/config-and-storage-resources/secret-v1/).

Note, this installation **does not** generate any X509 certificates **for use with Wazuh** itself. The docker container generates self-signed certs for the **filebeat** component if they are not mounted.

The "data" portion of the secret always contains the PEM-encoded data for each as per this table:

| Component | Secret Name | Data Subpath | Mounts to |
| --------- |:-----------:|:------------:| ---------|
| API <sub>(Manager)</sub> | *release_name*-api-certs | wazuh-api-key.pem | /var/ossec/api/configuration/ssl/server.key |
| API <sub>(Manager)</sub> | *release_name*-api-certs | wazuh-api-cert.pem | /var/ossec/api/configuration/ssl/server.crt |
| API <sub>(Manager)</sub>| *release_name*-api-certs | wazuh-api-root-ca.pem | (not mounted but must be present) |
| AuthD <sub>(Worker)</sub>| *release_name*-authd-certs | wazuh-authd-key.pem | /var/ossec/etc/sslmanager.key |
| AuthD <sub>(Worker)</sub>| *release_name*-authd-certs | wazuh-authd-cert.pem | /var/ossec/etc/sslmanager.cert |
| AuthD <sub>(Worker)</sub>| *release_name*-authd-certs | wazuh-authd-root-ca.pem | /var/ossec/etc/rootCA.pem |
| AuthD <sub>(Agent)</sub>| *release_name*-agent-certs | wazuh-agent-key.pem | /var/ossec/etc/agent.key |
| AuthD <sub>(Agent)</sub>| *release_name*-agent-certs | wazuh-agent-cert.pem | /var/ossec/etc/agent.crt |
| AuthD <sub>(Agent)</sub>| *release_name*-agent-certs | wazuh-agent-root-ca.pem | /var/ossec/etc/rootCA.pem |
| Filebeat | *release_name*-filebeat-certs | filebeat-key.pem |  /etc/filebeat/certs/filebeat-key.pem |
| Filebeat | *release_name*-filebeat-certs | filebeat-cert.pem |  /etc/filebeat/certs/filebeat.pem |
| Filebeat| *release_name*-filebeat-certs | filebeat-root-ca.pem | /etc/filebeat/certs/root-ca.pem |

\* Note the mounted paths are the defaults or injected into the configuration by the docker container at runtime. These should not be changed without modifying the helm chart itself.



## TODO
- The Wazuh API service is not exposed with a k8s *service* or *ingress* at the moment. Kibana environment is required to be deployed on the same K8S cluster inside the same namespace in order to get the UI working.
- ES permissions for the Wazuh Filebeat user need to be implemented manually via the Kibana "management" UI.
- Fix the es_hosts to handle situations:
  - Only works right now as a YAML array of quoted strings
  - Provided as a "string" that is just the hostname (needs to quote and convert to JSON array)
  - Provided YAML array of unquoted strings
  - Provided JSON
- Test persistence of the various containers. Right now containers re-initialize completely each time they're rebooted


# Resource materials
https://medium.com/@ibrahim.ayadhi/hello-and-welcome-to-our-new-article-which-will-be-covering-the-alerting-part-in-our-socaas-136cf6258c49
https://github.com/karql/elastalert-kibana-plugin
