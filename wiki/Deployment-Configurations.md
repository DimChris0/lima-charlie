# Deployment Configurations
This section describes which configurations need to be changed for a new deployment. It does NOT cover infrastructure configuration (like Cassandra), only LC-specific configurations.

## HCP Config
The HCP config defines specific information that gets patched in to your HCP binary which you can then deploy. It is strongly suggested to start from the `sensor/sample_configs/sample_hcp_sensor.conf` file. Once satisfied with your config you can patch it on the pre-built binaries using `sensor/scripts/set_sensor_config.py`.

### Callback Domains
You can define a primary and secondary (used as backup when primary domain fails). These can also be IPs although to limit the impact of moving infrastructure it's recommended to use DNS names.

### Crypto Keys
Generate and point to your these generated crypto keys, for more details see the [Crypto Discussion](Crypto-Discussion) and [Generating Keys](Full-Installation-Guide#generating-keys).

### Deployment Key
The deployment key is an ascii string that is sent along in the headers of every comms to the cloud. If the mirror setting `deployment_key` is set in the `EndpointProcessor` Actor, the early process of validating the data in the beacon will make sure the expected deployment key is set. This allows you to filter out sensors that may be unrelated to your deployment from talking to your cloud and polluting the data set. Therefore you should not publicize your deployment key (though it's not exactly a "secret" since it can be found in every HCP sensor you deploy).

## HBS Config
The HCP config defines specific information that gets patched in to your HBS binary which you can then deploy. It is strongly suggested to start from the `sensor/sample_configs/sample_hbs_sensor.conf` file. Once satisfied with your config you can patch it on the pre-built binaries using `sensor/scripts/set_sensor_config.py`.

### Crypto Key
At the moment the crypto key is the only real configuration (other than profiles) which you need to configure the HBS binary with. It is the key used to task HBS. Generate and point to your the generated crypto key, for more details see the [Crypto Discussion](Crypto-Discussion) and [Generating Keys](Full-Installation-Guide#generating-keys).

## Firewalls
By default, Beach and Cassandra do not enforce strong auth which makes it critical to ensure you have good segmentation. Here are some tips to get your policies started:

Deny by default, allow:
* All: NTP out, DNS out, SSH in.
* Cassandra: all from Beach nodes in.
* Beach nodes: all to Cassandra nodes out.
* Beach nodes: all to and from Beach nodes.
* Beach nodes: HTTP/S to internet out.
* Proxy: 443 in, all to Beach nodes.
* Misc (dashboards etc): all to Beach nodes.