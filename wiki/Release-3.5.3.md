# Release 3.5.3

## Changes
* Sensor SYNC events now have performance metrics.
  * PERCENT_CPU: CPU% used by the process.
  * MEMORY_USAGE: number of bytes of memory managed by LC directly.
  * MEMORY_SIZE: number of bytes of resident memory for the entire process.
* Web UI tweaks
  * Removed ADMIN_ORG from various panels where irrelevant.
* Various bug fixes.
* Appliance now generates self-signed TLS certificates for web ui.

## Upgrade Notes
* The ssl support in the web ui app requires `sudo pip install pyOpenSSL`.