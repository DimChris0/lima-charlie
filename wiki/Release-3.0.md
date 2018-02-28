# Release 3.0

## Features
* The main transport is now proper TLS over port 443 by default. This should play nicer with various proxies.
* New web UI. Now almost everything can be done via the web UI. No more key management, generating installers etc. Everything is available through the new UI.
* New upgrade for the sensor on disk, so this is the last manual upgrade you should have to do with sensors.
* Lots of bug fixes.

## Warning
* Because of the new transport (and new enrollment token), the new sensors are not backward compatible. To upgrade, on the hosts:
  * Delete the old identity file (Windows: c:\windows\system32\hcp.dat, OSX and Linux: /usr/local/hcp)
  * Download the new installer from your web ui
  * Run the new installer on the host
  * Reboot (or just restart the service)