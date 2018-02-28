# Release 3.5.2

## Changes
* Linux footprint
  * Linux sensors now store their config files (`hcp` and `hcp_conf`) in the Current Working Directory.
  * Since all deployments in production already require to script of some form to start the sensor (systemd or others), this can be used to `cd /where/to/store/hcp/conf/` before executing the sensor, making it customizable.
* Linux sensor build
  * The Linux sensor is now build with dependency on glibc v2.5, which means it's now drop in compatible with older releases like CentOS 5 and RHEL5.
* Fixes to Windows autoruns parsing along with new tests.
* Cleanup (`-c`) now also removes the new `hcp_conf` file.
* Windows service changes.
  * Display name changed to `LimaCharlie`.
  * Description field added.
  * Set to restart the service on first (and only) failure.
* Sensor begins sending data faster after enrollment.
* Various small quality of life changes to the cloud components.