# Release 3.4

## Changes
* Installers are now static and global. This enables us to sign every release (Mac and Windows).
  * Installers no longer get patched when creating a new organization.
  * To run the installer, you now require an Installation Key, available through the web UI.
  * Provide this key with `-i InstallationKey` on Mac and Windows (Installs + Enrolls), or `-d InstallationKey` on Linux (installation step is still up to you, the `-d` will only allow it to enroll).
  * The InstallationKey contains public encryption key as well as the URL of your LC backend so the sensor can enroll.
  * Similarly to before, if someone gets a hold of your InstallationKey, you can "re-generate" the sensors which will render the old key invalid and provide new with a new valid one.
  * This means you can now add the cert we use to sign to whatever security / whitelisting systems you have as a trusted cert.
  * Discussion [here](https://github.com/refractionPOINT/limacharlie/wiki/Enrollment-Flow).
* Appliance (!)
  * An LC appliance is now available for download.
  * Supports easy single-node deployment.
  * Supports easy multi-node clustered deployment (!).
  * Now the main supported deployment method.
  * Details [here](https://github.com/refractionPOINT/limacharlie/wiki/LC-Appliance).
* Beach Actor respawning.
  * Python is not great at garbage collection due to its lack of compaction. This means heavy throughput of some Actors on Beach leads to memory bloat.
  * Beach now will begin cleanly respawning Actors that report as "drainable" (opt-in) to reset their memory usage.
  * This does not result in loss of service or data as long as you're running more than 1 instance per drainable Actor (highly recommended and standard).
  * All this happens when a high memory waterline is reached of 80% of the Beach node's memory used.
* Uninstall-Clean
  * A new command line parameter for Windows and Mac (`-c`) will do a clean uninstall. In addition to removing the executable binaries and service (`-r`), will also remove the identity file of the sensor. Warning: doing this will lose the identity of the sensor and a reinstall will not restore it.
* ONGOING_IDENT event.
  * This new event is not sent back by default.
  * Every time a CODE_IDENT is not generated because the piece of code has been seen in the past, a smaller ONGOING_IDENT event is generated that includes the hash of the code in question.

## Schema Update
```
use hcp_analytics;
CREATE TABLE hcp_whitelist(
  oid uuid,
  iid uuid,
  bootstrap varchar,
  created timestamp,
  PRIMARY KEY( oid, iid )
) WITH compaction = { 'class' : 'SizeTieredCompactionStrategy' } AND gc_grace_seconds = 86400;
```

## Web UI Update
The `/cloud/limacharlie/app.py` web UI now expects the directory `/cloud/beach/hcp/utils` itself to be symlinked in `/cloud/limacharlie/` and not just its contents. This is to make future additional utils ported there automatically. You can use `ln -s .../cloud/beach/utils .../cloud/limacharlie/`.