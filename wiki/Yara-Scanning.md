## Modes

## How-To Enable Constant Scanning
1. Enable the Yara collector and the STARTING_UP event in the web UI's Sensor Configurations.
1. Load the [YaraUpdater](https://github.com/refractionPOINT/lc_cloud/blob/develop/beach/hcp/analytics/YaraUpdater.py) actor as part of a Patrol.

Because of limitations in the way the Yara API works, all Yara signatures must be bundled together before being run. To do this, a directory structure on disk is used to generate one signature set per platform. As seen on line 37 of the YaraUpdater.py file, the default directory for this is `/tmp/_yara_windows`.

In this rules directory, create a `windows`, `osx`, `linux` and `common` sub-directories. In each of those, create a `_all.yar` file. This file should `include` all the signatures you wish to be run on that particular platform.

Make sure this directory structure is available on all Beach nodes where the YaraUpdater is running.

You may also use remotely fetched rules. You can see a sample YaraUpdater config in an old version of the repository [here](https://github.com/refractionPOINT/lc_cloud/blob/d71fc9db1fc8e9c1508bc7fa22e8c0b5ae36b9a0/beach/sample_start.py#L530).

The YaraUpdater will compile the signature from this `_all.yar` file and will automatically task the signature set  with the hosts when the STARTING_UP event is received.

The update mechanism will be updated and streamlined at some point, reach out to us if you need it.