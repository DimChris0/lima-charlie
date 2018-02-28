# Troubleshooting

## Sensor is not starting

Sensor startup issues can be harder to troubleshoot. Here is how to investigate:

1. Run a 'debug' sensor. This will output verbose logs to stdout as well as OutputDebugString (on Windows, visible using [DebugView](https://technet.microsoft.com/en-us/sysinternals/debugview).

1. Check for the presence of the sensor id file and sensor crash-counter file. Their location depends on the platform and configuration (debug/release). The presence of the id file (hcp.dat and hcp_debug.dat) indicates the sensor started and was able to enroll successfully at least once. The absence of the hcpcc files (crash-counter) while the sensor is not running indicates the sensor shutdown cleanly.

  ```
  c:\windows\system32\hcp_debug.dat
  c:\windows\system32\hcp.dat
  c:\windows\system32\hcpcc_debug.dat
  c:\windows\system32\hcpcc.dat
  /etc/hcp
  hcpcc
  ```

1. This should give you hints as to the trouble. Unless it's obvious, contact LC users and developers with the logs on the [LC Google Group](https://groups.google.com/forum/#!forum/limacharlie).

## Sensor starts but returns no data
A few different stages need to be configured properly for the data to flow. Evaluate the configuration using the hcp admin cli. Start the cli interface, the paths below assume a default repo structure as provided by the cloud-in-a-can.

```
server@lc-server:~/$ cd ~/limacharlie/cloud/beach/hcp/
server@lc-server:~/limacharlie/cloud/beach/hcp$ sudo python ./admin_cli.py

        ====================
        RPHCP Interactive CLI
        (c) refractionPOINT 2015
        ====================
        
<NEED_LOGIN> %> login ../sample_cli.conf
Connected to node ops at: 192.168.1.63:4999
Interface to cloud set.
success, authenticated!
Successfully logged in.
Remote endpoint time: 1455990271.26.
*  /  %> 
```

The steps below are all commands to be typed in the admin_cli.py command line interface.

1. Confirm that an enrollment rule is present. This describes which sensor id to give to sensors which do not yet have global sensor ids. The rules can be configured with a lot of granularity, but in the case of a cloud-in-a-can it should look like this, indicating to enroll all sensors into the 1.1.*.*.* range.

  ```
   /  %> hcp_getEnrollmentRules
  <<<SUCCESS>>>
  { 'rules': ( { 'external_ip': '255.255.255.255',
                 'hostname': '',
                 'internal_ip': '255.255.255.255',
                 'mask': 'ff.ff.ffffffff.fff.ff',
                 'new_org': '0x1',
                 'new_subnet': '0x1'},)}
   /  %>
  ```

1. Confirm that the HBS sensor is in the cloud. Note that the hash value will vary per release and sensor configuration. You should see the HBS sensor for the platform you are trying to evaluate.

  ```
   /  %> hcp_getModules
  <<<SUCCESS>>>
  { 'modules': ( { 'description': 'hbs_osx_x64_debug_0.8',
                   'hash': '1ff4cfff7d0f63f896b0f1950fd16f83abacd2b016e0bee450c6de2d413dcdf1',
                   'module_id': 1},
                 { 'description': 'hbs_ubuntu_x64_debug_0.8',
                   'hash': 'ce972a2402e7b6588d989cef9a91770219b9459a7c0db55321327ecda389a30f',
                   'module_id': 1},
                 { 'description': 'hbs_win_x64_debug_0.8',
                   'hash': 'e0af7f0b150250b8060dde32d76ace2643aae38de50ce055fb992fa7d0340e9e',
                   'module_id': 1})}
  ```

1. Confirm the HBS sensors in the cloud are tasked to the sensor range you're using. The hashes in the tasking should match the hashes in the `hcp_getModules` command from above. The 'mask' value should match up the module's platform to the sensor id platform (First digit, 1=32bit, 2=64bit, Second digit, 1=Windows, 2=OSX, 3=Linux, Third digit, minor platform, 4=Ubuntu). See [Enrollment Rules](Full-Installation-Guide#add-enrollment-rule) for more details.

  ```
   /  %> hcp_getTaskings
  <<<SUCCESS>>>
  { 'taskings': ( { 'hash': 'e0af7f0b150250b8060dde32d76ace2643aae38de50ce055fb992fa7d0340e9e',
                    'mask': 'ff.ff.ffffffff.210.ff',
                    'module_id': 1},
                  { 'hash': '1ff4cfff7d0f63f896b0f1950fd16f83abacd2b016e0bee450c6de2d413dcdf1',
                    'mask': 'ff.ff.ffffffff.220.ff',
                    'module_id': 1},
                  { 'hash': 'ce972a2402e7b6588d989cef9a91770219b9459a7c0db55321327ecda389a30f',
                    'mask': 'ff.ff.ffffffff.254.ff',
                    'module_id': 1})}
  ```

1. Confirm a profile is set for HBS. A profile tells the sensor basic configuration information to be used at runtime like the initial list events to send back to the cloud or different timing values. If a profile is not set, the sensor will run fine but will not exfil any data back to the cloud. The profile can be a large JSON config so it is omitted below. Unless you've modified it yourself, the default checked in profile should be sane and exfil some data.

  ```
   /  %> hbs_getProfiles
  <<<SUCCESS>>>
  { 'profiles': ( ...........................
  ```

1. For guidance or questions on any of the steps or value, contact LC users and developers with the logs on the [LC Google Group](https://groups.google.com/forum/#!forum/limacharlie).