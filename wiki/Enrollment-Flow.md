## Enrollment Flow

As of 3.4, enrollment is done differently. 

### Then and Now
We used to patch each installer with the relevant keys needed to communicate with cloud. This made signing the installers impossible as they would have had to be signed for every single deployment out there.

The new flow does not modify the installers, which means they can be signed. Signing the installers makes adding the certificate issuer to your whitelist or other security products much easier.

### New Scheme
Since we no longer patch the installers, we now need a way to provide the keys and bootstrap information necessary for enrollment, and doing so securely.

An *Installation Key* is now created for every Organization and available through the web ui. This key is more or less a string version of what we used to patch in the installers. It is long, but it's small enough to fit on the command line.

Deploying an installer therefore now requires a small additional step, which is to include `-d <InstallationKey>` (to enroll without installing the sensor) or `-i <InstallationKey>` (to install the sensor and enroll).

### Example Usage
#### Windows
To install the sensor and enroll perform the following action from the command line:

`.\hcp_windows_x64_release_3.4.exe -i <Installation Key>`

To remove a sensor but leave enrollment information

`.\C:\Windows\System32\rphcp,exe -c` 

To remove a  sensor and the enrollment information

`.\C:\Windows\System32\rphcp.exe -r` 

#### OSX
For OSX after you download the agent the following actions would be performed:

`chmod +x hcp_osx_x64_release_3.4`

`.\hcp_osx_x64_release_3.4 -i <Installation Key>`

If you receive an error displayed below, run the command previous command with sudo

`ERROR ++++++++ bin/macosx/10.12.6/x86_64/release/executables/rpHostCommonPlatformExe/main.c: 586 installService() 1504712574 - could not write service descriptor`


To remove the OSX agent and its identity file perform the following action:

`.\/usr/local/bin/rphcp -c`


#### Linux
Perform the following actions:

`chmod +x hcp_linux_x64_release_3.4
./hcp_linux_x64_release_3.4 -d <InstallationKey>`

You may see the following warnings which is normal upon first run:

`WARNING ====== bin/ubuntu/16.04/x86_64/release/lib/rpHostCommonPlatformLib/beacon.c: 666 thread_conn() 1504792052 - no c2 public key found, this is only ok if this is the first time the sensor is starting or in debugging.`

`WARNING ====== bin/ubuntu/16.04/x86_64/release/lib/rpHostCommonPlatformLib/beacon.c: 927 thread_conn() 1504792063 - cycling destination` 