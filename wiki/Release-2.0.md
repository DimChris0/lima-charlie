# Release 2.0

## Features
* The sensor id scheme has been moved to a GUID-based format to enable better scaling for organizations wanting to manage multiple sub-orgs of sensors (like an MSS).
* Many many fixes.
* Kernel acquisition of network events on Windows.
* Moving the cloud components to a new submodule repo (lc_cloud).
* Disabling in-sensor stateful detects by default.
* Making the kernel acquisition delivery module more resilient.
* Adding installer functionality into the main HCP executable on macOS.

## Details
### Why the new IDs?
First, let's go over the new ID scheme briefly, in some ways it's very similar as the one in 1.X.

#### What is the new scheme
The new scheme is also a 5 tuple. The wildcard value is now "0" (zero) and not "FF" as it used to be.

The tuple is now:
<OrgId(OID)>.<InstallerId(IID)>.<SensorId(SID)>.<Platform>.<Architecture>

The OID, IID and SID are all UUIDs of the form 11111111-1111-1111-1111-111111111111. The platform and architecture are simple integers. The resulting 5 tuple is referred to as an Agent Id.

This means a full Agent Id could look something like:
df5cfb5d-781f-4ec4-aa08-1e04049f502a.279449cf-b899-440e-b90b-3018161b9d87.5e9c00ab-5dcc-4059-960c-bc214961e662.30000000.2

This quite a mouthfull, but don't worry since we only VERY rarely need to specify the entire 5 tuple. Let's split it up and analyze the components:
- *8OID: df5cfb5d-781f-4ec4-aa08-1e04049f502a**, this is just the Organization Id, this is the level at which sensors "roll up" and are grouped in.
- **IID: 279449cf-b899-440e-b90b-3018161b9d87**, this is the Installer Id, an identifier created at the time a sensor installer is built. This is useful to be able to attribute the origin of a sensor, and to blacklist/whitelist IIDs in the event an installer is leaked to a bad guy or leaked by mistake to something like VirusTotal (and security companies start trying to analyze the installer, running it and creating ghost sensors).
- **SID: 5e9c00ab-5dcc-4059-960c-bc214961e662**, this is a Sensor Id, it uniquely identifies this sensor. It is in theory enough alone to uniquely identify the sensor without the rest of the 5 tuple, but in some situations we want to refer to entire Organizations for example so we still need the near-full Agent Id.
- **Platform: 30000000**, this is as before the platform the sensor is running on. For full list see the [Wiki page](https://github.com/refractionpoint/limacharlie/wiki/Full-Installation-Guide#v20-and-later).
- **Architecture: 2**, this is the CPU architecture the sensor is running on, for definitions see Wiki page as above.

#### Why the UUIDs?
Moving to UUIDs has many desired effects.

Since UUIDs are close-to-random IDs generated, it means that they are generally not predictable and have an effectively-zero level of collision. This allows us to provision the IDs without the need to have a high level of centralized management, making scaling easier.

It makes the job of an attacker harder to predict Agent Ids, it makes the enrollment token safer and makes it easier to manage.

This scheme also makes it easier for someone to segment and manage multiple deployments of LC, like for a Managed Security Service for example.

#### Do I have to type it all?
In the main case where this new scheme would be a pain, the Command Line Interface, you actually don't need anything else than the SID unless you want to send a task to a wildcarded number of sensors. In fact, the CLI will accept both a 5 tuple OR a single UUID which it will assume is a SID.

So sensing a task to the Agent Id described above can be done either like this:

```
chid df5cfb5d-781f-4ec4-aa08-1e04049f502a.279449cf-b899-440e-b90b-3018161b9d87.5e9c00ab-5dcc-4059-960c-bc214961e662.30000000.2
```

or like this:

```
chid 5e9c00ab-5dcc-4059-960c-bc214961e662
```

or of course IID, Platform and Architecture wildcarded like this:

```
chid df5cfb5d-781f-4ec4-aa08-1e04049f502a.0.5e9c00ab-5dcc-4059-960c-bc214961e662.0.0
```