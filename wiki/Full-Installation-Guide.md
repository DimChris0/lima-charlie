# Installation Guide

The process of installing a LC cloud is non trivial, which is why we recommend first starting and evaluating LC using a [Cloud-in-a-Can](Installing-Cloud-in-a-can) as it's much easier. However, the Cloud-in-a-Can is not a secure and long-term solution since it creates the entirety of the LC infrastructure on a single node, which does not make use of the horizontal scaling technologies allowing it to scale to large deployments.

The following is a discussion of the main topic and process for setting up the infrastructure. Obviously the exact setup will need adaptation to your environment.

## Generating Keys (DEPRECATED)
***Deprecated: when the LC backend starts, it will now generate its own keys internally. Use this section only if you intend on keeping some keys offline or want higher level of control somehow).***

First step, although not as exciting is generating new keys. Now, test keys are included in the repo so you don't
**have** to do it, but unless it's a truly temporary test running on a test VM I'd **strongly** recommend using 
your own keys. If you use the test keys, remember that anyone can decrypt, task and intercept your sensors.

To generate a new key set (we use RSA 2048) from the root of the repo:

```
cd tools
python ./generate_key.py <keyName>
```

That will create a private and public key in a few different formats (but all the same key pair).

You need to generate 3 such key pairs:
- HCP: this pair is used to sign the modules we will load on the platform, in our case this will be HBS.
- C2: this is a least-privileged pair used to secure the link between the Command & Control for LC and the sensors.
- HBS: this is a pair used to sign the tasking we send to the HBS sensor.

The security of the HCP and HBS keys is critical as they could allow an attacker to "do stuff" to your sensors. The
C2 key on the other hand is not as critical since it allows only very basic "keeping the lights on" functionality
to the sensor. This is done on purpose. The entire LC model is done such that you could keep the critical keys
(HCP and HBS) in an air-gap and still be able to run LC.

Last step is to encrypt the HBS key. This will allow you to use the key in the LC Shell, which needs a key with
a password for added safety (since you use the HBS key more often and are less likely to completely air-gap it).

```
cd tools
./encrypt_key.sh <hbsPrivateKeyDer> <outHbsPrivateKeyEnc>
```

Now you're done, copy all the keys somewhere safe. Once we have our cloud running you will need the *C2 key public pem*
on your cloud and will reference to it from an Actor you start, we'll explain later.

## Installing Backend

### Beach Cluster
The cloud runs on a Beach cluster. Beach is Python based which makes development of all the analytics easier and
the Beach cluster can be expanded at runtime (it's peer-to-peer) which makes growing your deployment easier in the
future. So as not to duplicate doc, check out the *Basic Usage* section here: https://github.com/refractionPOINT/py-beach/

A one-node cluster is perfectly fine to do the testing of LC.

Copy the LC repo (whole repo is easier, but really it's the *cloud/beach* directory you need) to your Beach cluster. This
can be done manually, through a NFS-mounted directory or a config management system like Salt, Chef etc...

Point your Beach cluster config's data directory to the *cloud/beach* directory of the repo. Alternatively, use 
the sample Beach config found in the *cloud/beach* directory in the repo, it should have all the relative directories
pointed correctly. The *realm* we will use in the Beach cluster is called *hcp*, but you don't really need to know
that for now.

On each node of the Beach cluster, install the required packages. The canonical packages that are required can be found in the ```cloud/infrastructure/install_cloud_in_a_can.py``` file.

Note that you may need to bump up the maximum number of open file descriptors depending on your system configuration.

### Scale DB
The scale-db is a Cassandra cluster (again, one-node cluster for testing is fine). Cassandra will provide you with
highly-scalable storage, which is something you will need in order to run some of the analytics (especially Objects)
on a any real deployment. As with the state-db, just [install Cassandra 3.10+](http://cassandra.apache.org/download/) somewhere reachable to the Beach cluster and
create the schema found here:
```
cloud/schema/scale_db.cql
```

## Configuring Backend

### Set the Keys (DEPRECATED, see Generating keys for explanation)
Using the keys you generated earlier, copy the C2 public pem key to the cloud/beach/hcp/ directory on the Beach 
cluster and make sure the key name matches the name given in the parameters of the BeaconProcess Actor. In the
sample_start.py the default name is c2.priv.pem.

### Start the Actors
Now that we have all the raw components required ready, let's load the code onto the cluster.

To load the Actors that form the backend needed for LC, run the patrol script from a location having
access to the beach cluster (or from a node itself).

```
cd cloud/beach
python ./core_lc_patrol.py
```

The patrol script contains documentation about which Actor does what, which will allow you to customize
the composition of your production cloud infra for LC (if you need). In its current form, the script will
start one Actor of each required Actor for LC to work, including analytics. To also load detections, launch full_lc_patrol.py instead.

### Add Enrollment Rule
***Enrollment rules are now generated for you by the web ui. You can still control them manually from the CLI but unless you're certain of the requirement, don't do it.***
Now we want to add an enrollment rule. Because LC was designed to be able to cope with the challenges
of large organizations, we need to set a rule that describes what sensor id range a new sensor reporting in should
be associated to. 
#### Prior to v2.0
Sensor ids are a 5-tuple and have the following structure:
- Org Id (1 byte): allows a cloud to house multiple organizations
- Subnet Id (1 byte): further segmentation within an org
- Unique Id (4 bytes): this is a one-up number for each new sensor within the subnet
- Platform Id (1 byte split in 3 fields):
  - CPU Arch (2 bits)
    - 0 : reserved
    - 1 : 32 bit x86
    - 2 : 64 bit x64
    - 3 : mask value
  - Major version (3 bits):
    - 0 : reserved
    - 1 : Windows
    - 2 : OS X
    - 3 : IOS
    - 4 : Android
    - 5 : Linux
    - 6 : reserved
    - 7 : mask value
  - Minor version (3 bits): depends on the major, 7 is mask value
- Config Id (1 byte): runtime specifiable value, often ignored other than for specific deployment scenarios 

Sensor ids support masking, which means that the following expression represents all Windows 64 bit regarless
of organization and subnet: ff.ff.ffffffff.21f.ff

So for this simple testing, we'll create a rule that says "enroll all sensors into the same range, org=1 subnet=1".

#### v2.0 and later
Agent ids are a 5-tuple and have the following structure:
- Org Id (OID): a UUID representing the organization this sensor belongs to
- Installer Id (IID): a UUID representing the installer binary that was used to install the sensor (this can be used to whitelist installers that can enroll, or blacklist an installer leaked to VirusTotal for example)
- Sensor Id (SID): a UUID representing the sensor uniquely
- Platform: a hex integer representing the platform the sensor runs on where:
  - Windows = 0x10000000
  - Linux = 0x20000000
  - macOS = 0x30000000
  - iOS = 0x40000000
  - Android = 0x50000000
- Architecture: a hex integer representing the CPU architecture the sensor runs on where:
  - x86: 0x01
  - x64: 0x02

Each component of the AgentId can be masked at various points by simply setting the component to 0 as a wildcard value.

First, to interact with the cloud, we will start the LC Shell. Start by configuring a shell config file, for this
you can use the one in *cloud/beach/sample_cli.conf*. If you need, edit it and make the *beach_config* parameter
point to your Beach cluster config file, it's the only parameter required for the moment. Eventually we will
configure different access tokens in that config file, so you can think of it as a per-operator config file.

Now that this is ready, start the shell:
```
python cloud/beach/hcp/admin_cli.py
```

Log in to the cloud with the cli config file from a paragraph ago.
```
login cloud/beach/sample_cli.conf
```

It should tell you you've successfully logged in. This shell supports the '?' command and you can give commands the
'-h' flag to get a more detailed help. If you check out the '-h' for the 'login' command, you'll see it supports
the '-k keyFile' parameter. If you login without '-k', you can issue commands to the cloud and manage it, but you
cannot issue commands to the actual sensors. By loading the key (HBS private key you encrypted earlier), you can 
start issuing commands directly to sensors. When a key is loaded, a star will be displayed to the left in the CLI.

Back to the enrollment, add the following rule (this rule is for < v2.0, change to the relevant UUIDs for > v2.0):
```
hcp_addEnrollmentRule -m ff.ff.ffffffff.fff.ff -o 1 -s 1
hcp_getEnrollmentRules
```

Done, now new sensors coming in will get officially enrolled.

### Add Profile
***DEPRECATED: Profiles are also now generated for you by the web ui. You can still control this way but it's not recommended unless you're certain of your requirement.***
A Profile is a configuration for sensors, where we can configure the events exfiled and many other things. For
sensors to bring back anything, we must give them a profile, so let's add one, like the enrollment rule, for
every sensor we deal with. Notice that the Profile applies to the security sensor (HBS) and therefore the command
starts with *hbs_*. (This example is for a < v2.0 sensor id, change to the relevant UUIDs for > v2.0)

```
hbs_addProfile -m ff.ff.ffffffff.fff.ff -f cloud/beach/production_hbs.profile
```

## Generating Installers
***DEPRECATED: the web ui now takes care of generating all your sensors. You can still do the below if you're certain of your requirements.***
Great, the cloud is done, now we need to prepare installers for sensors. You can compile your own sensors if you'd
like, but we also release binary versions of vanilla sensor at major releases. The general procedure is to compile
a sensor (or download an official release), and then you patch it with a config so it uses your keys and settings.
If you don't patch it, the sensor will remain a "dev" sensor and will use demo keys and connect to a local cloud.
 
To create your own sensor config, see *sensor/sample_configs/*.
For now, we'll use the *sensor/sample_configs/sample_hcp_sensor.conf*. Before we patch, edit the *sample_hcp_sensor.conf* and change the *C2_PUBLIC_KEY* and 
*ROOT_PUBLIC_KEY* to the path to your C2 public key and HCP public key.
 
So to apply (patch) a sensor config, we use *sensor/scripts/set_sensor_config.py*:
```
python set_sensor_config.py <configFile> <sensorExecutable>
```

The executable is now patched, it's got your keys and is ready to execute.

## Running Installers (DEPRECATED)
NSIS installers are included in the repository but have yet to be revamped and therefore your mileage may vary.
For the moment your best bet is running the sensors manually as standalone executables with root privileges.

Since no component is installed permanently by LC (other than a tiny config file), distributing and running
the standalone versions of the HCP sensor is not problematic. HCP should not change (or very rarely) and HBS
can be updated from the cloud transparently. On Windows deploying HCP via Microsoft GPO is generally a good way
of mass deploying and undeploying HCP easily.

On Windows, the main hcp executable supports some command line parameters to install LC as a Service (-i).

## Confirm Sensors are Running
The sensor when launched as a service or executable does not fork so a simple "ps" should tell you if it's running.
On the Beach cluster, you should see activity in the syslog.
Finally, by pointing your browser to the LC dashboard, you should now see your sensors connecting in.

## Patch, Sign, Load and Task HBS
So now we have HCP sensors coming back to our cloud, but we're not pushing any actual sensors to them (HBS).
To remedy that, we'll prepare an HBS sensor and then task it to our sensors.

The patching process is the same as for HCP, except that in this case you want to patch it with a different set
of configs, mainly with a root HBS key which is used to send cloud events back to the sensor. Those events being
sent back down need to be signed with this key. So go ahead and use `set_sensor_config.py sample_hbs_sensor.conf 
<hbsBinary>`.

Now that HBS has the config we want, we need to sign it with the root HCP key we generated. To do this, use
```
python tools/signing.py -k rootHcpKey.der -f path/to/hbs/binary -o path/to/hbs/binary.sig
```

This generates a .sig file wich contains the signature of the HBS module by the root HCP key, and thus allows it
to be loaded by HCP.

Next we'll task the HBS sensor to HCP. This is done in two steps through the `admin_cli.py`, first we upload the
HBS module:
```
hcp_addModule -i 1 -b path/to/hbs/binary -s path/to/hbs/binary.sig -d "this is a test hbs"
```

note the hash string given as identifier for the module you just uploaded, it's just the sha-1 of the HBS module file.
Then we'll actually task the module we uploaded to the right sensors, in this case to every sensor (This example is for a < v2.0 sensor id, change to the relevant UUIDs for > v2.0):
```
hcp_addTasking -i 1 -m ff.ff.ffffffff.fff.ff -s hashOfTheModuleUploaded
```

From this point on, when the sensor contacts the cloud, the cloud will instruct it to load this HBS module.