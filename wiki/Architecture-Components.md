# Architecture Components


## RPAL
Stands for Refraction Point Abstraction Library. It is a static library providing low level abstraction across
all supported operating systems. All other components are based on it. It provides an abstraction of
- Basic data types, gives you a common definition for things like 32 bit int etc.
- Standard (or not so much) libraries, smooths out common functions like strlen that should be standard but are not always.
- Common data structures, providing staples of programming like b-trees, blobs etc.

## RPCM
Stands for Refraction Point Common Messaging. It is a static library that provides a serializable and cross-platform
message structure in a similar way as protobuf, but with a nicer C interface and without enforced schema. Has a C and
a Python API.

The basics of RPCM are best explained by comparing it to JSON. A JSON dictionary becomes an RPCM Sequence, while a 
JSON list is an RPCM List. The RPCM List however is limited to containing elements of the same type and with the same
tag, in order to force cleaner structures of data. All elements in Sequences and Lists are typed and tagged. The types
are very straight forward and include the basics. The tags are defined globally in `/meta_headers/rp_hcp_tags.json`.
There is no schema, so unlike protobuf, you can embed Sequences and Lists in any way you want. Once serialized, the
tags are serialized as their integer value, so unlike JSON, having long tag names has no impact on actual data size. 
Once the data reaches the cloud, it gets transformed into actual JSON, so we lose typing and a few tags (in lists) which
makes processing that data much easier. Most sensor config files are in Python RPCM's DSL if you'd like to see some
human readable examples.

## HCP
Stands for Host Common Platform, it is the platform residing on disk on the endpoints. It is responsible for crypto,
comms and loading modules sent by the cloud. It doesn't really "do" anything else, it's the base platform that gives
us flexibility in what we actually want to deploy.

### HCP Module
The sensor is written in C. HCP (base platform) supports multiple modules, if you'd like to write your own
I suggest having a look at the rpHCP_TestModule in /sensor/executables/. Modules can be loaded in parallel
so you having your own module does not mean it replaces HSB necessariliy.

## HBS
Stands for the Host Based Sensor. It is the "security monitoring" part of Lima Charlie. It's a module loadable by
HCP, so it is tasked from the cloud and does not persist on the endpoints, making it easier to manage upgrades 
across the fleet.

### HBS Collector
Expanding on HBS is much easier. Have a look at /sensor/executables/rpHCP_HostBasedSensor/main.c at the top
where Collectors are defined. Addind your own collector is very well scoped and should provide you with
all the functionality you need for a security sensor.