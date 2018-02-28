## Types of hosts
The full deployment (not Cloud in a Can) requires the following roles. More than one role can be on the same host (as in the Cloud in a Can where they're all on the same host).

1. Cassandra: this is a normal Cassandra cluster. There are lots of guides available online on managing these clusters so info here is kept to a minimum.
1. Beach: Beach is similar in concept to Cassandra, where it exposes a pool of hosts (cluster) to load Actors (micro-services) in a load balanced way.
1. Proxy: this is the simple TLS endpoint where sensors will connect to. A deployment can have more than one proxy, for example by doing DNS based load balancing. All proxies will connect to the Beach cluster where the heavy lifting is done. Therefore proxies are very lightweight.
1. Dashboard and management: this is a collection of a few things. They are all effectively some type of "client" infrastructure that needs to connect to the Beach cluster. Therefore it's common to have all of these running on another host.
  1. Beach has a dashboard to help monitor the state of the cluster.
  1. LimaCharlie has a web ui that needs to be hosted somewhere, it's the main interface into LC.
  1. The Beach Patrol (essentially a script that specifies which Actors need to be loaded and makes sure they maintain availability if an Actor goes down).

We will go into details of how to deploy each of those.

## Install Cassandra
As stated before, there is lots of documentation out there, for example: http://docs.datastax.com/en/landing_page/doc/landing_page/planning/planningAbout.html

Here is a simple way to install (with no customizations):
```
sudo apt-get install default-jre-headless -y
echo "deb http://www.apache.org/dist/cassandra/debian 310x main" | sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
curl https://www.apache.org/dist/cassandra/KEYS | sudo apt-key add -
sudo apt-get update -y
sudo apt-get install cassandra -y
```

The Cassandra cluster needs to be accessible from all Beach nodes in a LimaCharlie deployment.

## Load the Cassandra LC Schema
With Cassandra up and running, execute the LC Cassandra schema like this: `cqlsh -f lc_cloud/schema/scale_db.cql` or by launching `cqlsh` in interactive mode and pasting the contents of `scale_db.cql`.

## Install Beach
Beach is a P2P system, so all Beach nodes need access to other nodes. The Beach config will maintain a small list of "seed" nodes which will be used to start the P2P discovery process. A minimal hardware of 1CPU+1GB of RAM is recommended.

### Beach Package
Installation instructions for the Beach are [here](https://github.com/refractionPOINT/py-beach/wiki#creating-a-new-node). Beach will have to be installed on all hosts that need to access the Beach cluster, the package includes software for both clients and servers.

### Beach Nodes Packages
The main platform Beach is tested on is Ubuntu Server LTS, although other platforms like CentOS will work with minimal tweaks.

TODO: There is currently no mechanism in Beach to setup a systemd or upstart script to start the Beach node code at startup. Happily taking contributions.

In addition to installing Beach itself, your Beach nodes will require a few more packages to run the LC backend:
```
sudo apt-get install openssl python-dev debconf-utils python-pexpect unzip
sudo pip install markdown time_uuid cassandra-driver virustotal ipaddress tld pyqrcode pypng slacker slackclient python-dateutil
```

Finally, in order to use the Yara functionality in LC, you'll want to install the version of Yara supported by the sensors which is pinned by our fork of the Yara repo:
```
echo Building and installing the Yara lib.
git clone https://github.com/refractionPOINT/yara.git
cd yara
./bootstrap.sh
./configure --without-crypto
make
sudo make install

echo Building and installing the Yara Python bindings.
git clone https://github.com/refractionPOINT/yara-python.git
cd yara-python
python setup.py build
sudo python setup.py install
sudo echo "/usr/local/lib" >> /etc/ld.so.conf
sudo ldconfig
```

### LC Beach Code
All the code that the Beach cluster will run is in the form of Actors. These Actors must be accessible by all Beach nodes. This means you need to setup some mechanism to expose the code, the main options are:
1. Sync the code via `scp`, `ansible` or something like that locally to every Beach node. PRO: Simple and always local, CON: You need to issue a sync every time you make a change to the code.
1. `NFS` or `SMB` shared directory. PRO: Always in sync, CON: a bit more setup to ensure the directory get mounted every time.
1. `HTTP(S)` server, Beach can load all code via any URL handlers like `http://`, therefore if you setup an `HTTP(S)` server, Beach can fetch its code there at runtime. PRO: Always in sync, CON: Need to setup a web server which could also expose the Beach code to others. Note: if you always want to be up to date, you could use this with the github official repository over HTTPS.

Whichever method you chose, you will want to mount/copy the `/beach` directory of the [lc_cloud repo](https://github.com/refractionPOINT/lc_cloud/tree/master/beach).

Starting the Beach node (`python -m beach.hostmanager myBeachConfigFile.conf`) requires a config file. Unless you opted for the `HTTP(S)` method above, you can use/modify the [lc_local.yaml](https://github.com/refractionPOINT/lc_cloud/blob/master/beach/lc_local.yaml) config file provided.

In that config file, you will want to change the `seed_nodes` section to add seed (more permanent or good bootstrap) nodes. You may also want to add a [private key](https://github.com/refractionPOINT/py-beach/wiki#encrypted-node-comms) to use as a symmetric encryption key for the communications inter-beach-node. You will have to first generate a key and set the `private_key` value in your Beach config file with the path to your new key (as described in the link above).

### Beach Node Networking
* All Beach nodes need to be able to talk to each other.
* All Beach nodes need to be able to talk to the nodes of the Cassandra cluster.
* All Beach nodes need to be able to reach out to the internet by default (fetching new versions of Sensor Packs, Alexa and other rulesets).
* All Beach nodes need to be accessible to the Proxy and Dashboards.

## Proxy
The Proxy nodes are very simple. They receive sensor communications over port 443 (by default) and relay them to the relevant Actors in the Beach cluster. 

You need to install the Beach package (as per instructions above). You will also need to copy locally the [endpoint_proxy.py](https://github.com/refractionPOINT/lc_cloud/blob/master/standalone/endpoint_proxy.py) and Beach config files.

Since a Proxy is very lightweight, this can be a very small machine (1 CPU + 512 MB of RAM).

The Proxy is launched to listen on port 9090 like so:
`python /path/to/endpoint_proxy.py -c /path/to/myBeach.conf -l 0.0.0.0:9090`

### Proxy Networking
* Needs to accept connections from port 443 from the internet.
* Needs to be able to reach all Beach nodes.
* By default the Proxy listens on port 9090 locally (to be unprivileged) so you will have to redirect port 443 to 9090 like so:
  ```
  sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 9090
  sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 9090
  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
  sudo apt-get install iptables-persistent -y
  ```

## Dashboards
You need to install the Beach package (as per instructions above). All dashboards are built with `web.py`, which should be installed by Beach.

The following packages are also required:
`sudo pip install markdown ipaddress pyqrcode pypng python-dateutil`

The Beach dashboard only requires the Beach config file and can be launched on port 8080 like so:
`python -m beach.dashboard 8080 /path/to/myBeach.conf`

Starting the Beach REST bridge is also simple, but only recommended if you need it:
`python -m beach.restbridge 8889 /path/to/myBeach.conf hcp`

### Dashboard Networking
* Needs to be able to reach all Beach nodes.
* Needs to be able to accept connections (to the relevant port) from wherever you intend to access them (highly discouraged to be exposed to the wide internet).

## LC Web UI
You need to install the Beach package (as per instructions above). All dashboards are built with `web.py`, which should be installed by Beach.

The following packages are also required:
`sudo pip install markdown ipaddress pyqrcode pypng python-dateutil`

The LC Web UI requires the [limacharlie](https://github.com/refractionPOINT/lc_cloud/tree/master/limacharlie) directory from the `lc_cloud` repository. It also requires the contents of [hcp/utils](https://github.com/refractionPOINT/lc_cloud/tree/master/beach/hcp/utils) directory within the `limacharlie` directory. It is therefore common to simply:
```
git clone https://github.com/refractionPOINT/lc_cloud.git
ln -s lc_cloud/beach/hcp/utils/* lc_cloud/limacharlie
```
It also assumes that the Beach config file is in `lc_cloud/limacharlie/beach.conf`.

The LC Web UI can be started simply on port 8888:
`python lc_cloud/limacharlie/app.py 8888`
or as a uwsgi module something like this `uwsgi --socket 127.0.0.1:9000 --wsgi-file /lc_cloud/limacharlie/app.py --gevent 1000 --gevent-monkey-patch`

### LC Web UI Networking
* Needs to be able to reach all Beach nodes.
* Needs to be able to accept connections (to the relevant port) from wherever you intend to access them (discouraged to be exposed to the wide internet).

## Patrol
The Patrol is a [script](https://github.com/refractionPOINT/lc_cloud/blob/master/beach/core_lc_patrol.py) written as a Python Domain Specific Language and is interpreted by Beach. It describes all the Actors that need to be loaded, the number that need to be loaded as well as the various configuration arguments for each Actor.

You need to install the Beach package (as per instructions above).

Patrols are started like:
`python -m beach.patrol /path/to/myBeach.conf /path/to/core_lc_patrol.py --realm hcp --set-scale 10`

This means you will need your Beach config file as well as a Patrol file. You should use the [following Patrol file](https://github.com/refractionPOINT/lc_cloud/blob/master/beach/core_lc_patrol.py) as the basis for your own.

You will want to change the `SCALE_DB` value defined at the top of the Patrol file. It should be set to domain names or IPs of the Cassandra seed nodes you would like the relevant Actors to use when connecting to Cassandra.

Also check if you need to change the interface you want the `EndpointProcessor` to listen on for connections. It should be set to whatever your main network is and where it will get connections from the `endpoint_proxy`.

### Patrol Networking
* Needs to be able to reach all Beach nodes.

## Starting the Backend
Once all the nodes have been installed and configured as per above you will want to start the backend. By doing this, you should find yourself at the same point as having started a [Cloud in a Can](https://github.com/refractionpoint/limacharlie/wiki/Installing-Cloud-in-a-Can). New keys will be generated as well as an ADMIN_ORG created with the default user `admin@limacharlie` with password `letmein`.

1. Ensure that all Beach nodes are started, you can observe their logs in `/var/log/syslog`.
  1. Make sure you're not getting errors.
  1. You should see a log message indicating that each node has discovered the other nodes.
1. Start your Patrol file, again logs should be in `/var/log/syslog`, you should see messages indicating the various Actors are getting started.
1. Start your LC Web UI and dashboards.
1. Login to the LC Web UI and change password/2-factor.

If you want to narrowly test a specific Actor, you can issue a specific RPC to an Actor via the beach_cli like this:
```
python -m beach.beach_cli beach.conf \
    --req-realm hcp \
    --req-cat c2/sensordir \
    --req-cmd get_dir \
    --req-ident lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903 \
    --req-data '{ "aid" : "a32fdfd3-24ef-4057-803f-c5189f21bbde" }'
```