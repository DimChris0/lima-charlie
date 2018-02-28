## LC Appliance

The LC appliance is an OVA available for download [here](https://goo.gl/x7GNS3).
The appliance is designed to run on its own, but can also be expanded to form a cluster with other LC appliances. It is now the main supported deployment methodology.

### Hardware
The recommended hardware is at a minimum for production use, although you can probably get away with less:
* 4 CPU Cores
* 8 GB of RAM
* 20 GB main disk, 500 GB disk for Cassandra storage
* 1 Network card

### OS
* Current OS is Ubuntu Server 64bit 16.04.
* Default username is `server`.
* Default password is `letmein`.
* SSH is enabled on port 22.

### First installation
The first (or only if you're not looking at a cluster) appliance you download, use the following procedure:
1. `sudo ./init_cluster.py`: This will initialize the Cassandra database and other settings.
1. `./start_node.py`: This will start the Beach (compute platform used by LC).
1. `./start_ui.py`: This will start all the various components of the LC backend including the web ui.
1. Wait a minute for everything to start.
1. You can now login to the web ui with HTTPS on port 8888 of the appliance.
1. Login to the appliance with user `admin@limacharlie` and password `letmein` and no second factor. From there you can create your first organization and install sensors.

Port 8080 provides access to the web dashboard for Beach. Logs are in `/var/log/syslog`.

You can stop and start the appliance using the `./stop_node.py` and `./start_node.py` scripts.

### Adding Appliances to the Cluster
If you need to expand the capacity / high availability of your LC deployment without increasing the hardware of your first node, you can add a second (and more) appliance and cluster it.

The appliances require network connectivity to work together (obviously), so you will want to consider that for your firewall policies.

For the new appliance, the procedure should be:
1. `./join_cluster.py --address <ipOfTheFirstNode>`: The "ipOfTheFirstNode" is the IP address (or hostname if you've set all that up) of the first (or other) node of the cluster. You can repeat the `--address <ip>` parameter for as many previous nodes of the cluster you had.
1. `./start_node.py`: Starts the Beach component on the new node.
1. You may want to do a `./join_cluster.py` on the other nodes with all the IP addresses now in the cluster, although this is not required.
1. Issue a `./stop_node.py` and `./start_node.py` on the other nodes will ensure a good rebalancing of the cluster.

***Important note***: only do a `./start_ui.py` on one node, the node you want to access the web ui from.

*What's going on here?* Simple, the `./join_cluster.py` sets up "seeds" for Beach and Cassandra. "Seeds" are nodes that are used as well known points of contact for Cassandra and Beach. When a new Cassandra or Beach node starts, it contacts those "seeds" and gets a list of all nodes in the cluster (peer to peer). This means as long as you have one common seed, and that seed is up and running, all other nodes will discover each other. This is why it's good to do a `./join_cluster.py` on all nodes, it sets all nodes as seeds and therefore reduces the likeliness of a node in the cluster won't find the rest of the cluster.