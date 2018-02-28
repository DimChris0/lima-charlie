## High Availability Schemes
For production deployments where multiple nodes are used, some patterns of Beach Actors (and Patrols) can provide variations of high availability.

### Basic Concept
By default, most Actors in Beach will automatically load balance traffic over all instances of the peer Actors in the cluster (with some exceptions that require affinity for part of the traffic).

Therefore, by spreading (at least) one instance of each Actor category evenly over the cluster nodes will evenly spread the load.

The secondary benefit of this is that if one of the nodes (or Actors) goes down, after a retry period (usually a few seconds), the Actor issuing the request will send the same request to the next available Actor. This means no data is lost and traffic gets routed "around" the dead nodes/Actors.

This does of course have a small negative impact on performance as it increases inter-node traffic. But being able to stay running while losing a node, or while doing a rolling Actor upgrade (`stop_actor -c actor_category --delay 60` in the Beach CLI for example) is worth it.

### Mechanism
In order to achieve the behavior above, one Patrol parameter and one Actor argument can be used:
* `initialInstances`: this is the number of instances of the specific Actor the Patrol will start in the cluster.
* `strategy`: this will tell Beach how to prioritize where to start the Actor within the cluster.

To start one instance of the Actor on each node of the cluster, use an `initialInstances` of N, where N is the number of nodes in the cluster, and a `strategy` of `'repulsion'`, which tells Beach to try not to load two instances on the same node.

### Examples
A programmatic example of this strategy is visible in the [appliance patrol file](https://github.com/refractionPOINT/lc_cloud/blob/develop/beach/appliance_lc_patrol.py). 

At the top of the Patrol, we define `SCALE_DB` dynamically from a simple file on disk that describes all the nodes in the cluster. (In the appliance, scripts ensure a structure and base configuration for all the nodes so this is streamlined.)

Then, all Actors defined below it use `len( SCALE_DB )` as number of `initialInstances` and `'repulsion'` as a strategy. This ensures that as nodes are added to the cluster, the `initialInstances` grows and the Patrol spreads the load evenly.

### Complex Schemes
Beach offers many other ways of scaling and adjusting the "shape" (number of Actors and locations) of the cluster. Combined with the fact that Beach nodes operate in a peer to peer fashion (so it does not require all nodes to be specify all other nodes in the config file), this means one can even automate schemes where Beach nodes are added and removed dynamically at different times to cope with added load.

Another way to automate part of the scaling is using the `scalingFactor` parameter in a Patrol. This parameter indicates that a single instance of the Actor can usually "satisfy" a scaling metric of X. This metric is somewhat arbitrary but it is often useful to think of it in terms of hosts connecting to your cluster. A `scalingFactor` of 100 would therefore mean that a single instance of the Actor can handle the load of about 100 hosts.

The other part of the scaling factor equation is how the effective current factor is calculated. At the moment this current scaling factor is set by a command line argument to the Patrol (like [this](https://github.com/refractionPOINT/lc_cloud/blob/develop/infrastructure/appliance/start_ui.py#L38)). By setting the `--set-scale X` argument, we tell the Patrol to instantiate as many Actors as necessary to handle the load from X hosts connecting, according to each Actor's `scalingFactor`.

In production scenarios it means you could use this (after profiling the normal load on the cluster per Actor) by stopping the Patrol and relaunching it with a new `--set-scale X` value in parallel to adding new cluster nodes.

In some future version of Beach and LC, this scaling equation will become more automated.


