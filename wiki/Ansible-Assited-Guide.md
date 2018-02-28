# Warning
**This install process has not been tested in v1.0 and may be a bit out of date.**

# Ansible Assisted Guide

LC now has a set of Ansible scripts to assist in the deployment of a real LC infrastructure. The scripts are located in `/cloud/infrastructure/ansible/`.

Below are the steps necessary to prepare to use Ansible to deploy an infrastructure.

## Pre-requisites
This Ansible configuration assumes that you have a staging box (lc-master) which will have Ansible as well as will hold the LC repo as cloned from GitHub and will serve as an SSHFS mount point for the Beach cluster nodes.

On the staging node, you will want to:
1. Create a user called "lc".

1. Generate an SSH key pair as /home/lc/.ssh/id_rsa without a password (will be used to mount SSHFS).

1. Add "127.0.0.1 lc-master" to the /etc/hosts file.

1. `apt-get python-pip python-dev`

1. `pip install ansible`

1. `rm /etc/ansible/hosts`

1. `cd /home/lc; git clone https://github.com/refractionPOINT/limacharlie.git; chown -R lc:lc /home/lc/limacharlie`

1. `cd /etc/ansible; ln -s /home/lc/limacharlie/cloud/infrastructure/ansible/* ./`

## Configure infrastructure setup

### Main deployment variables
The main configuration file to edit is now in `/etc/ansible/group_vars/all.yaml`.
* **iface**: this is the network interface that the beach nodes will use to communicate with each other. If you are leveraging a private network between your nodes, it is likely eth1, but if you only have a flat network you would go for eth0.
* **limacharlie_master**: you will want to set the IP address of the staging node.
* **lc_root**: is the mount point of the SSHFS on each Beach node.
* **tmp_lc_root**: is the location where lc files are copied for non-Beach hosts that require some files, like the HTTP endpoint.
* **local_lc_root**: is the location where the repo/cloud/beach directory is on the staging box.
* **beach_config_file**: is the Beach cluster configuration file to use (relative to the lc_root).
* **cassandra_cluster_seeds**: is the list of comma separated IPs that form the seed nodes in Cassandra (scaling storage).
* **beach_log_level**: how verbose you want the Beach logging (highest is 10).

Note that you will also have to configure the Beach config file to, for example set the Beach seed nodes.

### Role association
Now you want to decide which hosts will do what. To create that association, you will ensure that every host you use for the infrastructure is either available through a DNS service, or in the /etc/hosts file of the staging node. Then you can edit the `/etc/ansible/hosts` file and set which hostname is under which role. The roles are as follow:

* **beach_nodes**: These hosts will be running as part of the Beach cluster.
* **endpoints**: These hosts will be running the HTTP endpoint script receiving the sensor beacons and relaying the information to and from the Beach cluster. (For security reasons we often want this role on dedicated machines that are well segmented off the main network).
* **scale_db**: These hosts will be running as part of the Cassandra cluster.

## Deploy
Now you're ready to simply run ansible: `ansible-playbook /etc/ansible/site.yaml`.

This should begin the deployment of all the various nodes of your infrastructure. Once that is done, the `rolling_*` scripts can help you do rolling restarts of part of the infrastructure if you need.

The next step once it's all done will be to start the LC Actors in the Beach cluster through the start_ scripts and begin loading your LC configs into the cloud. You will also likely want to configure the LC prebuilt binaries to have your own keys, C2 DNS endpoints etc, as covered in other parts of the wiki.
