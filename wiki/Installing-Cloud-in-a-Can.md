## Pre-Requirements
The cloud side of LC is designed and tested on Ubuntu Server x64. Other Debian distributions are likely going to work as well, but your mileage may vary.

Install Ubuntu Server x64 on a host / VM with at least 2 GB of RAM. This will provide you with a barebone install that should allow you to run all components and a few sensors in parallel. Full-blown LC infrastructure installs will have varying requirements depending on the components and numbers of sensors.

## Installing Cloud-Side

In a terminal window, using a user who can sudo (not `root`), enter the following command:

### One Liner Install
```sudo bash -c "curl -L https://raw.githubusercontent.com/refractionPOINT/lc_cloud/master/infrastructure/bootstrap_cloud_in_a_can.sh | tr '\n' '; ' | env LC_BRANCH=master bash -s"```

The resulting install will generate a default administrator account (user: admin@limacharlie, password: letmein). Use the credentials to log in to the web ui listening on port 8888 by default. You will have to change your password and record a second factor (using something like the [Google Authenticator for iOS](https://itunes.apple.com/us/app/google-authenticator/id388497605?mt=8) or the [Google Authenticator for Android](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2&hl=en).

Once logged in, follow the new deployment checklist available in the dashboard (click on the LimaCharlie icon to access the dashboard).

### Somewhat Custom Install
1. Clone the LC repository onto the Ubuntu server (```apt-get install git```). For simplicity I recommend checking it out to the home directory of your default user. These examples use a user called 'server'.

  ```
  cd ~/
  git clone --recursive https://github.com/refractionPOINT/limacharlie.git
  ```
1. Install and configure the software packages.

  ```
  cd ~/limacharlie/cloud/infrastructure/
  sudo python install_cloud_in_a_can.py
  ```
1. Start the Beach cluster and load the actors. This is the step you will want to repeat if you need to restart the cloud and actors. To start from a clean state, you can do a `sudo stop_cloud_in_a_can.sh` before doing the step below.

  ```
  cd ~/limacharlie/cloud/infrastructure/
  python start_cloud_in_a_can.py
  ```

### Cloud Actor Source

Note that by default, ```python ./start_cloud_in_a_can.py``` will start the cluster in a complete local mode. This means that it loads all the Actors from the local disk (```lc_local.yaml```). There is another option (give it a ```-h``` to see exact arguments) that allows you to instead load the Actors directly from a github repo. If you use the beach cluster config ```lc_develop.yaml``` or ```lc_release.yaml```, you will load the Actors from the official dev or release branch of LimaCharlie. The advantage here is you never have to update your Actors, you can always be on the latest version.

## Running Sensors
To get sensor installers, you will want to:
1. Login to the web ui (started on the server on port 8888 by default). Change the password and record the second factor. Like `http://<your_cloud_ip>:8888/`
1. Go to the Cloud Configurations menu from the main menu (top left).
1. Change the Primary and Secondary Domain and port to be where the sensors can reach the server. This can be a Domain or IP.
1. Change the UI Domain to the same, this is where the web ui can be reached, it is used to create smart links.
1. Go to your profile (admin@limacharlie by default) from the main menu.
1. Go to Create Org and create a new Organization with any name you want.
1. In All Organization choose the new Org and click Join Organizations.
1. Go to Installers and Logs from the main menu.
1. You should be able to see all installers present there. Those installers are specifically for this organization. Download the relevant installer and run it on the hosts you want. Installers can be re-used for multiple sensors.
1. Below the installers in the web ui, there is an `Installation Key`. This key is generated unique for this organization, it contains a public key and the URL of your LC backend. Copy this key by clicking on it.
1. On the host you wish to install the sensor, start an administrator (or root) command prompt (or terminal) and execute the installer with `-i <InstallationKey>`. This will install and enroll the sensor. Note that on Linux you need to use `-d <InstallationKey>` to execute the sensor and enroll, but this will not *install* the sensor, starting the sensor on Linux is dependant on the distribution you're using.

## Confirm Sensors Enrolled
You can now browse to `http://<your_cloud_ip>:8888/sensors`. The sensors you've started should be visible.

## Load Capabilities
Initially, only the core functionality is loaded in the cloud. Think of it as an EDR without actual detection. You can see a lot of events coming in and you can task sensors with command via the command line.

To get detection, you'll have to load capabilities, see the section on this [topic on the wiki](Load-Unload-Capabilities).