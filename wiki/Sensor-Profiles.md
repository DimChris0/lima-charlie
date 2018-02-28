# Sensor Profiles

Sensor profiles allow the cloud to send some basic configuration at run-time to the sensor. Different profiles can be sent to different sensors based on the sensor id mask provided.

## Customizing Profiles
Copy the `/cloud/beach/production_hbs.profile` or the `/cloud/beach/full_hbs.profile` and make your modifications. The two files are based on the RPCM Python API and should be fairly self-descriptive in general. To get detailed usage however you may have to look at the correct HBS sensor collector code if you're not sure of the usage.

Don't hesitate to just ask for [help on Slack](http://limacharlie.herokuapp.com/).