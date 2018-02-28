# Crypto Discussion

## Algorithms
TLS with strong cypher algorithms is used for transport encryption between the sensor and the cloud.

RSA-2048/SHA-256 is used to sign the taskings and modules.

SHA-256 is used as general hashing algorithm and for signatures. 

## Keys
### C2
This RSA key pair is used to secure the session key exchange with the command and control using TLS. It is NOT privileged in HCP
which means its compromise is important but not critical. An attacker will not be able to task the sensors with it.
It means it can safely sit in the cloud with BeaconProcessor Actors.

### HCP
The HCP key pair is used to sign the modules loaded on HCP. This means a compromise of this key is critical since
it could allow an attacker to load arbitrary code in HCP. For this reason it's recommended to keep it offline and
sign new module (like HBS) releases on an air-gapped trusted system, and copy the resulting `.sig` signatures back
to your cloud once signed.

### HBS
The HBS key pair is used to issue taskings to the HBS module. Compromise is also critical as it can allow an attacker
to modify the host. This key pair is NOT required to be "live" in the cloud. For this reason it is recommended that
key pair is kept in as much of an air-gap as possible and only loaded in the `admin_cli.py` only when required. The
`admin_cli.py` loads this key assuming it is protected and decrypts and loads them in 
memory, meaning you can (for example) keep the key on a USB stick and connect it only at the start time of the cli and
then disconnect, limiting the exposure of the keys.

## Offline Online Tradeoff
Although the official recommendation would be to keep the critical keys offline in an ideal scenario, it also complicates operation drastically. It also means the cloud may not task sensors in an automated fashion with makes Hunters unavailable. For these reasons the provided cloud implementation maintains those keys in its database to provide an easier to use backend with more advanced features.