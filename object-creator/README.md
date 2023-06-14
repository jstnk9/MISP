# Object Creator

Object creator is a python script that helps you to add IOCs (in object format) in your MISP with extra information and galaxies automatically. The information is retrieved from VirusTotal using the API Key. If the IOC is in VT, the information extracted is as follows:

* Files
  * Sha256
  * MD5
  * Sha1
  * ssdeep
  * vhash
  * tlsh
  * mimetype
  * filenames
  * magic
  * MITRE Techniques as MISP Galaxies
  * Sigma rules as MISP Galaxies
* IPs
  * IP
  * ASN
  * Country code
  * network
  * ASN Owner
* Domains
  * Domain
  * Registration date
  * Resolutions
* URLs 
  * URL
  * Host
  * Port
  * Resource Path
  * Query string
* Event
  * All the MITRE Techniques extracted from the files stored in the MISP event
  * All the Sigma rules extracted from the files stored in the MISP event

Blog explanation: https://jstnk9.github.io/jstnk9/blog/MISP-object-creator-with-Virustotal-and-Sigma

# How it works

![process](https://jstnk9.github.io/jstnk9/img/blog-object-creator/graph.png)

This repository contains 3 components. The whole repo is around MISP and VirusTotal. Both VirusTotal and MISP APIs are required, as well as the MISP URL where you want to store the information. In order to work with the script, you need to modify the `keys.py` file with your information.

* `core.py`: Is the main script and the one that you're going to use to add information in your MISP.
* `mispActions.py`: Is the script which contains the logic of MISP and VT.
* `keys.py`: Contains the information needed to interact with VT and MISP. You need to set the variables in order to use the script.

## Keys.py information

The information stored in the `keys.py` file is the following:

![keys](https://raw.githubusercontent.com/jstnk9/MISP/main/object-creator/img/keys.png)

The `galaxies` variable is needed to ensure that your galaxies are stored in your MISP events. If you want to know the ID of your `Sigma Galaxy` and `MITRE Galaxy`, you have to go to `Galaxies` -> `List Galaxies` section in your MISP (https://YOUR_MISP_HOSTNAME/galaxies/index).

Once you're in the index, look for `sigma` in the search bar. The result will bring you the ID of the Sigma galaxy that you need to fill in the `keys.py` file. The other galaxy that you need to have the galaxy is `Attack Pattern`. You can look for `mitre` and select the galaxy with name `Attack Pattern`.

![sigma_example](https://raw.githubusercontent.com/jstnk9/MISP/main/object-creator/img/sigma_example.png)

![mitre example](https://raw.githubusercontent.com/jstnk9/MISP/main/object-creator/img/mitre_example.png)

For the `misp_key` variable, you can add a new API key if you go to `Administration` -> `List Auth Keys` section (https://YOUR_MISP_HOSTNAME/auth_keys/index). Click on `+ Add authentication key` to create it and save to store the value in your `keys.py`.

Finally, you need to have VT API key and the hostname of your MISP.

# Script Usage

First, install the `requirements.txt`. I recommend the use of virtualenv for this purpose.

```
pip install -r requirements.txt
```

## Help

```bash
python core.py -h                                               
usage: core.py [-h] [-e EVENT] -f FILEH [-et EVENTTITLE] [--create]

MISP Objects creation

options:
  -h, --help            show this help message and exit
  -e EVENT, --event EVENT
                        MISP event ID where you want to add IOCs in case it already exists.
  -f FILEH, --file FILEH
                        TXT File with IOCs. Do not include different hashes from the same file if it is in Virustotal, just a MD5 or SHA1 or
                        SHA256 of the same file since the script is going to get the rest of hashes to store them in the event. You can add
                        URLs, domains, IPs as well, even broken like hxxp, [.], etc..
  -et EVENTTITLE, --event-title EVENTTITLE
                        In case you use --create flag, use -et with the title of the event that you want to create. For example, -et "Malicious campaign related to Trickbot"
  --create              Set this flag in case you want to create a new event. 
                        You need to set the title of  the event as well.
  ```

## Create a new MISP event 

If you want to add the IOCs to a new MISP event, you need to set the flags `--create` and `-et` including the event tittle to create it.
```
python core.py -f iocs.txt --create -et "Malicious campaign related to Trickbot"
```

## Add IOCs to an existing event

If you want to add the IOCs to an existing event, you need to set the flag `-e` followed by the event ID.

```
python core.py -f iocs.txt -e 33
```

# Images

As long as the samples added in the TXT file have the information associated with the Sigma and MITRE Techniques rules in VirusTotal, it will be added as a galaxy in the MISP event. If there were no information associated with any of the samples to be added, the galaxies would not be added. Finally, if there is any sample which is not in VT, it will be added just with the initial information of the TXT, for example, just a MD5 hash.

![image_event](https://raw.githubusercontent.com/jstnk9/MISP/main/object-creator/img/event_galaxies.png)

Additionally, in order to have the behavioral context of each sample, its personalized information is also added to the object. If a sample has multiple MITRE techniques and sigma rules that identify its behavior in VT, it will be added to the IOC.

![image_object](https://raw.githubusercontent.com/jstnk9/MISP/main/object-creator/img/object_created.png)
