## Author: @Joseliyo_Jstnk
from pymisp import PyMISP, MISPObject, MISPEvent, MISPTag
from pymisp.mispevent import MISPGalaxy
from keys import vt_apikey, galaxies
import json, urllib3, requests, re, urllib.parse, base64, datetime
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def mispInit(url, key, cer):
    """Function to initiate the MISP connection

    Args:
        url (str): MISP URL
        key (str): MISP API Key
        cer (bool): SSL Certificate False

    Returns:
        Object: Connection to MISP
    """
    return PyMISP(url, key, cer, debug=False)

def parseIocsTxtFile(fileh):
    """Function to parse the IOCs in the TXT file with IOCs

    Args:
        fileh (str): Path to the file with IOCs

    Returns:
        list: List of IOCs included in the file
    """
    iocs = []
    with open(fileh, "r") as f:
        lines = [line.strip() for line in f if line.strip()]
        for ioc in lines:
            iocs.append(ioc)
    return iocs

def extractSigmaTitles(vt_results):
    """Function which extract the Sigma Rules from VT results

    Args:
        vt_results (list): VT results

    Returns:
        list: List of Sigma rules matching the IOCs
    """
    sigmaTitles = list()
    for res in vt_results:
        # check if the result has sigma rules
        if res.get("data").get("attributes").get("sigma_analysis_results"):
            for sigma in res.get("data").get("attributes").get("sigma_analysis_results"):
                sigmaTitles.append(sigma.get("rule_title"))
    return sigmaTitles

def addMitreGalaxyEvent(event, misp, mitreTechniques):
    """Function to insert ATT&CK MITRE galaxies in the MISP event

    Args:
        event (object): MISP event 
        misp (object): MISP connection object
        mitreTechniques (list): List of MITRE techniques related to the IOCs
    """
    eventobj = misp.get_event(event, pythonify=True)
    galax = misp.get_galaxy(galaxies["mitre"])  

    for cluster in galax["GalaxyCluster"]:
        if cluster.get("value").split("-")[1].strip().lower() in mitreTechniques:
            eventobj.add_tag(tag='misp-galaxy:mitre-attack-pattern="%s"'%(cluster.get("value")))
    
    misp.update_event(eventobj)

def extractMitreTechniques(vt_mitre):
    """Function to extract MITRE techniques from VT sandboxes

    Args:
        vt_mitre (list): List of results related to VT from the IOCs

    Returns:
        list: MITRE Techniques related to the Event
    """
    mitreTechniques = list()
    for technique_obj in vt_mitre:
        for k,v in technique_obj["data"].items():
            if k == 'Zenbox' and v["tactics"]:
                for tactic in v["tactics"]:
                    for technique in tactic["techniques"]:
                        mitreTechniques.append(technique["id"].lower())
                        
    return mitreTechniques

def addSigmaGalaxyEvent(event, misp, sigmaTitles):
    """Function to insert Sigma rules galaxies in the MISP event

    Args:
        event (object): MISP event 
        misp (object): MISP connection object
        sigmaTitles (list): List of sigma rules related to the IOCs
    """
    eventobj = misp.get_event(event, pythonify=True)
    galax = misp.get_galaxy(galaxies["sigma-rules"])
    for cluster in galax["GalaxyCluster"]:
        if cluster.get("value") in sigmaTitles:
            eventobj.add_tag(tag='misp-galaxy:sigma-rules="%s"'%(cluster.get("value")))
    misp.update_event(eventobj)

def create_objectDomain_noVT(event, misp, domainsNotVT):
    """Create an object in the event for those IOCs that are not stored in VT

    Args:
        event (object): MISP event 
        misp (object): MISP connection object
        domainsNotVT (list): list of domains that are not in VT
    """
    for domain in domainsNotVT:
        mispobj = MISPObject(name="domain-ip")
        mispobj.add_attribute("domain", value=domain)
    misp.add_object(event, mispobj)

    return True

def create_domains_objects(event, misp, vt_results):
    """Create domain objetcs in the MISP event

    Args:
        event (object): MISP event 
        misp (object): MISP connection object
        vt_results (list): VT results
    """
    for res in vt_results:
        mispobj = MISPObject(name="domain-ip")
        if res.get("data").get("id"):
            mispobj.add_attribute("domain", value=res.get("data").get("id"))
            if res.get("data").get("attributes").get("creation_date"):
                mispobj.add_attribute("registration-date", value=datetime.datetime.fromtimestamp(res.get("data").get("attributes").get("creation_date")))
            if len(res.get("data").get("attributes").get("last_dns_records")) > 0:
                for record in res.get("data").get("attributes").get("last_dns_records"):
                    if record["type"] == "A":
                        mispobj.add_attribute("ip", value=record["value"], comment="Resolution obtained through VirusTotal")

        misp.add_object(event, mispobj)
    return True

def create_object_noVT(event, misp, hashesNotVT):
    """Function to create a file hash object not in VT

    Args:
        event (object): MISP event 
        misp (object): MISP connection object
        hashesNotVT (list): List of hashes not in VT
    """
    for hash in hashesNotVT:
        mispobj = MISPObject(name="file")
        if re.findall(r"^[a-fA-F\d]{32}$", hash):
            mispobj.add_attribute("md5", hash)
        if re.findall(r"^[a-fA-F\d]{40}$", hash):
            mispobj.add_attribute("sha1", hash)
        if re.findall(r"^[a-fA-F\d]{64}$", hash):
            mispobj.add_attribute("sha256", hash)
        misp.add_object(event, mispobj)

    return True

def createFromFileObjects(event, misp, vt_results, vt_mitre):
    """Function which creates file objects in the MISP event

    Args:
        event (object): MISP event 
        misp (object): MISP connection object
        vt_results (list): VT results
        vt_mitre (list): Results of VT with the ATT&CK MITRE Techniques
    """
    for res in vt_results:
        mispobj = MISPObject(name="file")
        sigmaTitles = list()
        # check if the result of VT has sigma rules. If yes, we want to map each sigma rule with the file
        if res.get("data").get("attributes").get("sigma_analysis_results"):
            for sigma in res.get("data").get("attributes").get("sigma_analysis_results"):
                sigmaTitles.append({'name': 'misp-galaxy:sigma-rules="%s"'%(sigma.get("rule_title"))})
        if res.get("mitre_res"):
            galax = misp.get_galaxy(galaxies["mitre"])
            mitreTechniques = list()
            for cluster in galax["GalaxyCluster"]:
                for t in res.get("mitre_res"):
                    for technique in t.get("techniques"):
                        if cluster.get("value").split("-")[1].strip().lower() == technique.get("id").lower():
                            mitreTechniques.append({'name': 'misp-galaxy:mitre-attack-pattern="%s"'%(cluster.get("value"))})
            sigmaTitles.extend(mitreTechniques)

        mispobj.add_attribute("sha1", value=res.get("data").get("attributes").get("sha1"), Tag=sigmaTitles)
        mispobj.add_attribute("md5", value=res.get("data").get("attributes").get("md5"))
        mispobj.add_attribute("sha256", value=res.get("data").get("attributes").get("sha256"))
        mispobj.add_attribute("ssdeep", value=res.get("data").get("attributes").get("ssdeep"))
        mispobj.add_attribute("vhash", value=res.get("data").get("attributes").get("vhash"))
        mispobj.add_attribute("tlsh", value=res.get("data").get("attributes").get("tlsh"))
        try:
            mispobj.add_attribute("mimetype", value=res.get("data").get("attributes").get("exiftool").get("MIMEType"))
        except AttributeError as e:
            pass
        mispobj.add_attribute("text", value=res.get("data").get("attributes").get("magic"))
        if res.get("data").get("attributes").get("names"):
            for name in res.get("data").get("attributes").get("names"):
                mispobj.add_attribute("filename", value=name)
        
        misp.add_object(event, mispobj)
    return True

def create_objecturl_noVT(event, misp, urlsNotVT):
    """Function to create URL objects not in VT

    Args:
        event (object): MISP event 
        misp (object): MISP connection object
        urlsNotVT (list): list of URLs not in VT
    """
    for url in urlsNotVT:
        mispobj = MISPObject(name="url")
        mispobj.add_attribute("url", value=url)
        if ":" in urllib.parse.urlparse(url).netloc:
            mispobj.add_attribute("host", value=urllib.parse.urlparse(url).netloc.split(":")[0])
            mispobj.add_attribute("port", value=urllib.parse.urlparse(url).netloc.split(":")[1])
        else:
            mispobj.add_attribute("host", value=urllib.parse.urlparse(url).netloc)
        if urllib.parse.urlparse(url).path != "/":
            mispobj.add_attribute("resource_path", value=urllib.parse.urlparse(url).path)
        if urllib.parse.urlparse(url).query:
            mispobj.add_attribute("query_string", value=urllib.parse.urlparse(url).query)

    misp.add_object(event, mispobj)

    return True

def create_ips_object(event, misp, vt_results):
    """Create an IP object in MISP

    Args:
        event (object): MISP event 
        misp (object): MISP connection object
        vt_results (list): VT results
    """
    for res in vt_results:
        mispobj = MISPObject(name="ip-port")
        if res.get("data").get("id"):
            mispobj.add_attribute("ip", value=res.get("data").get("id"))
            mispobj.add_attribute("AS", value=res.get("data").get("attributes").get("asn"))
            mispobj.add_attribute("country-code", value=res.get("data").get("attributes").get("country"))
            mispobj.add_attribute("ip", value=res.get("data").get("attributes").get("network"), comment="Network of the IP Address")
            mispobj.add_attribute("text", value=res.get("data").get("attributes").get("as_owner"), comment="Company Owner of the network")
        misp.add_object(event, mispobj)
    return True

def create_url_object(event, misp, vt_results):
    """Create an URL object in MISP

    Args:
        event (object): MISP event 
        misp (object): MISP connection object
        vt_results (list): VT results
    """
    for res in vt_results:
        parsed = urllib.parse.urlparse(res.get("data").get("attributes").get("url"))
        mispobj = MISPObject(name="url")
        if res.get("data").get("attributes").get("url"):
            mispobj.add_attribute("url", value=res.get("data").get("attributes").get("url"))
            if ":" in urllib.parse.urlparse(res.get("data").get("attributes").get("url")).netloc:
                mispobj.add_attribute("host", value=urllib.parse.urlparse(res.get("data").get("attributes").get("url")).netloc.split(":")[0])
                mispobj.add_attribute("port", value=urllib.parse.urlparse(res.get("data").get("attributes").get("url")).netloc.split(":")[1])
            else:
                mispobj.add_attribute("host", value=urllib.parse.urlparse(res.get("data").get("attributes").get("url")).netloc)
            if urllib.parse.urlparse(res.get("data").get("attributes").get("url")).path != "/":
                mispobj.add_attribute("resource_path", value=urllib.parse.urlparse(res.get("data").get("attributes").get("url")).path)
            if urllib.parse.urlparse(res.get("data").get("attributes").get("url")).query:
                mispobj.add_attribute("query_string", value=urllib.parse.urlparse(res.get("data").get("attributes").get("url")).query)
        #print(res.get("data").get("attributes").get("url"))
        misp.add_object(event, mispobj)
    return True

def create_objectIP_noVT(event, misp, ipsNotVT):
    """Function to create IPs MISP objects not stored in VT

    Args:
        event (object): MISP event 
        misp (object): MISP connection object
        ipsNotVT (list): list of IPs not in VT
    """
    for ip in ipsNotVT:
        mispobj = MISPObject(name="ip-port")
        mispobj.add_attribute("ip", value=ip)
    misp.add_object(event, mispobj)

    return True

def mergeVTResults(vt_results, vt_mitre):
    """This functions creates a unique JSON with the information about MITRE and basic info from hashes

    Args:
        vt_results (_type_): VT Results
        vt_mitre (_type_): VT MITRE results
        
    Returns:
        list: List of the merged results
    """
    ## This functions creates a unique JSON with the information about MITRE and basic info from hashes
    for res in vt_results:
        for technique_obj in vt_mitre:
            if res.get("data").get("attributes").get("sha1") in technique_obj.get("links").get("self") or res.get("data").get("attributes").get("md5") in technique_obj.get("links").get("self") or res.get("data").get("attributes").get("sha256") in technique_obj.get("links").get("self"):
                    for k,v in technique_obj["data"].items():
                        if k == 'Zenbox' and v["tactics"]:
                            res["mitre_res"] = v["tactics"]
    
    return vt_results

def masterQueryVT(iocs, search):
    """Function to query VT with information about the IOCs

    Args:
        iocs (list): List of IOCs stored in the TXT
        search (str): Type of search in VT

    Returns:
        list: List of results obtained from VT
    """
    resultList = list()
    resultListNotVT = list()
    headers = {
    "accept": "application/json",
    "x-apikey": vt_apikey
    }
    if search != "urls":
        for ioc in iocs:
            response = requests.get("https://www.virustotal.com/api/v3/%s/%s"%(search,ioc), headers=headers)
            if json.loads(response.text).get("error"): 
                resultListNotVT.append(ioc) 
            else:
                resultList.append(json.loads(response.text))
    else:
        for ioc in iocs:
            response = requests.get("https://www.virustotal.com/api/v3/%s/%s"%(search, base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")), headers=headers)
            if json.loads(response.text).get("error"): 
                resultListNotVT.append(ioc) 
            else:
                resultList.append(json.loads(response.text))
    return resultList, resultListNotVT 


def queryMitreVT(iocs):
    """Function to query VT and get MITRE results

    Args:
        iocs (list): List of IOCs stored in the TXT

    Returns:
        list: List of results obtained from VT
    """
    ## This query returns info related to MITRE about some iocs
    resultList = list()
    headers = {
    "accept": "application/json",
    "x-apikey": vt_apikey
    }
    for ioc in iocs:
        response = requests.get("https://www.virustotal.com/api/v3/files/%s/behaviour_mitre_trees"%(ioc), headers=headers)
        resultList.append(json.loads(response.text))
    return resultList


def mispEventCreation(misp, title):
    """Function to create a MISP event

    Args:
        misp (object): MISP connection object
        title (str): Title of the MISP event to create

    Returns:
        _type_: _description_
    """
    event = MISPEvent()
    event.distribution = 1 # this community only
    event.threat_level_id = 1 # high
    event.analysis = 0 # initial
    event.info = title # event title
    ev = misp.add_event(event, pythonify=True)
    return ev