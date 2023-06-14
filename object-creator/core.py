import re, argparse
from functools import reduce
import mispActions
from keys import misp_url, misp_key, misp_verifycert


def sanitizeIOCs(iocs):
    """Function to sanitize IOCs

    Args:
        iocs (list): List of IOCs in the TXT file

    Returns:
        list: List of sanitized IOCs
    """
    repls = ("hxxp", "http"), ("[.]", "."), ("[:]", ":"), ("[://]", "://"), ("[//]", "//")
    newIOCs = list()
    for ioc in iocs:
        newIOCs.append(reduce(lambda a, kv: a.replace(*kv), repls, ioc))
    return newIOCs

def determineIOCType(iocs):
    """Function to determine the type of IOC

    Args:
        iocs (list): List of IOCs in the TXT file

    Returns:
        list: Lists of IOCs types
    """
    urlList = list()
    hashesList = list()
    ipList = list()
    domainList = list()

    for ioc in iocs:
        if re.findall(r"^(http|https)://", ioc):
            urlList.append(ioc)
        if re.findall(r"^[a-fA-F\d]{32}$", ioc):
            hashesList.append(ioc)
        if re.findall(r"^[a-fA-F\d]{40}$", ioc):
            hashesList.append(ioc)
        if re.findall(r"^[a-fA-F\d]{64}$", ioc):
            hashesList.append(ioc)
        if re.findall(r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)", ioc):
            ipList.append(ioc)
        if re.findall(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]", ioc) and not ioc.startswith("http"):
            domainList.append(ioc)
 
    return urlList, hashesList, ipList, domainList

def eventCreationObjects(fileh, eventTitle, cEvent=False, idEvent=0):
    """Core function to start doing all the tasks in order to create or add the IOCs in MISP events

    Args:
        fileh (str): File path with IOCs
        eventTitle (str): MISP event title
        cEvent (bool, optional): . Defaults to False.
        idEvent (int, optional): _description_. Defaults to 0.
    """
    misp = mispActions.mispInit(misp_url, misp_key, misp_verifycert)
    if cEvent:
        event = mispActions.mispEventCreation(misp, eventTitle)
    else:
        event = idEvent

    iocs_f = mispActions.parseIocsTxtFile(fileh)
    iocs = sanitizeIOCs(iocs_f)
    urls, hashes, ips, domains = determineIOCType(iocs)

    if len(hashes) > 0:
        vt_results, hashesNotVT = mispActions.masterQueryVT(hashes, 'files')
        hashes = [x for x in hashes if x not in hashesNotVT] # we remove the hashes not in VT from the hashes list
        vt_mitre = mispActions.queryMitreVT(hashes)
        vt_results = mispActions.mergeVTResults(vt_results, vt_mitre)
        mispActions.createFromFileObjects(event, misp, vt_results, vt_mitre)
        sigmaTitles = mispActions.extractSigmaTitles(vt_results)
        rsig = mispActions.addSigmaGalaxyEvent(event, misp, sigmaTitles)
        mitreTechniques = mispActions.extractMitreTechniques(vt_mitre)
        xx = mispActions.addMitreGalaxyEvent(event, misp, mitreTechniques)
        if len(hashesNotVT) > 0: # this means that there is at least 1 hash not in VT, and we want to create an object
            mispActions.create_object_noVT(event, misp, hashesNotVT)

    if len(urls) > 0:
        vt_urls, urlsNotVT = mispActions.masterQueryVT(urls, 'urls')
        urls = [x for x in urls if x not in urlsNotVT] 
        mispActions.create_url_object(event, misp, vt_urls)
        if len(urlsNotVT) > 0: 
            mispActions.create_objecturl_noVT(event, misp, urlsNotVT)

    if len(ips) > 0:
        vt_ips, ipsNotVT = mispActions.masterQueryVT(ips, 'ip_addresses')
        ips = [x for x in ips if x not in ipsNotVT]
        mispActions.create_ips_object(event, misp, vt_ips)
        if len(ipsNotVT) > 0: 
            mispActions.create_objectIP_noVT(event, misp, ipsNotVT)

    if len(domains) > 0:
        vt_domains, domainsNotVT = mispActions.masterQueryVT(domains, 'domains')
        domains = [x for x in domains if x not in domainsNotVT] 
        mispActions.create_domains_objects(event, misp, vt_domains)
        if len(domainsNotVT) > 0: 
            mispActions.create_objectDomain_noVT(event, misp, domainsNotVT)
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="MISP Objects creation")
    parser.add_argument("-e", "--event", dest="event", required=False, default=False, help="MISP event ID where you want to add IOCs in case it already exists.")
    parser.add_argument("-f", "--file", dest="fileh", required=True, default=False, help="TXT File with IOCs. Do not include different hashes from the same file if it is in Virustotal, just a MD5 or SHA1 or SHA256 of the same file since the script is going to get the rest of hashes to store them in the event. You can add URLs, domains, IPs as well, even broken like hxxp, [.], etc..")
    parser.add_argument("-et", "--event-title", dest="eventTitle", required=False, default=False, help="In case you use --create flag, use -et with the title of the event that you want to create. For example, -et 'Malicious campaign related to Trickbot'")
    parser.add_argument("--create", action="store_true", required=False, help="Set this flag in case you want to create a new event. You need to set the title of  the event as well. ")
    args = parser.parse_args()
    if args.event and (args.create or args.eventTitle):
        parser.error("Please select if you want to create a new event or add the iocs to an existing one.")
    if (args.create and not args.eventTitle) or (args.eventTitle and not args.create):
        parser.error("Please, if you want to create a new event, add the title between \"\". For example, -et \"New IOCs related to XX\". And use the --create flag")

    eventCreationObjects(args.fileh, args.eventTitle, cEvent=args.create, idEvent=int(args.event))