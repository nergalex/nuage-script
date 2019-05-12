# -*- coding: utf-8 -*-
"""
--- Object ---
Fetch all instances in your organization and get their geographic uplink

--- Usage ---
Run 'python Nuage-getPraStatus.py -h' for an overview

--- Documentation ---
none

--- Author ---
DA COSTA Alexis <alexis.dacosta@bt.com>

--- Examples ---

TODO

"""

import argparse
import sys
from prettytable import PrettyTable

try:
    # Try and import Nuage VSPK from the development release
    from vspk import v5_0 as vsdk
except ImportError:
    # If this fails, import the Nuage VSPK from the pip release
    from vspk.vsdk import v5_0 as vsdk

def setup_logging(debug, verbose, log_file):
    import logging
    from vspk.utils import set_log_level
    
    if debug:
        log_level = logging.DEBUG
    elif verbose:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING
        
    set_log_level(log_level)
    logging.basicConfig(filename=log_file, format='%(asctime)s %(levelname)s %(message)s', level=log_level)
    logger = logging.getLogger(__name__)
    return logger

def start_nuage_connection(nuage_host, nuage_port, nuage_username, nuage_password, nuage_organization, logger):
        logger.info('Connecting to Nuage server %s:%s with username %s' % (nuage_host, nuage_port, nuage_username))
        session = vsdk.NUVSDSession(username=nuage_username,
                                    password=nuage_password,
                                    enterprise=nuage_organization,
                                    api_url="https://%s:%s" % (nuage_host, nuage_port))

        # Connecting to Nuage
        try:
            session.start()
        except:
            logger.error('Could not connect to Nuage host %s with user %s, enterprise %s and specified password' % (nuage_host, nuage_username, nuage_enterprise))
        return session.user  

def get_args():
    """
    Supports the command-line arguments listed below.
    """

    parser = argparse.ArgumentParser(description="Fetch a DOMAIN template.")
    parser.add_argument('-d', '--debug', required=False, help='Enable debug output', dest='debug', action='store_true')
    parser.add_argument('-l', '--log-file', required=False, help='File to log to (default = stdout)', dest='logfile', type=str)
    parser.add_argument('--nuage-organization', required=True, help='The organization with which to connect to the Nuage VSD/SDK host', dest='nuage_organization', type=str)
    parser.add_argument('--nuage-host', required=True, help='The Nuage VSD/SDK endpoint to connect to', dest='nuage_host', type=str)
    parser.add_argument('--nuage-port', required=True, help='The Nuage VSD/SDK server port to connect to (default = 8443)', dest='nuage_port', type=int, default=8443)
    parser.add_argument('--nuage-password', required=True, help='The password with which to connect to the Nuage VSD/SDK host. If not specified, the user is prompted at runtime for a password', dest='nuage_password', type=str)
    parser.add_argument('--nuage-user', required=True, help='The username with which to connect to the Nuage VSD/SDK host', dest='nuage_username', type=str)
    parser.add_argument('-v', '--verbose', required=False, help='Enable verbose output', dest='verbose', action='store_true')
    parser.add_argument('-e', '--extended', required=False, help='Enable extended output', dest='extended', action='store_true')
    parser.add_argument('--nuage-L2Domain_filter', required=False, help='String in L2 Domain name', dest='nuage_l2domain', type=str)
    parser.add_argument('--nuage-L3Domain_filter', required=False, help='String in L3 Domain name', dest='nuage_l3domain', type=str)
    
    args = parser.parse_args()
    return args

def clear(logger):
    """
    Clears the terminal
    """
    if logger:
        logger.debug('Clearing terminal')
    os.system(['clear', 'cls'][os.name == 'nt'])

def getDefaultPrimarySite(myDomain):
    if "Lille" in myDomain: 
        myEntryDefaultPrimarySite = 'Lille'
    elif "Lyon" in myDomain: 
        myEntryDefaultPrimarySite = 'Lyon'
    else:
        myEntryDefaultPrimarySite = 'unknown'
    return myEntryDefaultPrimarySite
    
def getPRAstatus(myEntryDefaultPrimarySite, myEntryVPortPrimarySite, myEntryVPortSecundarySite):
    if len(myEntryVPortPrimarySite) == 0 and len(myEntryVPortSecundarySite) == 0:
        myEntryPRAstatus = 'ERROR: No PRA devices'
        myEntryCurrentSite = 'unknwon'
    elif len(myEntryVPortPrimarySite) == 0:
        myEntryPRAstatus = 'OK'
        if  myEntryDefaultPrimarySite == 'Lille':
            myEntryCurrentSite = 'Lyon'
        elif  myEntryDefaultPrimarySite == 'Lyon':
            myEntryCurrentSite = 'Lille'
        else:
            myEntryCurrentSite = 'ERROR: unknown'
    elif len(myEntryVPortSecundarySite) == 0:
        myEntryPRAstatus = 'OK'
        if  myEntryDefaultPrimarySite == 'Lille':
            myEntryCurrentSite = 'Lille'
        elif  myEntryDefaultPrimarySite == 'Lyon':
            myEntryCurrentSite = 'Lyon'
        else:
            myEntryCurrentSite = 'ERROR: unknown'
    else:
        myEntryPRAstatus = 'NOK'
        myEntryCurrentSite = 'Dual Site'

    return [myEntryPRAstatus, myEntryCurrentSite]
    
def main():
    # Handling arguments

    args                = get_args()
    debug               = args.debug
    verbose             = args.verbose
    log_file            = args.logfile
    nuage_organization  = args.nuage_organization
    nuage_host          = args.nuage_host
    nuage_port          = args.nuage_port
    nuage_password      = args.nuage_password
    nuage_username      = args.nuage_username
    extended            = None
    if args.extended:
        extended        = args.extended
    nuage_l2domain            = None
    if args.nuage_l2domain:
        nuage_l2domain        = args.nuage_l2domain
    nuage_l3domain            = None
    if args.nuage_l3domain:
        nuage_l3domain        = args.nuage_l3domain
    """
    # Bouchonnage arguments
    debug               = False
    verbose             = False
    log_file            = 'Nuage-log.txt'
    nuage_organization  = 'AES'
    nuage_host          = '127.1.1.2'
    nuage_port          = '8443'
    nuage_password      = 'Sncfaes2017!'
    nuage_username      = 'admin'
    extended            = None
    nuage_l2domain      = None
    nuage_l3domain      = 'DMZ-10'
    """
    
    # Logging settings
    logger = setup_logging(debug, verbose, log_file)
        
    # Getting user password for Nuage connection
    if nuage_password is None:
        logger.debug('No command line Nuage password received, requesting Nuage password from user')
        nuage_password = getpass.getpass(prompt='Enter password for Nuage host %s for user %s: ' % (nuage_host, nuage_username))
    
    # Connection to VSD
    nc = start_nuage_connection(nuage_host, nuage_port, nuage_username, nuage_password, nuage_organization, logger)

    # Execute action
    
    if extended:
        logger.debug('Setting up extended output table')
        pt = PrettyTable(['Enterprise', 'Domain', 'PRA Consistency', 'Default Primary Site', 'Current Site', 'vPort on Primary Site', 'vPort on Secundary Site'])
        pt.align['Domain'] = 'l'
        pt.align['vPort on Primary Site'] = 'l'
        pt.align['vPort on Secundary Site'] = 'l'   
    else:
        logger.debug('Setting up basic output table')
        pt = PrettyTable(['Enterprise', 'Domain', 'PRA Consistency', 'Default Primary Site', 'Current Site'])
        pt.align['Domain'] = 'l'  
        
    for cur_ent in nc.enterprises.get():
        # L3 DOMAIN
        for cur_domain in cur_ent.domains.get():           
            # Default Primary Site
            myEntryDefaultPrimarySite = getDefaultPrimarySite(cur_domain.name)
            
            # PRA mode
            if "mode PRA supporte" not in cur_domain.description:
                myEntryPRAstatus = 'Not a PRA DMZ'
                myEntryCurrentSite = myEntryDefaultPrimarySite
                myEntryVPortPrimarySite = 'no lookup done'
                myEntryVPortSecundarySite = 'none'
            elif (nuage_l3domain and nuage_l3domain in cur_domain.name) or (not nuage_l3domain):
                myEntryVPortPrimarySite = []
                myEntryVPortSecundarySite = []            
                for cur_zone in cur_domain.zones.get():
                    for cur_subnet in cur_zone.subnets.get():
                        for cur_vport in cur_subnet.vports.get():
                            if '__Member' in cur_vport.description:
                                myEntryVPortPrimarySite.append(cur_vport.name)
                            elif '-PRA__Member' in cur_vport.description: 
                                myEntryVPortSecundarySite.append(cur_vport.name)
                
                # Define PRA Status
                [myEntryPRAstatus, myEntryCurrentSite] = getPRAstatus(myEntryDefaultPrimarySite, myEntryVPortPrimarySite, myEntryVPortSecundarySite)
            
            # Add an output entry
            if (nuage_l3domain and nuage_l3domain in cur_domain.name) or (not nuage_l3domain):
                if extended:
                    pt.add_row([cur_ent.name, cur_domain.name, myEntryPRAstatus, myEntryDefaultPrimarySite, myEntryCurrentSite, myEntryVPortPrimarySite, myEntryVPortSecundarySite])
                else:
                    pt.add_row([cur_ent.name, cur_domain.name, myEntryPRAstatus, myEntryDefaultPrimarySite, myEntryCurrentSite])

        # L2 DOMAIN
        for cur_domain in cur_ent.l2_domains.get():           
            # Default Primary Site
            myEntryDefaultPrimarySite = getDefaultPrimarySite(cur_domain.name)
            
            # PRA mode
            if "mode PRA supporte" in cur_domain.description:
                myEntryPRAstatus = 'Not a PRA DMZ'
                myEntryCurrentSite = myEntryDefaultPrimarySite
                myEntryVPortPrimarySite = 'no lookup done'
                myEntryVPortSecundarySite = 'none'
            elif (nuage_l2domain and nuage_l2domain in cur_domain.name) or (not nuage_l2domain):
                myEntryVPortPrimarySite = []
                myEntryVPortSecundarySite = []            
                for cur_vport in cur_domain.vports.get():
                    if '__Member' in cur_vport.description:
                        myEntryVPortPrimarySite.append(cur_vport.name)
                    elif '-PRA__Member' in cur_vport.description: 
                        myEntryVPortSecundarySite.append(cur_vport.name)
                
                # Define PRA Status
                [myEntryPRAstatus, myEntryCurrentSite] = getPRAstatus(myEntryDefaultPrimarySite, myEntryVPortPrimarySite, myEntryVPortSecundarySite)
            
            # Add an output entry
            if (nuage_l2domain and nuage_l2domain in cur_domain.name) or (not nuage_l2domain):
                if extended:
                    pt.add_row([cur_ent.name, cur_domain.name, myEntryPRAstatus, myEntryDefaultPrimarySite, myEntryCurrentSite, myEntryVPortPrimarySite, myEntryVPortSecundarySite])
                else:
                    pt.add_row([cur_ent.name, cur_domain.name, myEntryPRAstatus, myEntryDefaultPrimarySite, myEntryCurrentSite])

    logger.debug('Printing output')
    print (pt.get_string(sortby='PRA Consistency'))

    return 0
            
# Start program
if __name__ == "__main__":
    main()