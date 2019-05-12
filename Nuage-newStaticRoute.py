# -*- coding: utf-8 -*-
"""
--- Object ---
Create a Static Route

--- Usage ---
Run 'python Nuage-newStaticRoute.py -h' for an overview

--- Documentation ---
none

--- Author ---
DA COSTA Alexis <alexis.dacosta@bt.com>

--- Examples ---

none

"""

import argparse
import sys

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

    parser = argparse.ArgumentParser(description="Deploy a DOMAIN template.")
    parser.add_argument('-d', '--debug', required=False, help='Enable debug output', dest='debug', action='store_true')
    parser.add_argument('-l', '--log-file', required=False, help='File to log to (default = stdout)', dest='logfile', type=str)
    parser.add_argument('--nuage-organization', required=True, help='The organization with which to connect to the Nuage VSD/SDK host', dest='nuage_organization', type=str)
    parser.add_argument('--nuage-host', required=True, help='The Nuage VSD/SDK endpoint to connect to', dest='nuage_host', type=str)
    parser.add_argument('--nuage-port', required=False, help='The Nuage VSD/SDK server port to connect to (default = 8443)', dest='nuage_port', type=int, default=8443)
    parser.add_argument('--nuage-password', required=False, help='The password with which to connect to the Nuage VSD/SDK host. If not specified, the user is prompted at runtime for a password', dest='nuage_password', type=str)
    parser.add_argument('--nuage-user', required=True, help='The username with which to connect to the Nuage VSD/SDK host', dest='nuage_username', type=str)
    parser.add_argument('--nuage-myEnterprise', required=False, help='The Nuage enterprise to which the VM (baremetal or Appliance) should be connected', dest='nuage_myEnterprise', type=str)
    parser.add_argument('-v', '--verbose', required=False, help='Enable verbose output', dest='verbose', action='store_true')
    parser.add_argument('--nuage-myDomain', required=False, help='The name of the Nuage L3Domain to which the VM (baremetal or Appliance) should be connected', dest='nuage_myDomain', type=str)
    parser.add_argument('--nuage-myRouteAddress', required=False, help='The Address of the Static Route', dest='nuage_myRouteAddress', type=str)
    parser.add_argument('--nuage-myRouteNetmask', required=False, help='The Netmask of the Static Route', dest='nuage_myRouteNetmask', type=str)
    parser.add_argument('--nuage-myRouteNextHopIP', required=False, help='The Next Hop IP of the Static Route', dest='nuage_myRouteNextHopIP', type=str)

    args = parser.parse_args()
    return args

def clear(logger):
    """
    Clears the terminal
    """
    if logger:
        logger.debug('Clearing terminal')
    os.system(['clear', 'cls'][os.name == 'nt'])

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
    nuage_myEnterprise  = args.nuage_myEnterprise
    nuage_myDomain      = args.nuage_myDomain
    nuage_myRouteAddress        = args.nuage_myRouteAddress
    nuage_myRouteNetmask        = args.nuage_myRouteNetmask
    nuage_myRouteNextHopIP      = args.nuage_myRouteNextHopIP
    MyCmsName = 'CMS-scripts'
      
    """
    # Bouchonnage arguments
    debug               = False
    verbose             = False
    log_file            = 'Nuage-log.txt'
    nuage_organization  = 'TEST'
    nuage_host          = '127.1.1.2'
    nuage_port          = '8443'
    nuage_password      = 'test2018'
    nuage_username      = 'admin-test'
    nuage_myEnterprise = 'TEST'
    nuage_myDomain     = 'myTestDomain2'
    nuage_myDomainDesc = 'DMZ d hebergement des interfaces Front des Proxy ou Rebond et dont la gateway est le composant ADC'
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
    myFilter = "name == \"" + nuage_myEnterprise +"\""
    myEnterprise = nc.enterprises.get_first(filter = myFilter)
    print('Entreprise : %s' % myEnterprise.name)
    
    myFilter = "name == \"" + nuage_myDomain +"\""
    myDomain = myEnterprise.domains.get_first(filter = myFilter)
    print('Domain : %s' % myDomain.name)
    
    myNewRoute = vsdk.NUStaticRoute(bfd_enabled = False,
                                                ip_type = 'IPV4',
                                                address = nuage_myRouteAddress,
                                                netmask = nuage_myRouteNetmask,
                                                next_hop_ip = nuage_myRouteNextHopIP,
                                                entity_scope = 'ENTERPRISE',
                                                type = 'OVERLAY',
                                                external_id = MyCmsName
                                               )
    print ('Route %s %s via %s is created.' % (myNewRoute.address, myNewRoute.netmask, myNewRoute.next_hop_ip))

    myDomain.create_child(myNewRoute)
    print ('Route %s %s via %s id: %s' % (myNewRoute.address, myNewRoute.netmask, myNewRoute.next_hop_ip, myNewRoute.id))
    
    logger.warning ('Enterprise %s > Domain %s > Static Route %s %s via %s id: %s' % (myEnterprise.name, myDomain.name, myNewRoute.address, myNewRoute.netmask, myNewRoute.next_hop_ip, myNewRoute.id))

# Start program
if __name__ == "__main__":
    main()