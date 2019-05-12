# -*- coding: utf-8 -*-
"""
--- Object ---
Create a L2 Domain

--- Usage ---
Run 'python Nuage-newL2Domain.py -h' for an overview

--- Documentation ---
none

--- Author ---
DA COSTA Alexis <alexis.dacosta@bt.com>

--- Examples ---

TODO

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
    parser.add_argument('--nuage-port', required=True, help='The Nuage VSD/SDK server port to connect to (default = 8443)', dest='nuage_port', type=int, default=8443)
    parser.add_argument('--nuage-password', required=True, help='The password with which to connect to the Nuage VSD/SDK host. If not specified, the user is prompted at runtime for a password', dest='nuage_password', type=str)
    parser.add_argument('--nuage-user', required=True, help='The username with which to connect to the Nuage VSD/SDK host', dest='nuage_username', type=str)
    parser.add_argument('--nuage-myEnterprise', required=True, help='The Nuage enterprise to which the VM (baremetal or Appliance) should be connected', dest='nuage_myEnterprise', type=str)
    parser.add_argument('-v', '--verbose', required=False, help='Enable verbose output', dest='verbose', action='store_true')
    parser.add_argument('--nuage-myDomainTemplate', required=True, help='The name of the Nuage L3Domain Template to which the L3DOMAIN will be instaciated', dest='nuage_myDomainTemplate', type=str)
    parser.add_argument('--nuage-myDomain', required=True, help='The name of the Nuage L3Domain to which the VM (baremetal or Appliance) should be connected', dest='nuage_myDomain', type=str)
    parser.add_argument('--nuage-myDomainDesc', required=True, help='The Description of the Nuage L3Domain to which the VM (baremetal or Appliance) should be connected', dest='nuage_myDomainDesc', type=str)
    parser.add_argument('--nuage-myDefaultGatewayIp', required=True, help='The IP address of the gateway of this l2 domain', dest='nuage_myDefaultGatewayIp', type=str)
    parser.add_argument('--nuage-myDefaultGatewayMac', required=True, help='The MAC address of the Gateway.', dest='nuage_myDefaultGatewayMac', type=str)
    parser.add_argument('--nuage-mySubnetAddress', required=True, help='Network address of the L2Domain / L2Domain template defined.', dest='nuage_mySubnetAddress', type=str)
    parser.add_argument('--nuage-mySubnetMask', required=True, help='Netmask of the L2Domain / L2Domain template defined', dest='nuage_mySubnetMask', type=str)
       
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
    nuage_myDomainTemplate      = args.nuage_myDomainTemplate
    nuage_myDomain              = args.nuage_myDomain
    nuage_myDomainDesc          = args.nuage_myDomainDesc
    nuage_myDefaultGatewayIp    = args.nuage_myDefaultGatewayIp
    nuage_myDefaultGatewayMac   = args.nuage_myDefaultGatewayMac
    nuage_mySubnetAddress       = args.nuage_mySubnetAddress
    nuage_mySubnetMask          = args.nuage_mySubnetMask
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
    nuage_myDomainTemplate      = 'L3_PXY-RBD_FRT'
    nuage_myDomain     = 'myTestDomain'
    nuage_myDomainDesc = 'DMZ TEST'
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
    
    myFilter = "name == \"" + nuage_myDomainTemplate +"\""
    myDomainTemplate = myEnterprise.l2_domain_templates.get_first(filter = myFilter)
    print ('Domain Template : %s' % (myDomainTemplate.name))
    
    myNewDomain = vsdk.NUL2Domain(name        = nuage_myDomain,
                                                template_id = myDomainTemplate.id,
                                                description = nuage_myDomainDesc,
                                                # gateway = nuage_myDefaultGatewayIp,
                                                # gateway_mac_address = nuage_myDefaultGatewayMac,
                                                # address = nuage_mySubnetAddress,
                                                # netmask = nuage_mySubnetMask,
                                                dhcp_managed = False,
                                                dpi = 'DISABLED',
                                                encryption = 'DISABLED',
                                                entity_scope = 'ENTERPRISE',
                                                stretched = False,                                
                                                multicast = 'DISABLED',
                                                ip_type = 'IPV4',
                                                external_id = MyCmsName
                                               )
    print ('L2Domain %s is created.' % (myNewDomain.name))

    myEnterprise.create_child(myNewDomain)
    print ('L2Domain %s id: %s' % (myNewDomain.name, myNewDomain.id))
    logger.warning('L2Domain %s id %s is created' % (myNewDomain.name, myNewDomain.id))

# Start program
if __name__ == "__main__":
    main()