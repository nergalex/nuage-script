# -*- coding: utf-8 -*-
"""
--- Object ---
Set Maintenance Mode for all instances in your organization

--- Usage ---
Run 'python Nuage-setDomainMaintenance.py -h' for an overview

--- Documentation ---
none

--- Author ---
DA COSTA Alexis <alexis.dacosta@bt.com>

--- Examples ---

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

    parser = argparse.ArgumentParser(description="Fetch a DOMAIN template.")
    parser.add_argument('-d', '--debug', required=False, help='Enable debug output', dest='debug', action='store_true')
    parser.add_argument('-l', '--log-file', required=False, help='File to log to (default = stdout)', dest='logfile', type=str)
    parser.add_argument('--nuage-organization', required=True, help='The organization with which to connect to the Nuage VSD/SDK host', dest='nuage_organization', type=str)
    parser.add_argument('--nuage-host', required=True, help='The Nuage VSD/SDK endpoint to connect to', dest='nuage_host', type=str)
    parser.add_argument('--nuage-port', required=False, help='The Nuage VSD/SDK server port to connect to (default = 8443)', dest='nuage_port', type=int, default=8443)
    parser.add_argument('--nuage-password', required=False, help='The password with which to connect to the Nuage VSD/SDK host. If not specified, the user is prompted at runtime for a password', dest='nuage_password', type=str)
    parser.add_argument('--nuage-user', required=True, help='The username with which to connect to the Nuage VSD/SDK host', dest='nuage_username', type=str)
    parser.add_argument('-v', '--verbose', required=False, help='Enable verbose output', dest='verbose', action='store_true')
    parser.add_argument('--nuage-domain_filter', required=False, help='Domain name', dest='nuage_domain_filter', type=str)
    parser.add_argument('--nuage-domain_maintenance_mode', required=False, help='Maintenance Mode', dest='nuage_domain_maintenance_mode', type=str, choices=[u'DISABLED', u'ENABLED'])
    
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
    nuage_domain_filter  = args.nuage_domain_filter
    nuage_domain_maintenance_mode  = args.nuage_domain_maintenance_mode
    
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
    logger.warning('>Enterprise>Domain_type>Domain>Zone>Subnet>vPort>VM_name>VM_uuid>VMinterface_mac>VMinterface_ip_address')
    for cur_ent in nc.enterprises.get():
        print('\n Enterprise %s' % cur_ent.name)
        
        # L3 DOMAIN
        print ('|>---------- L3 DOMAIN ----------<') 
        for cur_domain in cur_ent.domains.get():
            if (nuage_domain_filter and nuage_domain_filter in cur_domain.name) or (not nuage_domain_filter):
                print('+-- L3 Domain: %s' % cur_domain.name)
                if (nuage_domain_maintenance_mode):
                    print('|   +-- State before: %s' % cur_domain.maintenance_mode)
                    print('|   +-- Passage en mode: %s' % nuage_domain_maintenance_mode)
                    cur_domain.maintenance_mode = nuage_domain_maintenance_mode
                    cur_domain.save()
                    print('|   +-- State after: %s' % cur_domain.maintenance_mode)
                    print('|')
                else:
                    print('|   +-- State : %s' % cur_domain.maintenance_mode)
                print('|')  
                
        # L2 DOMAIN
        print ('|>---------- L2 DOMAIN ----------<') 
        for cur_domain in cur_ent.l2_domains.get():
            if (nuage_domain_filter and nuage_domain_filter in cur_domain.name) or (not nuage_domain_filter):
                print('+-- L3 Domain: %s' % cur_domain.name)
                if (nuage_domain_maintenance_mode):
                    print('|   +-- State before: %s' % cur_domain.maintenance_mode)
                    print('|   +-- Passage en mode: %s' % nuage_domain_maintenance_mode)
                    cur_domain.maintenance_mode = nuage_domain_maintenance_mode
                    cur_domain.save()
                    print('|   +-- State after: %s' % cur_domain.maintenance_mode)
                    print('|')
                else:
                    print('|   +-- State : %s' % cur_domain.maintenance_mode)
                print('|')   
                        
                        
# Start program
if __name__ == "__main__":
    main()