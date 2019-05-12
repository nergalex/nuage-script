# -*- coding: utf-8 -*-
"""
--- Object ---
Create a Port of a Gateway

--- Usage ---
Run 'python Nuage-newPort.py -h' for an overview

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
    parser.add_argument('--nuage-myGateway', required=False, help='The name of the Gateway Hardware VTEP', dest='nuage_myGateway', type=str)
    parser.add_argument('--nuage-myPortName', required=False, help='Name of the Port', dest='nuage_myPortName', type=str)
    parser.add_argument('--nuage-myPortDesc', required=False, help='A description of the Port', dest='nuage_myPortDesc', type=str)
    parser.add_argument('--nuage-myPortPhysicalName', required=False, help='Identifier of the Port on the switch', dest='nuage_myPortPhysicalName', type=str)

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
    nuage_myGateway     = args.nuage_myGateway
    nuage_myPortName    = args.nuage_myPortName
    nuage_myPortDesc    = args.nuage_myPortDesc
    nuage_myPortPhysicalName  = args.nuage_myPortPhysicalName
    MyCmsName = 'CMS-scripts'
    
    """
    # Bouchonnage arguments
    debug               = False
    verbose             = False
    log_file            = 'Nuage-log.txt'
    nuage_organization  = 'AES'
    nuage_host          = '127.1.1.2'
    nuage_port          = '8443'
    nuage_password      = 'Sncfaes2017!'
    nuage_username      = 'csproot'
    nuage_organization = 'csp'
    nuage_myGateway     = 'EPART513V00'
    nuage_myPortName    = 'Appliance_primaire_simulation'
    nuage_myPortDesc    = 'Test_vlan_all_DESCRIPTION'
    nuage_myPortPhysicalName  = 'EPART513V00:::Bridge-Aggregation298'
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
    myFilter = "name == \"" + nuage_myGateway +"\""
    myGateway = nc.gateways.get_first(filter = myFilter)
    print('Gateway : %s' % myGateway.name)
    
    myNewPort = vsdk.NUPort(name = nuage_myPortName,
                                                permitted_action = 'ALL',
                                                description = nuage_myPortDesc,
                                                physical_name = nuage_myPortPhysicalName,
                                                entity_scope = 'GLOBAL',
                                                port_type = 'ACCESS',
                                                is_resilient = False,
                                                vlan_range = '0-4095',
                                                external_id = MyCmsName
                                               )
    print ('Port %s is created.' % (myNewPort.name))

    myGateway.create_child(myNewPort)
    print ('Port %s id: %s' % (myNewPort.name, myNewPort.id))
    
    logger.warning('Port %s id: %s' % (myNewPort.name, myNewPort.id))
    
# Start program
if __name__ == "__main__":
    main()