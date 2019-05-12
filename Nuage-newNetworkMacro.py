# -*- coding: utf-8 -*-
"""
--- Object ---
Create a NetworkMacro


--- Usage ---
Run 'python Nuage-newNetworkMacro.py -h' for an overview


--- Documentation ---
none


--- Author ---
LEGRAND Aurelien <aurelien.legrand@hpe.com>


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
    parser.add_argument('--nuage-myEnterprise', required=True, help='The Nuage enterprise to which the VM (baremetal or Appliance) should be connected', dest='nuage_myEnterprise', type=str)
    parser.add_argument('-v', '--verbose', required=False, help='Enable verbose output', dest='verbose', action='store_true')
    parser.add_argument('--nuage-myNetworkMacroName', required=False, help='The name of the Nuage NetworkMacro that should be created', dest='nuage_myNetworkMacroName', type=str)
    parser.add_argument('--nuage-myNetworkMacroAddress', required=False, help='The prefix of the Nuage NetworkMacro that should be created', dest='nuage_myNetworkMacroAddress', type=str)
    parser.add_argument('--nuage-myNetworkMacroMask', required=False, help='The mask of the Nuage NetworkMacro that should be created (e.g. 255.255.255.0)', dest='nuage_myNetworkMacroMask', type=str)
    
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
    nuage_myNetworkMacroName  = args.nuage_myNetworkMacroName
    nuage_myNetworkMacroAddress  = args.nuage_myNetworkMacroAddress
    nuage_myNetworkMacroMask  = args.nuage_myNetworkMacroMask
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
        
    myNewNetworkMacro = vsdk.NUEnterpriseNetwork(name = nuage_myNetworkMacroName,
                                                ip_type = 'IPV4',
                                                address = nuage_myNetworkMacroAddress,
                                                netmask = nuage_myNetworkMacroMask,
                                                external_id = MyCmsName
                                               )
    print ('Network Macro %s is created.' % (myNewNetworkMacro.name))


    myEnterprise.create_child(myNewNetworkMacro)
    print ('Network Macro %s id: %s' % (myNewNetworkMacro.name, myNewNetworkMacro.id))
    
    logger.warning('Network Macro %s id: %s' % (myNewNetworkMacro.name, myNewNetworkMacro.id))


# Start program
if __name__ == "__main__":
    main()