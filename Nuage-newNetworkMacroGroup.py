# -*- coding: utf-8 -*-
"""
--- Object ---
Create a NetworkMacroGroup


--- Usage ---
Run 'python Nuage-newNetworkMacroGroup.py -h' for an overview


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
    parser.add_argument('--nuage-myNetworkMacroGroupName', required=True, help='The name of the Nuage NetworkMacroGroup that should be created', dest='nuage_myNetworkMacroGroupName', type=str)
    parser.add_argument('--nuage-myNetworkMacroGroupNetworkMacros', required=False, help='Network Macros that should be assigned to the Network Macro Group. Network Macros names should be separated by spaces', dest='nuage_myNetworkMacroGroupNetworkMacros', type=str)
    
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
    nuage_myNetworkMacroGroupName  = args.nuage_myNetworkMacroGroupName
    nuage_myNetworkMacroGroupNetworkMacros  = args.nuage_myNetworkMacroGroupNetworkMacros
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
        
    myNewNetworkMacroGroup = vsdk.NUNetworkMacroGroup(name = nuage_myNetworkMacroGroupName,
                                                     external_id = MyCmsName
                                                     )
    print ('Network Macro Group %s is created.' % (myNewNetworkMacroGroup.name))


    myEnterprise.create_child(myNewNetworkMacroGroup)
    print('Network Macro Group %s id: %s' % (myNewNetworkMacroGroup.name, myNewNetworkMacroGroup.id))
    logger.warning('Network Macro %s id: %s' % (myNewNetworkMacroGroup.name, myNewNetworkMacroGroup.id))


    if nuage_myNetworkMacroGroupNetworkMacros:
        networkMacroslist = []
        # Gets all the Networks Macros using the list of names provided
        for curr_networkMacroName in nuage_myNetworkMacroGroupNetworkMacros.split("~~"):
            myFilter = "name == \"" + curr_networkMacroName +"\""
            curr_networkMacro = myEnterprise.enterprise_networks.get_first(filter = myFilter)
            if curr_networkMacro:
                networkMacroslist.append(curr_networkMacro)
            else:
                print('Network Macro %s was not found.' % (curr_networkMacroName))
                logger.error('Network Macro %s was not found.' % (curr_networkMacroName))


        # Assign all the Network Macros found to our Network Macro Group
        myNewNetworkMacroGroup.assign(networkMacroslist, vsdk.NUEnterpriseNetwork)
    else:
        print('Network Macro Group is empty (no Network Macros assigned to this group yet)')
        logger.warning('Network Macro Group is empty (no Network Macros assigned to this group yet)')




# Start program
if __name__ == "__main__":
    main()