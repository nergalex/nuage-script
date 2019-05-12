# -*- coding: utf-8 -*-
"""
--- Object ---
Delete a host interface for a baremetal or a physical appliance into a L2 DOMAIN

--- Usage ---
Run 'python Nuage-deleteL2HostInterface.py -h' for an overview

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
    parser.add_argument('-l', '--log-file', required=True, help='File to log to (default = stdout)', dest='logfile', type=str)
    parser.add_argument('--nuage-organization', required=True, help='The organization with which to connect to the Nuage VSD/SDK host', dest='nuage_organization', type=str)
    parser.add_argument('--nuage-host', required=True, help='The Nuage VSD/SDK endpoint to connect to', dest='nuage_host', type=str)
    parser.add_argument('--nuage-port', required=True, help='The Nuage VSD/SDK server port to connect to (default = 8443)', dest='nuage_port', type=int, default=8443)
    parser.add_argument('--nuage-password', required=True, help='The password with which to connect to the Nuage VSD/SDK host. If not specified, the user is prompted at runtime for a password', dest='nuage_password', type=str)
    parser.add_argument('--nuage-user', required=True, help='The username with which to connect to the Nuage VSD/SDK host', dest='nuage_username', type=str)
    parser.add_argument('--nuage-myEnterprise', required=True, help='The Nuage enterprise to which the VM (baremetal or Appliance) should be connected', dest='nuage_myEnterprise', type=str)
    parser.add_argument('-v', '--verbose', required=False, help='Enable verbose output', dest='verbose', action='store_true')
    parser.add_argument('--nuage-myDomain', required=True, help='The name of the Domain to which the baremetal or Appliance should be connected', dest='nuage_myDomain', type=str)
    parser.add_argument('--nuage-myVPortName', required=True, help='Name of the Virtual Port on dVRS', dest='nuage_myVPortName', type=str)
    parser.add_argument('--nuage-myVPortType', required=True, help='Type of the Virtual Port on dVRS', dest='nuage_myVPortType', type=str, choices=[u'HOST', u'BRIDGE', u'VM'])
    parser.add_argument('--nuage-myHostIfName', required=True, help='Name of the appliance interface', dest='nuage_myHostIfName', type=str)
    
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
    nuage_myVPortName   = args.nuage_myVPortName
    nuage_myHostIfName  = args.nuage_myHostIfName
    nuage_myVPortType   = args.nuage_myVPortType
    
    """
    # Bouchonnage arguments
    debug               = False
    verbose             = False
    log_file            = 'Nuage-log.txt'
    nuage_organization  = 'AES'
    nuage_host          = '127.1.1.2'
    nuage_port          = '8443'
    nuage_password      = 'test2018'
    nuage_username      = 'admin-test'
    nuage_organization  = 'TEST'
    nuage_myEnterprise = 'TEST'
    nuage_myDomain = 'Lille_vAES-1_DMZ-1_PXY-RBD_FRT'
    nuage_myZone = 'Interco'
    nuage_mySubnetName = 'interco-ADC'
    nuage_myVPortName   = 'EPPLB001V06_vlan1000'
    nuage_myHostIfMac = 'f4:15:63:2c:70:0b'
    nuage_myHostIfIp = '10.189.64.1'
    nuage_myHostIfName = 'EPPLB001V06_vlan1000_self.static'
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
    print ('Entreprise : %s' % myEnterprise.name)
    print ('|')
    myFilter = "name == \"" + nuage_myDomain +"\""
    myDomain = myEnterprise.l2_domains.get_first(filter = myFilter)
    print ('+-- Domain : %s' % (myDomain.name))

    myFilter = "name == \"" + nuage_myVPortName +"\""
    myVPort = myDomain.vports.get_first(filter = myFilter)
    print ('|   |   |   |')
    print ('|   |   |   +-- vPort : %s - %s' % (myVPort.name, myVPort.description))
    
    myFilter = "name == \"" + nuage_myHostIfName +"\""
    if nuage_myVPortType == 'HOST':
        myHostIf = myVPort.host_interfaces.get_first(filter = myFilter)
        print ('|   |   |   |   +-- vPort type : HOST - %s' % (myVPort.type))
    if nuage_myVPortType == 'BRIDGE':
        print ('|   |   |   |   +-- vPort type : BRIDGE - %s' % (myVPort.type))
        myHostIf = myVPort.bridge_interfaces.get_first(filter = myFilter)
    HostId = myHostIf.id
    
    myHostIf.delete()

    print ('Entreprise %s > Domain %s > vPort %s > Host Interface %s is deleted : %s' % (myEnterprise.name, myDomain.name, myVPort.name, nuage_myHostIfName, HostId ))
    logger.warning ('Entreprise %s > Domain %s > vPort %s > Host Interface %s is deleted : %s' % (myEnterprise.name, myDomain.name, myVPort.name, nuage_myHostIfName, HostId ))
    
# Start program
if __name__ == "__main__":
    main()