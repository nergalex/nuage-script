# -*- coding: utf-8 -*-
"""
--- Object ---
Fetch a Subnet

--- Usage ---
Run 'python Nuage-getSubnet.py -h' for an overview

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
    parser.add_argument('--nuage-myEnterprise', required=False, help='The Nuage enterprise to which the VM (baremetal or Appliance) should be connected', dest='nuage_myEnterprise', type=str)
    parser.add_argument('-v', '--verbose', required=False, help='Enable verbose output', dest='verbose', action='store_true')
    parser.add_argument('--nuage-myDomain', required=False, help='The name of the Nuage L3Domain to which the VM (baremetal or Appliance) should be connected', dest='nuage_myDomain', type=str)
    parser.add_argument('--nuage-myZone', required=False, help='The name of the Nuage Zone to which the VM (baremetal or Appliance) should be connected', dest='nuage_myZone', type=str)
    parser.add_argument('--nuage-mySubnetName', required=False, help='The name of the Nuage Subnet to which the VM (baremetal or Appliance) should be connected', dest='nuage_mySubnetName', type=str)
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
    nuage_myZone        = args.nuage_myZone
    nuage_mySubnetName  = args.nuage_mySubnetName
    
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
    nuage_myDomain     = 'L2_PXY-RBD_FRT'
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
    
    myFilter = "name == \"" + nuage_myDomain +"\""
    myDomain= myEnterprise.domains.get_first(filter = myFilter)
    print ('+-- Domain %s :' % (myDomain.name))
    
    myFilter = "name == \"" + nuage_myZone +"\""
    myZone = myDomain.zones.get_first(filter = myFilter)
    print ('|   +-- Zone %s :' % (myZone.name))
    
    myFilter = "name == \"" + nuage_mySubnetName +"\""
    mySubnet = myZone.subnets.get_first(filter = myFilter)
    print ('|   |   +-- Subnet %s :' % (mySubnet.name))
    print ('|   |   |   +-- id: %s' % (mySubnet.id))
    print ('|   |   |   +-- gateway: %s' % (mySubnet.gateway))
    print ('|   |   |   +-- network: %s %s' % (mySubnet.address, mySubnet.netmask))
    
    for cur_vport in mySubnet.vports.get():
        print ('|   |   |   +-- vPort: %s %s' % (cur_vport.name, cur_vport.description))
        print ('|   |   |   |   +-- system_type: %s' % (cur_vport.system_type))
        # print ('|   |   |   |   +-- active: %s' % (cur_vport.active))

        for cur_HostIf in cur_vport.host_interfaces.get():
            print ('|   |   |   |   +-- Host Interface: host %s ip %s mac %s' % (cur_HostIf.name, cur_HostIf.ip_address, cur_HostIf.mac))
       
        for cur_Vip in cur_vport.virtual_ips.get():
            print ('|   |   |   |   +-- VIP: %s mac %s' % (cur_Vip.virtual_ip, cur_Vip.mac))
        
        for cur_VM in cur_vport.vms.get():
            for cur_vmIf in cur_VM.vm_interfaces.get():
                print ('|   |   |   |   +-- VM Interface : vm %s if %s ip %s mac %s' % (cur_VM.name, cur_vmIf.name, cur_vmIf.ip_address, cur_vmIf.mac))
        """        
        for cur_ACE in cur_vport.egress_acl_entry_templates.get():
            print ('|   |   |   |   +-- Egress ACE: %s - %s' % (cur_ACE.acl_template_name, cur_ACE.description))
            print ('|   |   |   |   |   +-- action: %s' % (cur_ACE.action))
            print ('|   |   |   |   |   +-- location_type: %s' % (cur_ACE.location_type))
            print ('|   |   |   |   |   +-- ether_type: %s' % (cur_ACE.ether_type))
            print ('|   |   |   |   |   +-- stateful: %s' % (cur_ACE.stateful))
            print ('|   |   |   |   |   +-- dscp: %s' % (cur_ACE.dscp))
            print ('|   |   |   |   |   +-- parent_type: %s' % (cur_ACE.parent_type))
            
        for cur_ACE in cur_vport.egress_acl_entry_templates.get():
            print ('|   |   |   |   +-- Ingress ACE: %s - %s' % (cur_ACE.acl_template_name, cur_ACE.description))
            print ('|   |   |   |   |   +-- action: %s' % (cur_ACE.action))
            print ('|   |   |   |   |   +-- location_type: %s' % (cur_ACE.location_type))
            print ('|   |   |   |   |   +-- ether_type: %s' % (cur_ACE.ether_type))
            print ('|   |   |   |   |   +-- stateful: %s' % (cur_ACE.stateful))
            print ('|   |   |   |   |   +-- dscp: %s' % (cur_ACE.dscp))
            print ('|   |   |   |   |   +-- parent_type: %s' % (cur_ACE.parent_type))
        """   
            # Start program
if __name__ == "__main__":
    main()