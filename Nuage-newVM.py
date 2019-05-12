# -*- coding: utf-8 -*-
"""
--- Object ---
Create a VM for a Virtual Machine

--- Usage ---
Run 'python Nuage-newVM.py -h' for an overview

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
    parser.add_argument('--nuage-myDomain', required=True, help='The name of the Domain to which the baremetal or Appliance should be connected', dest='nuage_myDomain', type=str, action='append')
    parser.add_argument('--nuage-myZone', required=False, help='For L3 DOMAIN only, the name of the Zone to which the baremetal or Appliance should be connected', dest='nuage_myZone', type=str, action='append')
    parser.add_argument('--nuage-mySubnetName', required=False, help='For L3 DOMAIN only, the name of the Subnet to which the baremetal or Appliance should be connected', dest='nuage_mySubnetName', type=str, action='append')
    parser.add_argument('--nuage-myVPortName', required=True, help='Name of the Virtual Port on dVRS', dest='nuage_myVPortName', type=str, action='append')
    parser.add_argument('--nuage-myVMname', required=True, help='Name of the Virtual Machine', dest='nuage_myVMname', type=str)
    parser.add_argument('--nuage-myVMuuid', required=True, help='Unique Identifier of the Virtual Machine on vCenter', dest='nuage_myVMuuid', type=str)
    parser.add_argument('--nuage-myVMIfMac', required=True, help='Static MAC of the VM interface', dest='nuage_myVMIfMac', type=str, action='append')
    parser.add_argument('--nuage-myVMIfIp', required=True, help='Static IP of the VM interface', dest='nuage_myVMIfIp', type=str, action='append')
 
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
    nuage_myZone = []
    if args.nuage_myZone:
        nuage_myZone = args.nuage_myZone
    nuage_mySubnetName = []
    if args.nuage_mySubnetName:
        nuage_mySubnetName = args.nuage_mySubnetName
    nuage_myVPortName   = args.nuage_myVPortName
    nuage_myVMname      = args.nuage_myVMname
    nuage_myVMuuid      = args.nuage_myVMuuid
    nuage_myVMIfIp = []
    if args.nuage_myVMIfIp:
        nuage_myVMIfIp = args.nuage_myVMIfIp
    nuage_myVMIfMac     = args.nuage_myVMIfMac
    MyCmsName = 'CMS-scripts'
    
    # Logging settings
    logger = setup_logging(debug, verbose, log_file)
           
    # Getting user password for Nuage connection
    if nuage_password is None:
        logger.debug('No command line Nuage password received, requesting Nuage password from user')
        nuage_password = getpass.getpass(prompt='Enter password for Nuage host %s for user %s: ' % (nuage_host, nuage_username))
    
    # Connection to VSD
    nc = start_nuage_connection(nuage_host, nuage_port, nuage_username, nuage_password, nuage_organization, logger)
    
    # lookup Enterprise
    myFilter = "name == \"" + nuage_myEnterprise +"\""
    myEnterprise = nc.enterprises.get_first(filter = myFilter)
    print ('Entreprise : %s' % myEnterprise.name)

    # Sanity checks
    if  len(nuage_myDomain) > 0 and len(nuage_myDomain) != len(nuage_myVMIfMac) :
        print ('!!!>error: incorrect arguments. Each interface must be in a different subnet, zone, domain.<!!!')
        logger.critical('Specific to AES project. Each interface must be in a different subnet, zone, domain.')
        return 1
    if  len(nuage_myVPortName) > 0 and len(nuage_myVPortName) != len(nuage_myVMIfMac) :
        print ('!!!>error: incorrect arguments. Each interface must be in a different subnet, zone, domain.<!!!')
        logger.critical('Specific to AES project. Each interface must be in a different subnet, zone, domain.')
        return 1
    
    myFilter = "name == \"" + nuage_myDomain[0] +"\""
    myDomain= myEnterprise.domains.get_first(filter = myFilter)
    if myDomain:
        print ('|>---------- L3 DOMAIN ----------<')
        domain_type = "L3_DOMAIN"
        if  len(nuage_myZone) > 0 and len(nuage_myZone) != len(nuage_myVMIfMac) :
            print ('!!!>error: incorrect arguments. Each interface must be in a different subnet, zone, domain.<!!!')
            logger.critical('Specific to AES project. Each interface must be in a different subnet, zone, domain.')
            return 1
        if  len(nuage_mySubnetName) > 0 and len(nuage_mySubnetName) != len(nuage_myVMIfMac) :
            print ('!!!>error: incorrect arguments. Each interface must be in a different subnet, zone, domain.<!!!')
            logger.critical('Specific to AES project. Each interface must be in a different subnet, zone, domain.')
            return 1
        if  len(nuage_myVMIfIp) > 0 and len(nuage_myVMIfIp) != len(nuage_myVMIfMac) :
            print ('!!!>error: incorrect arguments. Each interface must be in a different subnet, zone, domain.<!!!')
            logger.critical('Specific to AES project. Each interface must be in a different subnet, zone, domain.')
            return 1
    else:
        myDomain= myEnterprise.l2_domains.get_first(filter = myFilter)
        print ('|>---------- L2 DOMAIN ----------<')
        domain_type = "L2_DOMAIN"
        
    # Handling each mac/subnet combination and creating the necessary VM Interfaces
    vports = []
    vm_interfaces = []
    for mac in nuage_myVMIfMac:
        index = nuage_myVMIfMac.index(mac)
        domain_name = nuage_myDomain[index]
        zone_name = nuage_myZone[index]
        subnet_name = nuage_mySubnetName[index]
        vport_name = nuage_myVPortName[index]
        
        # lookup Domain
        myFilter = "name == \"" + domain_name +"\""
        if domain_type == "L3_DOMAIN":
            myDomain= myEnterprise.domains.get_first(filter = myFilter)
        else :
            myDomain= myEnterprise.l2_domains.get_first(filter = myFilter)
        print ('+-- Domain : %s' % (myDomain.name))
        
        # lookup Zone
        if domain_type == "L3_DOMAIN":
            myFilter = "name == \"" + zone_name +"\""
            myZone = myDomain.zones.get_first(filter = myFilter)
            print ('|   +-- Zone : %s' % (myZone.name))

        # lookup Subnet
        if domain_type == "L3_DOMAIN":
            myFilter = "name == \"" + subnet_name +"\""
            mySubnet = myZone.subnets.get_first(filter = myFilter)
            print ('|   |   +-- Subnet : %s - %s %s' % (mySubnet.name, mySubnet.address, mySubnet.netmask))

        # Get vPort
        myFilter = "name == \"" + vport_name +"\""
        if domain_type == "L3_DOMAIN":
            myVPort = myZone.vports.get_first(filter = myFilter)
        else:
            # L2_DOMAIN
            cur_domain
            myVPort = cur_domain.vports.get_first(filter = myFilter)
        print ('|   |   |  +-- vPort : %s' % (myVPort.name))
        vports.append(myVPort)
        
        # Creating VMInterface
        if domain_type == "L3_DOMAIN":
            vm_interface = vsdk.NUVMInterface(name='eth%s' % (index + 1),
                                              vport_id=myVPort.id,
                                              mac=mac,
                                              external_id=MyCmsName,
                                              ip_address = nuage_myVMIfIp[index]
                                             )
        else:
            # L2_DOMAIN
            vm_interface = vsdk.NUVMInterface(name='eth%s' % (index + 1),
                                              vport_id=myVPort.id,
                                              mac=mac,
                                              external_id=MyCmsName
                                             )
        vm_interfaces.append(vm_interface)
    
    # Creating VM
    logger.info('Creating VM %s with UUID %s' % (nuage_myVMname, nuage_myVMuuid))
    vm = vsdk.NUVM(name=nuage_myVMname,
                   uuid=nuage_myVMuuid,
                   interfaces=vm_interfaces,
                  external_id=MyCmsName
                  )
    try:
        logger.debug('Trying to save VM %s.' % nuage_myVMname)
        nc.create_child(vm)
        print ('VM %s is created by user %s.' % (vm.name, vm.user_name))
    except Exception as e:
        logger.critical('VM %s can not be created because of error %s' % (nuage_myVMname, str(e)))
        print ('!!!> error: VM %s is NOT %s because of error %s<!!!' % (nuage_myVMname, str(e)))

# Start program
if __name__ == "__main__":
    main()