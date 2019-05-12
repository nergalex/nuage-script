# -*- coding: utf-8 -*-
"""
--- Object ---
Get a list of all VMs for a user

--- Usage ---
Run 'python Nuage-getUserVMs.py -h' for an overview

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
    parser.add_argument('-v', '--verbose', required=False, help='Enable verbose output', dest='verbose', action='store_true')
    parser.add_argument('--nuage-hypervisor_filter', required=False, help='IP address of the hypervisor that this VM is currently running in', dest='nuage_hypervisor_filter', type=str)
    parser.add_argument('--nuage-vm_filter', required=False, help='VM name', dest='nuage_vm_filter', type=str)
    
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
    nuage_hypervisor_filter    = None
    if args.nuage_hypervisor_filter:
        nuage_hypervisor_filter = args.nuage_hypervisor_filter
    nuage_vm_filter    = None
    if args.nuage_vm_filter:
        nuage_vm_filter = args.nuage_vm_filter
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
    for cur_vm in nc.vms.get():
        if ((nuage_hypervisor_filter and nuage_hypervisor_filter in cur_vm.hypervisor_ip) and (not nuage_hypervisor_filter)) or ((nuage_vm_filter and nuage_vm_filter in cur_vm.name) or (not nuage_vm_filter)):
            print('\nVM %s - status %s' % (cur_vm.name, cur_vm.status))
            
            print('+-- VSC : show vswitch-controller virtual-machines vm-name %s detail' % (cur_vm.name))
            print('+-- UUID : %s' % (cur_vm.uuid))
            print('+-- Enterprise : %s' % cur_vm.enterprise_name)
            print('+-- Hypervisor : %s' % cur_vm.hypervisor_ip)
            print('+-- reason_type : %s' % cur_vm.reason_type)
            print('+-- resync_info : %s' % cur_vm.resync_info)
            # print('+-- entity_scope : %s' % cur_vm.entity_scope)
            print('+-- created by : %s' % cur_vm.external_id)
            print('+-- owner : %s' % cur_vm.user_name)
            # print('+-- user_id : %s' % cur_vm.user_id)
            for cur_vmif in cur_vm.vm_interfaces.get():
                print('+-- Interface %s' % (cur_vmif.name))
                print('|   +-- domain %s' % (cur_vmif.domain_name))
                print('|   +-- zone %s' % (cur_vmif.zone_name))
                print('|   +-- subnet %s' % (cur_vmif.network_name))
                print('|   +-- vPort %s' % (cur_vmif.vport_name))
                print('|   +-- mac %s' % (cur_vmif.mac))
                print('|   +-- ip_address %s / %s' % (cur_vmif.ip_address, cur_vmif.netmask))   
                print('|   +-- gateway %s' % (cur_vmif.gateway))
        
# Start program
if __name__ == "__main__":
    main()