# -*- coding: utf-8 -*-
"""
--- Object ---
Set a parameter for all objects that matches your filter

--- Usage ---
Run 'python Nuage-setMassiveParameter.py -h' for an overview

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

    parser = argparse.ArgumentParser(description="Set a parameter for all objects that matches your filter.")
    parser.add_argument('-d', '--debug', required=False, help='Enable debug output', dest='debug', action='store_true')
    parser.add_argument('-l', '--log-file', required=True, help='File to log to (default = stdout)', dest='logfile', type=str)
    parser.add_argument('--nuage-organization', required=True, help='The organization with which to connect to the Nuage VSD/SDK host', dest='nuage_organization', type=str)
    parser.add_argument('--nuage-host', required=True, help='The Nuage VSD/SDK endpoint to connect to', dest='nuage_host', type=str)
    parser.add_argument('--nuage-port', required=True, help='The Nuage VSD/SDK server port to connect to (default = 8443)', dest='nuage_port', type=int, default=8443)
    parser.add_argument('--nuage-password', required=False, help='The password with which to connect to the Nuage VSD/SDK host. If not specified, the user is prompted at runtime for a password', dest='nuage_password', type=str)
    parser.add_argument('--nuage-user', required=True, help='The username with which to connect to the Nuage VSD/SDK host', dest='nuage_username', type=str)
    parser.add_argument('-v', '--verbose', required=False, help='Enable verbose output', dest='verbose', action='store_true')
    parser.add_argument('--nuage-domain_filter', required=False, help='Domain name', dest='nuage_domain_filter', type=str)
    parser.add_argument('--nuage-vm_filter', required=False, help='VM name', dest='nuage_vm_filter', type=str)
    parser.add_argument('--nuage-set_vport_active', required=False, help='Indicates if this vport is up or down', dest='nuage_set_vport_active', type=str, choices=[u'UP', u'DOWN'])
    parser.add_argument('--evaluate', required=False, help='Do not update parameter', dest='evaluate', action='store_true')
    
    args = parser.parse_args()
    return args

def clear(logger):
    """
    Clears the terminal
    """
    if logger:
        logger.debug('Clearing terminal')
    os.system(['clear', 'cls'][os.name == 'nt'])

def setVPortActive (evaluate, vport, vm, nuage_vm_filter, nuage_set_vport_active, logger):
    if nuage_vm_filter in vm.name:
        if evaluate:
            logger.warning('evaluate function setVPortActive for vPort %s > VM %s : old value %s => new value %s' % (vport.name, vm.name, vport.active, nuage_set_vport_active))
        else:
            if nuage_set_vport_active.lower() == 'up':
                oldvalue = vport.active
                vport.active = True
            else:
                oldvalue = vport.active
                vport.active = False
            vport.save()
            logger.warning('executed function setVPortActive for vPort %s > VM %s : old value %s => new value %s' % (vport.name, vm.name, oldvalue, vport.active))
        
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
    # ' nuage_domain_filter
    nuage_domain_filter    = None
    if args.nuage_domain_filter:
        nuage_domain_filter = args.nuage_domain_filter
    # ' nuage_vm_filter 
    nuage_vm_filter    = None
    if args.nuage_vm_filter:
        nuage_vm_filter = args.nuage_vm_filter
    # ' nuage_vm_filter 
    nuage_vm_filter    = None
    if args.nuage_vm_filter:
        nuage_vm_filter = args.nuage_vm_filter
    # ' nuage_set_vport_active 
    nuage_set_vport_active    = None
    if args.nuage_set_vport_active:
        nuage_set_vport_active = args.nuage_set_vport_active
    # ' evaluate
    evaluate    = None
    if args.evaluate:
        evaluate = args.evaluate
        
    # Logging settings
    logger = setup_logging(debug, verbose, log_file)
        
    # Getting user password for Nuage connection
    if nuage_password is None:
        logger.debug('No command line Nuage password received, requesting Nuage password from user')
        nuage_password = getpass.getpass(prompt='Enter password for Nuage host %s for user %s: ' % (nuage_host, nuage_username))
    
    # Connection to VSD
    nc = start_nuage_connection(nuage_host, nuage_port, nuage_username, nuage_password, nuage_organization, logger)

    # Execute action
    for cur_ent in nc.enterprises.get():
        print('\n Enterprise %s' % cur_ent.name)
        
        # L3 DOMAIN
        print ('|>---------- L3 DOMAIN ----------<') 
        for cur_domain in cur_ent.domains.get():
            if (nuage_domain_filter and nuage_domain_filter in cur_domain.name) or (not nuage_domain_filter):
                print('+-- L3 Domain: %s' % cur_domain.name)
                for cur_zone in cur_domain.zones.get():
                    print ('|  +-- Zone: %s' % cur_zone.name)
                    for cur_subnet in cur_zone.subnets.get():
                        print('|  |  +-- Subnets: %s - %s %s' % (cur_subnet.name, cur_subnet.address, cur_subnet.netmask))
                        for cur_vport in cur_subnet.vports.get():
                            print ('|  |  |  +-- vPort: %s %s active %s' % (cur_vport.name, cur_vport.description, cur_vport.active))          
                            for cur_VM in cur_vport.vms.get():
                                if (nuage_vm_filter and nuage_vm_filter in cur_VM.name) or (not nuage_vm_filter):
                                    print ('|  |  |  |  +-- VM: %s' % (cur_VM.name))
                                    if nuage_set_vport_active:
                                        setVPortActive (evaluate, cur_vport, cur_VM, nuage_vm_filter, nuage_set_vport_active, logger)
                print ('|')
            
        # L2 DOMAIN
        print ('|>---------- L2 DOMAIN ----------<') 
        for cur_domain in cur_ent.l2_domains.get():
            if (nuage_domain_filter and nuage_domain_filter in cur_domain.name) or (not nuage_domain_filter):
                print('+-- L2 Domain: %s' % cur_domain.name)
                for cur_vport in cur_domain.vports.get():
                    print ('|  +-- vPort: %s %s active %s' % (cur_vport.name, cur_vport.description, cur_vport.active))
                    for cur_VM in cur_vport.vms.get():
                        if (nuage_vm_filter and nuage_vm_filter in cur_VM.name) or (not nuage_vm_filter):
                            print ('|  |  +-- VM: %s' % (cur_VM.name))
                            if nuage_set_vport_active:
                                setVPortActive (evaluate, cur_vport, cur_VM, nuage_vm_filter, nuage_set_vport_active, logger)
                print ('|')

# Start program
if __name__ == "__main__":
    main()