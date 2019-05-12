# -*- coding: utf-8 -*-
"""
--- Object ---
Fetch all baremetal in your organization

--- Usage ---
Run 'python Nuage-getBaremetal.py -h' for an overview

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

    parser = argparse.ArgumentParser(description="Fetch a DOMAIN template.")
    parser.add_argument('-d', '--debug', required=False, help='Enable debug output', dest='debug', action='store_true')
    parser.add_argument('-l', '--log-file', required=False, help='File to log to (default = stdout)', dest='logfile', type=str)
    parser.add_argument('--nuage-organization', required=True, help='The organization with which to connect to the Nuage VSD/SDK host', dest='nuage_organization', type=str)
    parser.add_argument('--nuage-host', required=True, help='The Nuage VSD/SDK endpoint to connect to', dest='nuage_host', type=str)
    parser.add_argument('--nuage-port', required=False, help='The Nuage VSD/SDK server port to connect to (default = 8443)', dest='nuage_port', type=int, default=8443)
    parser.add_argument('--nuage-password', required=False, help='The password with which to connect to the Nuage VSD/SDK host. If not specified, the user is prompted at runtime for a password', dest='nuage_password', type=str)
    parser.add_argument('--nuage-user', required=True, help='The username with which to connect to the Nuage VSD/SDK host', dest='nuage_username', type=str)
    parser.add_argument('-v', '--verbose', required=False, help='Enable verbose output', dest='verbose', action='store_true')
    parser.add_argument('--nuage-L2Domain_filter', required=False, help='String in L2 Domain name', dest='nuage_l2domain', type=str)
    parser.add_argument('--nuage-L3Domain_filter', required=False, help='String in L3 Domain name', dest='nuage_l3domain', type=str)
    
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
    nuage_l2domain            = None
    if args.nuage_l2domain:
        nuage_l2domain        = args.nuage_l2domain
    nuage_l3domain            = None
    if args.nuage_l3domain:
        nuage_l3domain        = args.nuage_l3domain
        
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
    logger.warning('>type>Enterprise>Domain>Domain_type>Zone>Subnet>vPort_name>vport_type>vport_subtype>name>mac>ip>vlanid')
    for cur_ent in nc.enterprises.get():
        print('\n Enterprise %s' % cur_ent.name)
        for cur_domain in cur_ent.domains.get():
            if nuage_l3domain and nuage_l3domain in cur_domain.name:
                print('+-- Domain: %s' % cur_domain.name)
                for cur_zone in cur_domain.zones.get():
                    print ('|  +-- Zone: %s' % cur_zone.name)
                    for cur_subnet in cur_zone.subnets.get():
                        print('|  |  +-- Subnets: %s - %s %s gw %s' % (cur_subnet.name, cur_subnet.address, cur_subnet.netmask, cur_subnet.gateway))
                        for cur_vport in cur_subnet.vports.get():
                            print ('|  |  |  +-- vPort: %s %s' % (cur_vport.name, cur_vport.description))
                            for cur_HostIf in cur_vport.host_interfaces.get():
                                print ('|  |  |  |  +-- Host Interface: %s ip %s mac %s' % (cur_HostIf.name, cur_HostIf.ip_address, cur_HostIf.mac))
                                logger.warning('>host>%s>%s>L3_DOMAIN>%s>%s>%s>%s>%s>%s>%s>%s>%s' % (cur_ent.name, cur_domain.name, cur_zone.name, cur_subnet.name, cur_vport.name, cur_vport.type, cur_vport.sub_type,cur_HostIf.name, cur_HostIf.mac, cur_HostIf.ip_address, cur_vport.vlanid))
                            cur_HostIf = 'none'
                            for cur_Vip in cur_vport.virtual_ips.get():
                                print ('|  |  |  |  +-- VIP: %s mac %s' % (cur_Vip.virtual_ip, cur_Vip.mac)) 
                                logger.warning('>vip>%s>%s>L3_DOMAIN%s>>%s>%s>%s>%s>>%s>%s>' % (cur_ent.name, cur_domain.name, cur_zone.name, cur_subnet.name, cur_vport.name, cur_vport.type, cur_vport.sub_type, cur_Vip.mac, cur_Vip.virtual_ip))
                            cur_Vip = 'none'
                        cur_vport = 'none'
                    cur_subnet = 'none'
                cur_zone = 'none'
        print ('|')
        for cur_domain in cur_ent.l2_domains.get():
            if nuage_l2domain and nuage_l2domain in cur_domain.name:
                print('+-- Domain: %s' % cur_domain.name)
                for cur_vport in cur_domain.vports.get():
                    print ('|  |  |  +-- vPort: %s %s' % (cur_vport.name, cur_vport.description))
                    for cur_HostIf in cur_vport.host_interfaces.get():
                        print ('|  |  |  |  +-- Host Interface: %s ip %s mac %s' % (cur_HostIf.name, cur_HostIf.ip_address, cur_HostIf.mac))
                        logger.warning('>host>%s>%s>L2_DOMAIN>none>none>%s>%s>%s>%s>%s>%s>%s' % (cur_ent.name, cur_domain.name, cur_vport.name, cur_vport.type, cur_vport.sub_type, cur_HostIf.name, cur_HostIf.mac, cur_HostIf.ip_address, cur_vport.vlanid))
                    for cur_Vip in cur_vport.virtual_ips.get():
                        print ('|  |  |  |  +-- VIP: %s' % (cur_Vip.virtual_ip)) 
                        logger.warning('>vip>%s>%s>L2_DOMAIN>none>none>%s>%s>%s>>%s>%s>' % (cur_ent.name, cur_domain.name, cur_vport.name, cur_vport.type, cur_vport.sub_type, cur_Vip.mac, cur_Vip.virtual_ip))
        print ('|')

# Start program
if __name__ == "__main__":
    main()