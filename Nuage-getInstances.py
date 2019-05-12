# -*- coding: utf-8 -*-
"""
--- Object ---
Fetch all instances in your organization

--- Usage ---
Run 'python Nuage-getInstances.py -h' for an overview

--- Documentation ---
none

--- Author ---
DA COSTA Alexis <alexis.dacosta@bt.com>

--- Examples ---

python Nuage-getInstances.py   --log-file Nuage-log.txt --nuage-organization TEST --nuage-host 127.1.1.2 --nuage-port 8443 --nuage-password test2018 --nuage-user admin-test

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
    parser.add_argument('--nuage-enterprise_filter', required=False, help='Enterprise name', dest='nuage_enterprise_filter', type=str)
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
    nuage_enterprise_filter = args.nuage_enterprise_filter
    
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
        if (nuage_enterprise_filter and nuage_enterprise_filter in cur_ent.name) or (not nuage_enterprise_filter):
            print('\n Enterprise %s' % cur_ent.name)
            # L3 DOMAIN
            print ('|') 
            print ('|>---------- L3 DOMAIN ----------<') 
            for cur_domain in cur_ent.domains.get():
                if (nuage_domain_filter and nuage_domain_filter in cur_domain.name) or (not nuage_domain_filter):
                    print('+-- L3 Domain: %s' % cur_domain.name)
                    print('|  +-- back_haul_vnid: %s' % (cur_domain.back_haul_vnid))
                
                    for cur_fip in cur_domain.floating_ips.get():
                        print ('|  +-- FIP: address=%s; assigned_object_type=%s; assigned=%s; id=%s' % (cur_fip.address, cur_fip.assigned_to_object_type, cur_fip.assigned, cur_fip.id))
                        for cur_vport in cur_fip.vports.get():
                            print ('|  |  +-- vport: name=%s' % (cur_vport.name))
                            for cur_vip in cur_vport.virtual_ips.get():
                                print ('|  |  |  +-- vip: mac=%s; address=%s; FIP_id=%s' % (cur_vip.mac, cur_vip.virtual_ip, cur_vip.associated_floating_ip_id))
                                    
                    for cur_route in cur_domain.static_routes.get():
                        print ('|  +-- Route %s %s via %s' % (cur_route.address, cur_route.netmask, cur_route.next_hop_ip))
                        
                    for cur_dhcp_option in cur_domain.dhcp_options.get():
                        print ('|  +-- DHCP type %s value %s length %s' % (cur_dhcp_option.actual_type, cur_dhcp_option.actual_values, cur_dhcp_option.length))
                        
                    print('|  |  +-- HW VTEP: display ip routing-table vpn-instance vrf%s' % (cur_domain.service_id))
                    print('|  |  +-- VSC: show vswitch-controller ip-routes enterprise "%s" domain "%s"' % (cur_ent.name, cur_domain.name))
                    
                    for cur_redir in cur_domain.redirection_targets.get():
                        print ('|  +-- redirection_target: name=%s; redundancy=%s; VNID=%s; endpoint=%s; trigger_type=%s' % (cur_redir.name, cur_redir.redundancy_enabled, cur_redir.virtual_network_id, cur_redir.end_point_type, cur_redir.trigger_type))
                        for cur_vip in cur_redir.virtual_ips.get():
                            print ('|  |  +-- vip: mac=%s; vip=%s; subnet_id=%s; vsd_id=%s' % (cur_vip.mac, cur_vip.virtual_ip, cur_vip.subnet_id, cur_vip.id))
                                
                    for cur_zone in cur_domain.zones.get():
                        print ('|  +-- Zone: %s' % cur_zone.name)
                        for cur_subnet in cur_zone.subnets.get():
                            print('|  |  +-- Subnets: %s - %s %s' % (cur_subnet.name, cur_subnet.address, cur_subnet.netmask))
                            print('|  |  |  +-- HW VTEP: dis l2vpn mac-address vsi evpn%s' % (cur_subnet.service_id))
                            print('|  |  |  +-- VSC: show vswitch-controller enterprise "%s" domain "%s" subnet "%s" detail' % (cur_ent.name, cur_domain.name, cur_subnet.name))
                            print('|  |  |  +-- VNID=%s; RD=%s; RT=%s' % (cur_subnet.vn_id, cur_subnet.route_distinguisher, cur_subnet.route_target))
                            print('|  |  |  +-- Gateway: %s - %s' % (cur_subnet.gateway, cur_subnet.gateway_mac_address))
                            for cur_vport in cur_subnet.vports.get():
                                print ('|  |  +-- vPort: %s %s' % (cur_vport.name, cur_vport.description))
                                print ('|  |  |  +-- type: %s' % (cur_vport.type))
                                if cur_vport.type == 'HOST':
                                    print ('|  |  |  +-- VSC: show vswitch-controller vports type host enterprise "%s" domain "%s" vport-name "%s"' % (cur_ent.name, cur_domain.name, cur_vport.name))
                                elif cur_vport.type == 'BRIDGE':
                                    print ('|  |  |  +-- VSC: show vswitch-controller vports type bridge enterprise "%s" domain "%s" vport-name "%s"' % (cur_ent.name, cur_domain.name, cur_vport.name))
                                else:
                                    print ('|  |  |  +-- VSC: show vswitch-controller vports type vm enterprise "%s" domain "%s" vport-name "%s"' % (cur_ent.name, cur_domain.name, cur_vport.name))

                                for cur_HostIf in cur_vport.host_interfaces.get():
                                    print ('|  |  |  +-- Host Interface: %s ip %s mac %s' % (cur_HostIf.name, cur_HostIf.ip_address, cur_HostIf.mac))
                                    
                                for cur_Vip in cur_vport.virtual_ips.get():
                                    print ('|  |  |  +-- vip=%s; mac=%s; vsd_id=%s; FIP_id=%s' % (cur_Vip.virtual_ip, cur_Vip.mac, cur_Vip.id, cur_Vip.associated_floating_ip_id))
                                    if cur_Vip.associated_floating_ip_id is not None:
                                        cur_fip = vsdk.NUFloatingIp(id=cur_Vip.associated_floating_ip_id)
                                        print ('|  |  |  |  +-- FIP: address=%s; assigned_object_type=%s; assigned=%s; id=%s' % (cur_fip.address, cur_fip.assigned_to_object_type, cur_fip.assigned, cur_fip.id))
                                    
                                for cur_VM in cur_vport.vms.get():
                                    print ('|  |  |  +-- VM=%s; status=%s; uuid=%s' % (cur_VM.name, cur_VM.status, cur_VM.uuid))
                                    # print ('|  |  |  |  +-- VSC: show vswitch-controller vports type vm detail enterprise "%s" domain "%s" subnet "%s"' % (cur_ent.name, cur_domain.name, cur_subnet))
                                    for cur_vmIf in cur_VM.vm_interfaces.get():
                                        print ('|  |  |  |  +-- vmInterface: %s - %s mac %s' % (cur_vmIf.name, cur_vmIf.ip_address, cur_vmIf.mac))

                                        logger.warning('>%s>L3_DOMAIN>%s>%s>%s>%s>%s>%s>%s>%s' % (cur_ent.name, cur_domain.name, cur_zone.name, cur_subnet.name, cur_vport.name, cur_VM.name, cur_VM.uuid, cur_vmIf.mac, cur_vmIf.ip_address))
                    for cur_acl in cur_domain.ingress_acl_templates.get():
                        print('|  +-- Ingress ACL type %s : %s ( %s )' % (cur_acl.priority_type, cur_acl.description, cur_acl.name))
                        print('|  |  +-- Active: %s' % cur_acl.active)
                        print('|  |  +-- Status: %s' % cur_acl.policy_state)
                        print('|  |  +-- default_allow_ip: %s' % cur_acl.default_allow_ip)
                        i = 0
                        for cur_rule in cur_acl.ingress_acl_entry_templates.get():
                            i = i + 1
                            print('|  |  |  +-- Rule %s: %s' % (i, cur_rule.description))

                    for cur_acl in cur_domain.egress_acl_templates.get():
                        print('|  +-- Egress ACL type %s : %s ( %s )' % (cur_acl.priority_type, cur_acl.description, cur_acl.name))
                        print('|  |  +-- Active: %s' % cur_acl.active)
                        print('|  |  +-- Status: %s' % cur_acl.policy_state)
                        print('|  |  +-- default_allow_ip: %s' % cur_acl.default_allow_ip)
                        i = 0
                        for cur_rule in cur_acl.egress_acl_entry_templates.get():
                            i = i + 1
                            print('|  |  |  +-- Rule %s: %s' % (i, cur_rule.description))

                    for cur_acl in cur_domain.firewall_acls.get():
                        print('|  +- FW ACL: %s' % cur_acl.name)
                        i = 0
                        for cur_rule in cur_acl.firewall_rules.get():
                            i = i + 1
                            print('|  |  |  +-- Rule %s: %s' % (i, cur_rule.description))

                    print ('|')

            # L2 DOMAIN
            print ('|>---------- L2 DOMAIN ----------<') 
            for cur_domain in cur_ent.l2_domains.get():
                if (nuage_domain_filter and nuage_domain_filter in cur_domain.name) or (not nuage_domain_filter):
                    print('+-- L2 Domain: %s' % cur_domain.name)
                    for cur_vport in cur_domain.vports.get():
                        print ('|  |  |  +-- vPort: %s %s' % (cur_vport.name, cur_vport.description))
                        print ('|  |  |  |   +-- active: %s' % (cur_vport.active))
                        print ('|  |  |  |   +-- type: %s' % (cur_vport.type))
                        print ('|  |  |  |   +-- systemType: %s' % (cur_vport.system_type))

                        for cur_HostIf in cur_vport.host_interfaces.get():
                            print ('|  |  +-- Host Interface: %s ip %s mac %s' % (cur_HostIf.name, cur_HostIf.ip_address, cur_HostIf.mac))

                        for cur_VM in cur_vport.vms.get():
                            print ('|  |  +-- VM: %s' % (cur_VM.name))

                            for cur_vmIf in cur_VM.vm_interfaces.get():
                                print ('|  |  |  +-- vmInterface: %s mac %s' % (cur_vmIf.name, cur_vmIf.mac))

                                logger.warning('>%s>L2_DOMAIN>%s>%s>%s>%s>%s>%s' % (cur_ent.name, cur_domain.name, cur_vport.name, cur_VM.name, cur_VM.uuid, cur_vmIf.mac, cur_vmIf.ip_address))

                    for cur_acl in cur_domain.ingress_acl_templates.get():
                        print('|  +- Ingress ACL type %s : %s ( %s )' % (cur_acl.priority_type, cur_acl.description, cur_acl.name))
                        print('|  |  +-- Active: %s' % cur_acl.active)
                        print('|  |  +-- Status: %s' % cur_acl.policy_state)
                        print('|  |  +-- default_allow_ip: %s' % cur_acl.default_allow_ip)
                        i = 0
                        for cur_rule in cur_acl.ingress_acl_entry_templates.get():
                            i = i + 1
                            print('|  |  |  +-- Rule %s: %s' % (i, cur_rule.description))

                    for cur_acl in cur_domain.egress_acl_templates.get():
                        print('|  +- Egress ACL type %s : %s ( %s )' % (cur_acl.priority_type, cur_acl.description, cur_acl.name))
                        print('|  |  +-- Active: %s' % cur_acl.active)
                        print('|  |  +-- Status: %s' % cur_acl.policy_state)
                        print('|  |  +-- default_allow_ip: %s' % cur_acl.default_allow_ip)
                        i = 0
                        for cur_rule in cur_acl.egress_acl_entry_templates.get():
                            i = i + 1
                            print('|  |  |  +-- Rule %s: %s' % (i, cur_rule.description))

                    print ('|')   
                        
                        
# Start program
if __name__ == "__main__":
    main()