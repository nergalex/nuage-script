# -*- coding: utf-8 -*-
"""
--- Object ---
Create a SecurityPolicy


--- Usage ---
Run 'python Nuage-newSecurityPolicy.py -h' for an overview


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
    parser.add_argument('--nuage-mySecurityPolicyName', required=True, help='The name of the Nuage SecurityPolicy that should be created', dest='nuage_mySecurityPolicyName', type=str)
    parser.add_argument('--nuage-myTemplateOrDomain', required=True, help='Is this a domain template Security Policy or a domain Security Policy. Possible values = Template or Domain.', dest='nuage_myTemplateOrDomain', type=str, choices=['Template', 'Domain'])
    parser.add_argument('--nuage-myL2OrL3', required=True, help='Is this policy assigned to an L2 or L3 domain. Possible values = L2 or L3.', dest='nuage_myL2OrL3', type=str, choices=['L2', 'L3'])
    parser.add_argument('--nuage-myDomain', required=True, help='Domain template or domain for this Security Policy', dest='nuage_myDomain', type=str)
    parser.add_argument('--nuage-myIngressOrEgress', required=True, help='Domain template or domain for this Security Policy', dest='nuage_myIngressOrEgress', type=str, choices=['Ingress', 'Egress'])
    parser.add_argument('--nuage-myDescription', required=False, help='Description for security rule', dest='nuage_myDescription', type=str)
    parser.add_argument('--nuage-myAction', required=True, help='Action for security rule', dest='nuage_myAction', type=str, choices=['DROP', 'FORWARD'])
    parser.add_argument('--nuage-mySourceType', required=True, help='Source Type for security rule', dest='nuage_mySourceType', type=str, choices=['ANY', 'PGEXPRESSION', 'POLICYGROUP', 'ENTERPRISE_NETWORK', 'NETWORK_MACRO_GROUP'])
    parser.add_argument('--nuage-mySource', required=True, help='Source for security rule', dest='nuage_mySource', type=str)
    parser.add_argument('--nuage-myDestinationType', required=True, help='Destination Type for security rule', dest='nuage_myDestinationType', type=str, choices=['ANY', 'PGEXPRESSION', 'POLICYGROUP', 'ENTERPRISE_NETWORK', 'NETWORK_MACRO_GROUP'])
    parser.add_argument('--nuage-myDestination', required=True, help='Destination for security rule', dest='nuage_myDestination', type=str)
    parser.add_argument('--nuage-mySourcePort', required=True, help='Source Port for security rule', dest='nuage_mySourcePort', type=str)
    parser.add_argument('--nuage-myDestinationPort', required=True, help='Destination Port for security rule', dest='nuage_myDestinationPort', type=str)
    parser.add_argument('--nuage-myProtocol', required=True, help='Protocol for security rule', dest='nuage_myProtocol', type=str)
    parser.add_argument('--nuage-myPriority', required=True, help='Priority for security rule', dest='nuage_priority', type=str)
     
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
    
    args                        = get_args()
    debug                       = args.debug
    verbose                     = args.verbose
    log_file                    = args.logfile
    nuage_organization          = args.nuage_organization
    nuage_host                  = args.nuage_host
    nuage_port                  = args.nuage_port
    nuage_password              = args.nuage_password
    nuage_username              = args.nuage_username
    nuage_myEnterprise          = args.nuage_myEnterprise
    nuage_mySecurityPolicyName  = args.nuage_mySecurityPolicyName
    nuage_myTemplateOrDomain    = args.nuage_myTemplateOrDomain
    nuage_myL2OrL3              = args.nuage_myL2OrL3
    nuage_myDomain              = args.nuage_myDomain
    nuage_myIngressOrEgress     = args.nuage_myIngressOrEgress
    nuage_myDescription         = args.nuage_myDescription
    nuage_myAction              = args.nuage_myAction
    nuage_mySourceType          = args.nuage_mySourceType
    nuage_mySource              = args.nuage_mySource
    nuage_myDestinationType     = args.nuage_myDestinationType
    nuage_myDestination         = args.nuage_myDestination
    nuage_mySourcePort          = args.nuage_mySourcePort
    nuage_myDestinationPort     = args.nuage_myDestinationPort
    nuage_myProtocol            = args.nuage_myProtocol
    nuage_priority              = args.nuage_priority
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


    if nuage_myTemplateOrDomain == "Template":
        mySecurityPolicy = get_policy_template(logger, myEnterprise, nuage_myDomain, nuage_myL2OrL3, nuage_mySecurityPolicyName, nuage_myIngressOrEgress)
    elif nuage_myTemplateOrDomain == "Domain":
        mySecurityPolicy = get_policy_domain(logger, myEnterprise, nuage_myDomain, nuage_myL2OrL3, nuage_mySecurityPolicyName, nuage_myIngressOrEgress)


    if nuage_mySourceType == "POLICYGROUP":
        source_name = nuage_mySource
        nuage_mySource = get_policy_group(logger, myEnterprise, nuage_mySource, nuage_myTemplateOrDomain, nuage_myDomain, nuage_myL2OrL3)
        if not nuage_mySource:
            exit('Error : Source Policy group %s not found.' % (source_name))
        print('Source Policy group %s id %s.' % (nuage_mySource.name, nuage_mySource.id))
        nuage_mySource = nuage_mySource.id


    if nuage_mySourceType == "NETWORK_MACRO_GROUP":
        nuage_mySource = get_network_macro_group(myEnterprise, nuage_mySource)
        print('Source Network Macro group %s id %s.' % (nuage_mySource.name, nuage_mySource.id))
        nuage_mySource = nuage_mySource.id


    if nuage_mySourceType == "ENTERPRISE_NETWORK":
        nuage_mySource = get_network_macro(myEnterprise, nuage_mySource)
        print('Source Network Macro %s id %s.' % (nuage_mySource.name, nuage_mySource.id))
        nuage_mySource = nuage_mySource.id


    if nuage_mySourceType == "ANY":
        nuage_mySource = ""


    if nuage_myDestinationType == "POLICYGROUP":
        nuage_myDestination = get_policy_group(logger, myEnterprise, nuage_myDestination, nuage_myTemplateOrDomain, nuage_myDomain, nuage_myL2OrL3)
        print('Destination Policy group %s id %s.' % (nuage_myDestination.name, nuage_myDestination.id))
        nuage_myDestination = nuage_myDestination.id


    if nuage_myDestinationType == "NETWORK_MACRO_GROUP":
        nuage_myDestination = get_network_macro_group(myEnterprise, nuage_myDestination)
        print('Destination Network Macro group %s id %s.' % (nuage_myDestination.name, nuage_myDestination.id))
        nuage_myDestination = nuage_myDestination.id


    if nuage_myDestinationType == "ENTERPRISE_NETWORK":
        nuage_myDestination = get_network_macro(myEnterprise, nuage_myDestination)
        print('Destination Network Macro %s id %s.' % (nuage_myDestination.name, nuage_myDestination.id))
        nuage_myDestination = nuage_myDestination.id


    if nuage_myDestinationType == "ANY":
        nuage_myDestination = ""


    if nuage_myProtocol == "ICMP":
        nuage_myProtocol = "1"
    if nuage_myProtocol == "TCP":
        nuage_myProtocol = "6"
    if nuage_myProtocol == "UDP":
        nuage_myProtocol = "17"
    if nuage_myProtocol == "Any":
        nuage_myProtocol = "*"


    mySecurityPolicyRule = None


    if nuage_myIngressOrEgress == "Ingress":
        # If protocol is ICMP or Any, source and destination port must be omitted.
        if nuage_myProtocol != "6" and nuage_myProtocol != "17":
            mySecurityPolicyRule = vsdk.NUIngressACLEntryTemplate(dscp="*",
                                                            action=nuage_myAction,
                                                            description=nuage_myDescription,
                                                            ether_type="0x0800",
                                                            location_type=nuage_mySourceType,
                                                            location_id=nuage_mySource,
                                                            network_type=nuage_myDestinationType,
                                                            network_id=nuage_myDestination,
                                                            protocol=nuage_myProtocol,
                                                            external_id = MyCmsName,
                                                            priority = nuage_priority
                                                            )
        else :
            mySecurityPolicyRule = vsdk.NUIngressACLEntryTemplate(dscp="*",
                                                            action=nuage_myAction,
                                                            description=nuage_myDescription,
                                                            ether_type="0x0800",
                                                            location_type=nuage_mySourceType,
                                                            location_id=nuage_mySource,
                                                            network_type=nuage_myDestinationType,
                                                            network_id=nuage_myDestination,
                                                            source_port=nuage_mySourcePort,
                                                            destination_port=nuage_myDestinationPort,
                                                            protocol=nuage_myProtocol,
                                                            external_id = MyCmsName,
                                                            priority = nuage_priority
                                                            )
    elif nuage_myIngressOrEgress == "Egress":
        # If protocol is ICMP or Any, source and destination port must be omitted.
        if nuage_myProtocol != "6" and nuage_myProtocol != "17":
            mySecurityPolicyRule = vsdk.NUEgressACLEntryTemplate(dscp="*",
                                                            action=nuage_myAction,
                                                            description=nuage_myDescription,
                                                            ether_type="0x0800",
                                                            network_type=nuage_mySourceType,
                                                            network_id=nuage_mySource,
                                                            location_type=nuage_myDestinationType,
                                                            location_id=nuage_myDestination,
                                                            protocol=nuage_myProtocol,
                                                            external_id = MyCmsName,
                                                            priority = nuage_priority
                                                            )
        else:
            mySecurityPolicyRule = vsdk.NUEgressACLEntryTemplate(dscp="*",
                                                            action=nuage_myAction,
                                                            description=nuage_myDescription,
                                                            ether_type="0x0800",
                                                            network_type=nuage_mySourceType,
                                                            network_id=nuage_mySource,
                                                            location_type=nuage_myDestinationType,
                                                            location_id=nuage_myDestination,
                                                            source_port=nuage_mySourcePort,
                                                            destination_port=nuage_myDestinationPort,
                                                            protocol=nuage_myProtocol,
                                                            external_id = MyCmsName,
                                                            priority = nuage_priority
                                                            )
    mySecurityPolicy.create_child(mySecurityPolicyRule)


    print ('Security Policy Rule id: %s' % (mySecurityPolicyRule.id))
    
    logger.warning('Security Policy Rule id: %s' % (mySecurityPolicyRule.id))


def get_domain(logger, myEnterprise, nuage_myDomain, nuage_myL2OrL3):
    myFilter = "name == \"" + nuage_myDomain +"\""
    myDomain = None

    if nuage_myL2OrL3 == "L3":
        myDomain = myEnterprise.domains.get_first(filter = myFilter)
    elif nuage_myL2OrL3 == "L2":
        myDomain = myEnterprise.l2_domains.get_first(filter = myFilter)

    if not myDomain:
        print('ERROR: Domain %s was not found.' % (nuage_myDomain))
        exit(1)
    
    print('%s Domain: %s' % (nuage_myL2OrL3, myDomain.name))

    return myDomain


def get_domain_template(logger, myEnterprise, nuage_myDomain, nuage_myL2OrL3):
    myFilter = "name == \"" + nuage_myDomain +"\""

    myDomainTemplate = None

    if nuage_myL2OrL3 == "L3":
        myDomainTemplate = myEnterprise.domain_templates.get_first(filter = myFilter)
    elif nuage_myL2OrL3 == "L2":
        myDomainTemplate = myEnterprise.l2_domain_templates.get_first(filter = myFilter)

    if not myDomainTemplate:
        print('ERROR: Domain Template %s was not found.' % (nuage_myDomain))
        exit(1)
    
    print('%s Domain Template: %s' % (nuage_myL2OrL3, myDomainTemplate.name))

    return myDomainTemplate
    

def get_policy_template(logger, myEnterprise, nuage_myDomain, nuage_myL2OrL3, nuage_mySecurityPolicyName, nuage_myIngressOrEgress):
    myDomainTemplate = get_domain_template(logger, myEnterprise, nuage_myDomain, nuage_myL2OrL3)

    myFilter = "name == \"" + nuage_mySecurityPolicyName +"\""
    mySecurityPolicy = None

    if nuage_myIngressOrEgress == "Ingress":
        mySecurityPolicy = myDomainTemplate.ingress_acl_templates.get_first(filter = myFilter)
    elif nuage_myIngressOrEgress == "Egress":
        mySecurityPolicy = myDomainTemplate.egress_acl_templates.get_first(filter = myFilter)

    if not mySecurityPolicy:
        print('ERROR: %s Security Policy %s was not found.' % (nuage_myIngressOrEgress, nuage_mySecurityPolicyName))
        exit(1)

    return mySecurityPolicy


def get_policy_domain(logger, myEnterprise, nuage_myDomain, nuage_myL2OrL3, nuage_mySecurityPolicyName, nuage_myIngressOrEgress):
    myDomain = get_domain(logger, myEnterprise, nuage_myDomain, nuage_myL2OrL3)

    myFilter = "name == \"" + nuage_mySecurityPolicyName +"\""
    mySecurityPolicy = None

    if nuage_myIngressOrEgress == "Ingress":
        mySecurityPolicy = myDomain.ingress_acl_templates.get_first(filter = myFilter)
    elif nuage_myIngressOrEgress == "Egress":
        mySecurityPolicy = myDomain.egress_acl_templates.get_first(filter = myFilter)

    if not mySecurityPolicy:
        print('ERROR: %s Security Policy %s was not found.' % (nuage_myIngressOrEgress, nuage_mySecurityPolicyName))
        exit(1)

    return mySecurityPolicy


def get_policy_group(logger, myEnterprise, myPolicyGroupName, nuage_myTemplateOrDomain, nuage_myDomain, nuage_myL2OrL3):
    myDomain = None

    if nuage_myTemplateOrDomain == "Template":
        myDomain = get_domain_template(logger, myEnterprise, nuage_myDomain, nuage_myL2OrL3)
    else:
        myDomain = get_domain(logger, myEnterprise, nuage_myDomain, nuage_myL2OrL3)

    myFilter = "name == \"" + myPolicyGroupName +"\""
    myPolicyGroupTemplate = myDomain.policy_group_templates.get_first(filter=myFilter)

    return myPolicyGroupTemplate

def get_network_macro_group(myEnterprise, nuage_mySource):
    myFilter = "name == \"" + nuage_mySource +"\""
    myNetworkMacroGroup = myEnterprise.network_macro_groups.get_first(filter=myFilter)
    
    if not myNetworkMacroGroup:
        print('ERROR: Network Macro Group %s was not found.' % (nuage_mySource))
        exit(1)
    return myNetworkMacroGroup

def get_network_macro(myEnterprise, nuage_mySource):
    myFilter = "name == \"" + nuage_mySource +"\""
    myNetworkMacro = myEnterprise.enterprise_networks.get_first(filter=myFilter)

    if not myNetworkMacro:
        print('ERROR: Network Macro %s was not found.' % (nuage_mySource))
        exit(1)

    return myNetworkMacro


# Start program
if __name__ == "__main__":
    main()