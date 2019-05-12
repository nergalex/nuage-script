# -*- coding: utf-8 -*-
"""
--- Object ---
Get a SecurityPolicy


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
    parser.add_argument('--nuage-mySecurityPolicyName', required=True, help='The name of the Nuage SecurityPolicy', dest='nuage_mySecurityPolicyName', type=str)
    parser.add_argument('--nuage-myTemplateOrDomain', required=True, help='Is this a domain template Security Policy or a domain Security Policy. Possible values = Template or Domain.', dest='nuage_myTemplateOrDomain', type=str, choices=['Template', 'Domain'])
    parser.add_argument('--nuage-myL2OrL3', required=True, help='Is this policy assigned to an L2 or L3 domain. Possible values = L2 or L3.', dest='nuage_myL2OrL3', type=str, choices=['L2', 'L3'])
    parser.add_argument('--nuage-myDomain', required=True, help='Domain template or domain for this Security Policy', dest='nuage_myDomain', type=str)
    parser.add_argument('--nuage-myIngressOrEgress', required=True, help='Domain template or domain for this Security Policy', dest='nuage_myIngressOrEgress', type=str, choices=['Ingress', 'Egress'])
    
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


    mySecurityPolicy = None


    if nuage_myTemplateOrDomain == "Template":
        mySecurityPolicy = get_policy_template(logger, myEnterprise, nuage_myDomain, nuage_myL2OrL3, nuage_mySecurityPolicyName, nuage_myIngressOrEgress)
    elif nuage_myTemplateOrDomain == "Domain":
        mySecurityPolicy = get_policy_domain(logger, myEnterprise, nuage_myDomain, nuage_myL2OrL3, nuage_mySecurityPolicyName, nuage_myIngressOrEgress)


    print ('|')
    myFilter = "name == \"" + nuage_myDomain +"\""
    myDomain = None


    if nuage_myTemplateOrDomain == "Template":
        myDomain = get_domain_template(logger, myEnterprise, nuage_myDomain, nuage_myL2OrL3)
    elif nuage_myTemplateOrDomain == "Domain":
        myDomain = get_domain(logger, myEnterprise, nuage_myDomain, nuage_myL2OrL3)


    if not myDomain:
        print('ERROR: Domain %s not found.', nuage_myDomain)
        exit(1)


    print('+--- %s %s: %s' % (nuage_myL2OrL3, nuage_myTemplateOrDomain, myDomain.name))
    print ('|   |')
    print ('|   +--- %s Security Policy %s :' % (nuage_myIngressOrEgress, mySecurityPolicy.name))
    print ('|   |   |')
    print ('|   |   description: %s' % (mySecurityPolicy.description))
    print ('|   |   Allow IP traffic: %s' % (mySecurityPolicy.default_allow_ip))
    print ('|   |   Allow non-IP traffic: %s' % (mySecurityPolicy.default_allow_non_ip))
    print ('|   |   Active: %s' % (mySecurityPolicy.active))
    print ('|   |   Rules:')


    security_policy_rules = None 


    if nuage_myIngressOrEgress == "Ingress":
        security_policy_rules = mySecurityPolicy.ingress_acl_entry_templates.get()
    elif nuage_myIngressOrEgress == "Egress":
        security_policy_rules = mySecurityPolicy.egress_acl_entry_templates.get()


    if not security_policy_rules or security_policy_rules == []:
        print ('|   |        +--- No Security Policy rules for this policy')


    for rule in security_policy_rules:
        print ('|   |        +--- %s Rule %s:' % (rule.priority, rule.description))
        print ('|   |        |    +--- Condition')
        print ('|   |        |    |    +--- protocol = %s' % (rule.protocol))
        print ('|   |        |    +--- Action = %s' % (rule.action))


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


# Start program
if __name__ == "__main__":
    main()