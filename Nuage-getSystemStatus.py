# -*- coding: utf-8 -*-
"""
--- Object ---
Fetch system metrics in your VSP platform

--- Usage ---
Run 'python Nuage-getSystemStatus.py -h' for an overview

--- Documentation ---
none

--- Author ---
DA COSTA Alexis <alexis.dacosta@bt.com>

--- Examples ---

TODO

"""

import argparse
import sys
from time import sleep

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
    parser.add_argument('--nuage-device_filter', required=False, help='Domain name', dest='nuage_device_filter', type=str, choices=[u'VSC', u'VSD', u'eventlog'])
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
    nuage_device_filter  = args.nuage_device_filter
    max_eventlog = 3
    fetch_interval = 5
    
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
    logger.warning(';VSC;name;status;current_cpuusage;current_memory_usage')
    while True:
        for cur_vsp in nc.vsps.get():
            print ('VSP %s (%s)' % (cur_vsp.name, cur_vsp.description))
            print ('  +-- product_version: %s' % (cur_vsp.product_version))
            print ('  +-- location: %s' % (cur_vsp.location))

            # VSC
            if (nuage_device_filter and nuage_device_filter == 'VSC') or (not nuage_device_filter):
                print ('  |  +----------------------- VSC ----------------------- ')
                for cur_vsc in cur_vsp.vscs.get():
                    print ('  |  |  +-- VSC %s (%s)' % (cur_vsc.name, cur_vsc.description))
                    print ('  |  |  |  +-- general information')
                    print ('  |  |  |  |  +-- location: %s' % (cur_vsc.location))
                    print ('  |  |  |  |  +-- product_version: %s' % (cur_vsc.product_version))
                    print ('  |  |  |  |  +-- management_ip: %s' % (cur_vsc.management_ip))
                    print ('  |  |  |  |  +-- address: %s' % (cur_vsc.address))
                    print ('  |  |  |  |  +-- status: %s' % (cur_vsc.status)) 
                    print ('  |  |  |  |  +-- unavailable_timestamp: %s' % (cur_vsc.unavailable_timestamp))
                    print ('  |  |  +-- CPU')
                    print ('  |  |  |  |  +-- current_cpuusage: %s' % (cur_vsc.current_cpuusage))
                    print ('  |  |  |  |  +-- peak_cpuusage: %s' % (cur_vsc.peak_cpuusage))
                    print ('  |  |  |  |  +-- average_cpuusage: %s' % (cur_vsc.average_cpuusage))
                    print ('  |  |  +-- RAM')
                    print ('  |  |  |  |  +-- current_memory_usage: %s' % (cur_vsc.current_memory_usage))
                    print ('  |  |  |  |  +-- peak_memory_usage: %s' % (cur_vsc.peak_memory_usage))
                    print ('  |  |  |  |  +-- average_memory_usage: %s' % (cur_vsc.average_memory_usage))
                    # print ('  |  |  +-- Disk')
                    # print ('  |  |  |  |  +-- disks: %s' % (cur_vsc.disks))
                    print ('  |  |')
                    logger.warning(';VSC;%s;%s;%s;%s' % (cur_vsc.name, cur_vsc.status, cur_vsc.current_cpuusage, cur_vsc.current_memory_usage))

            # eventlog
            if (nuage_device_filter and nuage_device_filter == 'eventlog') or (not nuage_device_filter):
                print ('  |  +----------------------- eventlogs last %s ----------------------- ' % (max_eventlog))
                i = 0
                for cur_eventlog in cur_vsp.event_logs.get():
                    i += 1
                    if i < max_eventlog:
                        break
                    else:
                        print ('  |  |  +-- %s eventlog ------------------------------------------')
                        print ('  |  |  |  +-- general information')
                        print ('  |  |  |  |  +-- request_id: %s' % (cur_eventlog.request_id))
                        print ('  |  |  |  |  +-- entities: %s' % (cur_eventlog.entities))
                        print ('  |  |  |  |  +-- entity_parent_type: %s' % (cur_eventlog.entity_parent_type))
                        print ('  |  |  |  |  +-- entity_type: %s' % (cur_eventlog.entity_type))
                        print ('  |  |  |  |  +-- user: %s' % (cur_eventlog.user)) 
                        print ('  |  |  |  |  +-- event_received_time: %s' % (cur_eventlog.event_received_time))
                        print ('  |  |  |  |  +-- type: %s' % (cur_eventlog.type))  
                    
        sleep(fetch_interval)
            
# Start program
if __name__ == "__main__":
    main()