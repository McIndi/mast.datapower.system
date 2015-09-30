"""==========================================================
mast system:

A set of tools for automating routine system-administration
tasks associated with IBM DataPower appliances.

Copyright 2014, All Rights Reserved
McIndi Solutions LLC
=========================================================="""
import os
import sys
import flask
import shutil
import zipfile
import logging
import commandr
from mast.xor import xorencode
from time import time, sleep
from mast.logging import make_logger
from mast.timestamp import Timestamp
import mast.plugin_utils.plugin_utils as util
from mast.datapower import datapower

cli = commandr.Commandr()

MAST_HOME = os.environ["MAST_HOME"]

logger = make_logger("mast.datapower.system")

def _pmr_create_dirs(appliances, out_dir, timestamp):
    for appliance in appliances:
        _dir = os.path.join(
            out_dir,
            appliance.hostname,
            timestamp)
        os.makedirs(_dir)


def _pmr_get_error_report_settings(appliances):
    results = {}
    for appliance in appliances:
        config = appliance.get_config("ErrorReportSettings")
        results[appliance.hostname] = config
    return results


def _pmr_conditionally_save_internal_state(appliances, ers, timestamp):
    xpath = datapower.CONFIG_XPATH + "/ErrorReportSettings/InternalState"
    for appliance in appliances:
        internal_state = ers[appliance.hostname].xml.find(xpath).text
        internal_state = True if (internal_state == "on") else False
        if not internal_state:
            appliance.SaveInternalState()


def _pmr_generate_error_reports(appliances):
    for appliance in appliances:
        appliance.ErrorReport()


def _pmr_backup_all_domains(appliances, out_dir, timestamp):
    for appliance in appliances:
        filename = os.path.join(
            out_dir,
            appliance.hostname,
            timestamp)
        filename = os.path.join(
            filename,
            '%s-%s-all-domains.zip' % (
                timestamp,
                appliance.hostname))
        with open(filename, 'wb') as fout:
            fout.write(appliance.get_normal_backup())


def _pmr_query_status_providers(appliances, out_dir, timestamp):
    global MAST_HOME
    filename = os.path.join(MAST_HOME, 'etc', 'statusProviders.txt')
    with open(filename, 'r') as fin:
        default_providers = [_.strip() for _ in fin.readlines()]
    filename = os.path.join('etc', 'statusProviders-applicationDomains.txt')
    with open(filename, 'r') as fin:
        application_providers = [_.strip() for _ in fin.readlines()]
    for appliance in appliances:
        for domain in appliance.domains:
            providers = application_providers
            if domain == 'default':
                providers = default_providers
            filename = 'pmrinfo-%s-%s-%s.xml' % (
                appliance.hostname, domain, timestamp)
            filename = os.path.join(
                out_dir,
                appliance.hostname,
                timestamp,
                filename)
            with open(filename, 'w') as fout:
                msg = "<pmrInfo-{}-{}>{}".format(
                    appliance.hostname, domain, os.linesep)
                fout.write(msg)
                for provider in providers:
                    fout.write('<{}>{}'.format(provider, os.linesep))
                    try:
                        status = appliance.get_status(
                            provider, domain=domain).pretty
                        fout.write(status)
                    except Exception:
                        fout.write("Failed to retrieve status!")
                    fout.write('</{}>{}'.format(provider, os.linesep))
                    fout.write(os.linesep)
                fout.write('</pmrInfo-{}-{}>{}'.format(
                    appliance.hostname, domain, os.linesep))


def _pmr_download_error_reports(appliances, out_dir, ers, timestamp):
    protocol_xpath = datapower.CONFIG_XPATH + "/ErrorReportSettings/Protocol"
    raid_path_xpath = datapower.CONFIG_XPATH + "/ErrorReportSettings/RaidPath"

    for appliance in appliances:
        protocol = ers[appliance.hostname].xml.find(protocol_xpath).text

        if protocol == 'temporary':
            path = 'temporary:'
            filestore = appliance.get_filestore('default', path)
            _dir = filestore.xml.find('.//location[@name="%s"]' % (path))

        elif protocol == 'raid':
            try:
                path = ers[appliance.hostname].xml.find(raid_path_xpath).text
            except AttributeError:
                path = ''
            path = "{}/{}".format(appliance.raid_directory, path)
            if path.endswith('/'):
                path = path[:-1]
            filestore = appliance.get_filestore('default', 'local:')
            _dir = filestore.xml.find('.//directory[@name="%s"]' % (path))

        else:
            appliance.log_warn(''.join(
                    ('\tThe failure notification looks like it is set for ',
                    protocol,
                    ', which we do not currently support. Failing back',
                    'to temporary:...\n')))
            path = 'temporary:'
            filestore = appliance.get_filestore('default', path)
            _dir = filestore.xml.find('.//location[@name="%s"]' % (path))

        if not _dir:
            appliance.log_warn("There were no error reports found.")
            return
        files = []
        for node in _dir.findall('.//*'):
            if node.tag == "file":
                if 'error-report' in node.get('name'):
                    files.append(node.get('name'))
        for file in files:
            fqp = '%s/%s' % (path, file)
            filename = '%s-%s' % (appliance.hostname, file)
            filename = os.path.join(
                out_dir,
                appliance.hostname,
                timestamp,
                filename)
            with open(filename, 'wb') as fout:
                fout.write(appliance.getfile('default', fqp))


def _pmr_cleanup(appliances, out_dir, timestamp):
    for appliance in appliances:
        zip_filename = '{}-{}-PMR_INFO.zip'.format(
            timestamp, appliance.hostname)
        zip_filename = os.path.join(out_dir, zip_filename)
        z = zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED)
        _zipdir(os.path.join(out_dir, appliance.hostname, timestamp), z)
        shutil.rmtree(
            os.path.abspath(
                os.path.join(out_dir, appliance.hostname, timestamp)))


def _zipdir(path, z):
    for root, dirs, files in os.walk(path):
        for file in files:
            z.write(os.path.join(root, file), os.path.basename(file))


def _verify_zip(zip_file):
    if isinstance(zip_file, basestring):
        try:
            zip_file = zipfile.ZipFile(zip_file, 'r')
        except zipfile.BadZipfile:
            return False
    if zip_file.testzip() is None:
        # if testzip returns None then there were no errors
        return True
    return False


@cli.command('xor', category='utilities')
def xor(string='', web=False, no_check_hostname=False):
    """This will xor encode and base64 encode the given string
for suitable use in passing credentials to MAST CLI commands.
This is a useful utility for scripting multiple MAST CLI commands
since your credentials will not be in plain text.

**PLEASE NOTE THAT THIS IS OBFUSCATION AT BEST, SO DON'T LEAN
TOO HEAVILY ON THIS SECURITY**"""
    if web:
        return xorencode(string), ""
    print xorencode(string)


#~#~#~#~#~#~#~#
# Caches
# ======
#
# These functions are meant to be used to flush the caches that DataPower
# maintains.
#
# Current Commands:
# ----------------
#
# FlushAAACache(PolicyName)
# FlushArpCache()
# FlushDNSCache()
# FlushDocumentCache(XMLManager)
# FlushLDAPPoolCache(XMLManager)
# FlushNDCache()
# FlushNSSCache(ZosNSSClient)
# FlushPDPCache(XACMLPDP)
# FlushRBMCache()
# FlushStylesheetCache(XMLManager)
#

@cli.command('flush-aaa-cache', category='caches')
def flush_aaa_cache(appliances=[], credentials=[],
                    timeout=120, Domain="", aaa_policy="", no_check_hostname=False, web=False):
    """This will flush the AAA Cache for the specified AAAPolicy
in the specified Domain on the specified appliances.

Parameters:

* Domain - The domain where the specified AAAPolicy resides
* aaa_policy - The AAAPolicy who's cache you would like to flush"""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)

    logger.info(
        "Attempting to flush AAA cache on {} in {} domain.".format(
            str(env.appliances), Domain))
    kwargs = {"PolicyName": aaa_policy, 'domain': Domain}
    responses = env.perform_action('FlushAAACache', **kwargs)
    logger.debug("Responses received: {}".format(str(responses)))

    if web:
        return util.render_boolean_results_table(
            responses, suffix="flush_aaa_cache"), util.render_history(env)

    for host, response in list(responses.items()):
        if response:
            print
            print host
            print '=' * len(host)
            if response:
                print 'OK'
            else:
                print "FAILURE"
                print response


@cli.command('flush-arp-cache', category='caches')
def flush_arp_cache(appliances=[], credentials=[],
                    timeout=120, no_check_hostname=False, web=False):
    """This will flush the ARP cache on the specified appliances."""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    logger.info("Attempting to flush ARP cache for {}".format(
        str(env.appliances)))
    responses = env.perform_action('FlushArpCache')
    logger.debug("Responses received: {}".format(str(appliances)))

    if web:
        return util.render_boolean_results_table(
            responses, suffix="flush_arp_cache"), util.render_history(env)

    for host, response in list(responses.items()):
        if response:
            print
            print host
            print '=' * len(host)
            if response:
                print 'OK'
            else:
                print "FAILURE"
                print response


@cli.command('flush-dns-cache', category='caches')
def flush_dns_cache(appliances=[], credentials=[],
                    timeout=120, no_check_hostname=False, web=False):
    """This will flush the DNS cache on the specified appliances."""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    logger.info("Attempting to flush DNS cache on {}".format(
        str(env.appliances)))
    responses = env.perform_action('FlushDNSCache')
    logger.debug("Responses received: {}".format(responses))

    if web:
        return util.render_boolean_results_table(
            responses, suffix="flush_dns_cache"), util.render_history(env)

    for host, response in list(responses.items()):
        if response:
            print
            print host
            print '=' * len(host)
            if response:
                print 'OK'
            else:
                print "FAILURE"
                print response


@cli.command('flush-document-cache', category='caches')
def flush_document_cache(appliances=[], credentials=[],
                    timeout=120, Domain="", xml_manager="",
                    no_check_hostname=False, web=False):
    """This will flush the Daocument cache for the specified
xml_manager in the specified domain on teh specified appliances.

Parameters:

* Domain - The domain where xml_manager resides
* xml_manger - The XMLManager who's document cache you would
like to flush"""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    logger.info(
        "Attempting to flush document cache for "
        "{} in {} domain for {} xml manager".format(
            str(env.appliances),
            Domain,
            xml_manager))
    kwargs = {"XMLManager": xml_manager, 'domain': Domain}
    responses = env.perform_action('FlushDocumentCache', **kwargs)
    logger.debug("Responses received: {}".format(str(resonses)))

    if web:
        return util.render_boolean_results_table(
            responses, suffix="flush_document_cache"), util.render_history(env)

    for host, response in list(responses.items()):
        if response:
            print
            print host
            print '=' * len(host)
            if response:
                print 'OK'
            else:
                print "FAILURE"
                print response


@cli.command('flush-ldap-pool-cache', category='caches')
def flush_ldap_pool_cache(appliances=[], credentials=[],
                          timeout=120, Domain="", xml_manager="",
                          no_check_hostname=False, web=False):
    """This will flush the LDAP Pool Cache for the specified
xml_manager in the specified domain on the specified appliances

Parameters:

* Domain - The domain where xml_manager resides
* xml_manager - The XMLManager who's LDAP Pool cache you would
like to flush"""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    logger.info(
        "Attempting to flush LDAP Pool Cache for "
        "{} in {} domain for {} xml manager".format(
            str(env.appliances), Domain, xml_manager))
    kwargs = {"XMLManager": xml_manager, 'domain': Domain}
    responses = env.perform_action('FlushLDAPPoolCache', **kwargs)
    logger.debug("Responses received: {}".format(str(responses)))

    if web:
        return util.render_boolean_results_table(
            responses, suffix="flush_ldap_pool_cache"), util.render_history(env)

    for host, response in list(responses.items()):
        if response:
            print
            print host
            print '=' * len(host)
            if response:
                print 'OK'
            else:
                print "FAILURE"
                print response


@cli.command('flush-nd-cache', category='caches')
def flush_nd_cache(appliances=[], credentials=[],
                   timeout=120, no_check_hostname=False, web=False):
    """This will flush the ND cache for the specified appliances."""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    logger.info("Attempting to flush ND Cache for {}".format(
        str(env.appliances)))
    responses = env.perform_action('FlushNDCache')
    logger.debug("Responses received: {}".format(str(responses)))

    if web:
        return util.render_boolean_results_table(
            responses, suffix="flush_nd_cache"), util.render_history(env)

    for host, response in list(responses.items()):
        if response:
            print
            print host
            print '=' * len(host)
            if response:
                print 'OK'
            else:
                print "FAILURE"
                print response


@cli.command('flush-nss-cache', category='caches')
def flush_nss_cache(appliances=[], credentials=[],
                    timeout=120, Domain="", zos_nss_client="",
                    no_check_hostname=False, web=False):
    """This will flush the NSS cache for the specified ZOSNSSClient
in the specified domain for the specified appliance.

Parameters:

* Domain - The domain where zos_nss_client resides
* zos_nss_client - The ZOSNSSClient who's cache you would like to
flush"""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)

    logger.info("Attempting to flush NSS Cache for {} {} {}".format(
        str(env.appliances), Domain, zos_nss_client))
    kwargs = {"ZosNSSClient": zos_nss_client, 'domain': Domain}
    responses = env.perform_action('FlushNSSCache', **kwargs)
    logger.debug("Responses received: {}".format(str(responses)))

    if web:
        return util.render_boolean_results_table(
            responses, suffix="flush_nss_cache"), util.render_history(env)

    for host, response in list(responses.items()):
        if response:
            print
            print host
            print '=' * len(host)
            if response:
                print 'OK'
            else:
                print "FAILURE"
                print response


@cli.command('flush-pdp-cache', category='caches')
def flush_pdp_cache(appliances=[], credentials=[],
                    timeout=120, XACML_PDP="",
                    no_check_hostname=False, web=False):
    """This will flush the PDP cache for the specified XACML_PDP
for the specified appliances.

Parameters:

* XACML_PDP - The XACMLPDP object who's cache you would like to flush"""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)

    logger.info("Attempting to flush PDP Cache for {} {}".format(
        str(env.appliances), XACML_PDP))
    kwargs = {"XACMLPDP": XACML_PDP}
    responses = env.perform_action('FlushPDPCache', **kwargs)
    logger.debug("Responses received: {}".format(str(responses)))

    if web:
        return util.render_boolean_results_table(
            responses, suffix="flush_pdp_cache"), util.render_history(env)

    for host, response in list(responses.items()):
        if response:
            print
            print host
            print '=' * len(host)
            if response:
                print 'OK'
            else:
                print "FAILURE"
                print response


@cli.command('flush-rbm-cache', category='caches')
def flush_rbm_cache(appliances=[], credentials=[],
                    timeout=120, Domain="",
                    no_check_hostname=False, web=False):
    """This will flush the RBM cache in the specified domain for
the specified appliances.

Parameters:

* Domain - The domain who's RBM cache you would like to flush"""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    logger.info("Attempting to flush RBM cache {} {}".format(
        str(env.appliances), Domain))
    responses = env.perform_action('FlushRBMCache', **{'domain': Domain})
    logger.debug("Responses received: {}".format(str(responses)))

    if web:
        return util.render_boolean_results_table(
            responses, suffix="flush_rbm_cache"), util.render_history(env)

    for host, response in list(responses.items()):
        if response:
            print
            print host
            print '=' * len(host)
            if response:
                print 'OK'
            else:
                print "FAILURE"
                print response


@cli.command('flush-stylesheet-cache', category='caches')
def flush_stylesheet_cache(appliances=[], credentials=[],
                          timeout=120, Domain="", xml_manager="",
                          no_check_hostname=False, web=False):
    """This will flush the stylesheet cache for the specified xml_manager
in the specified Domain on the specified appliances.

Parameters:

* Domain - The domain where xml_manager resides
* xml_manager - The XMLManager who's cache you would like to flush"""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    logger.info("Attempting to flush Stylesheet Cache for {} {} {}".format(
        str(env.appliances),
        Domain,
        xml_manager))
    kwargs = {"XMLManager": xml_manager, 'domain': Domain}
    responses = env.perform_action('FlushStylesheetCache', **kwargs)
    logger.debug("Responses received: {}".format(str(responses)))

    if web:
        return util.render_boolean_results_table(
            responses,
            suffix="flush_stylesheet_cache"), util.render_history(env)

    for host, response in list(responses.items()):
        if response:
            print
            print host
            print '=' * len(host)
            if response:
                print 'OK'
            else:
                print "FAILURE"
                print response
#
#~#~#~#~#~#~#~#

#~#~#~#~#~#~#~#
# configuration
# =============
#
# These functions are meant to be used to affect the confiuration of the
# DataPower appliances.
#
# current commands:
# ----------------
#
# save - save the current configuration of the specified domains
#


# Tested!
@cli.command('save', category='configuration')
def save_config(appliances=[], credentials=[],
                timeout=120, Domain=['default'],
                no_check_hostname=False, web=False):
    """Saves the configuration in the given domain(s)

Parameters:
* Domain - A list of domains to save

    >>> result = system.save_config(
    ...     appliances=["localhost"],
    ...     credentials=["user:pass"],
    ...     timeout=120,
    ...     Domain=["default"],
    ...     web=False)
    >>> print result
    None
    >>> print len(APPLIANCES[0]._history)
    1
    >>> result = system.save_config(
    ...     appliances=["localhost"],
    ...     credentials=["user:pass"],
    ...     timeout=120,
    ...     Domain=["all-domains"],
    ...     web=False)
    >>> print result
    None
    >>> print len(APPLIANCES[1]._history)
    5
"""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    if isinstance(Domain, basestring):
        Domain = [Domain]

    if web:
        return (
            util.render_save_config_results_table(env, Domain),
            util.render_history(env))

    for appliance in env.appliances:
        _domains = Domain
        if "all-domains" in _domains:
            _domains = appliance.domains
        for domain in _domains:
            logger.info("Attempting to save configuration of {} {}".format(
                appliance, domain))
            resp = appliance.SaveConfig(domain=domain)
            logger.debug("Response received: {}".format(resp))


@cli.command("quiesce-service", category="configuration")
def quiesce_service(appliances=[], credentials=[], timeout=120,
                    type="", name="", Domain="", quiesce_timeout="60",
                    no_check_hostname=False, web=False):
    """This will quiesce a service in the specified domain on the specified
appliances.

Parameters:

* type - The type of service to quiesce
* name - The name of the service to quiesce
* Domain - The domain in which the service resides
* quiesce_timeout - This is the amount of time (in seconds) the appliance
should wait before forcing the quiesce (**Must be at least 60**)"""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    kwargs = {
        "type": type,
        "name": name,
        "timeout": quiesce_timeout,
        "domain": Domain}
    logger.info("Attempting to quiesce service {} in {} on {}".format(
        name, Domain, str(env.appliances)))
    resp = env.perform_action("ServiceQuiesce", **kwargs)
    logger.debug("Responses received: {}".format(str(resp)))

    if web:
        return util.render_boolean_results_table(
            resp, suffix="quiesce_service"), util.render_history(env)

    for host, xml in resp.items():
        print host, '\n', "=" * len(host)
        print '\n\n', xml


@cli.command("unquiesce-service", category="configuration")
def unquiesce_service(appliances=[], credentials=[], timeout=120,
                      Domain="", type="", name="", quiesce_timeout=120,
                      no_check_hostname=False, web=False):
    """This will unquiesce a service in the specified domain on the specified
appliances.

Parameters:

* Domain - The domain in which the service resides
* type - The type of the service to unquiesce
* name - The name of the service to unquiesce"""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    kwargs = {
        "type": type,
        "name": name,
        "timeout": quiesce_timeout,
        "domain": Domain}
    logger.info("Attempting to unquiesce service {} in {} on {}".format(
        name, Domain, str(env.appliances)))
    resp = env.perform_action("ServiceUnquiesce", **kwargs)
    logger.debug("Responses received: {}".format(str(resp)))

    if web:
        return util.render_boolean_results_table(
            resp, suffix="unquiesce_service"), util.render_history(env)

    for host, xml in resp.items():
        print host, '\n', "=" * len(host)
        print '\n\n', xml

#
#~#~#~#~#~#~#~#

#~#~#~#~#~#~#~#
# domains
# =======
#
# These functions are meant to be used to affect the domains
# of the DataPower appliances.
#
# current commands:
# ----------------
# show-domains - Shows the domains of the specified appliances
# add-domain - adds a domain to the specified appliances
# del-domain - removes a domain from the specified appliances
# quiesce-domain - quiesce the specified domain
# unquiesce-domain - unquiesce the specified domain
# disable-domain - set the admin-state to disabled for the specified domain
# enable-domain - set the admin-state to enabled for the specified domain
#


# Tested!
@cli.command('show-domains', category='domains')
def list_domains(appliances=[], credentials=[],
                 timeout=120, no_check_hostname=False, web=False):
    """Lists the domains on the specified appliances as well as all common
domains."""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)

    if web:
        return util.render_list_domains_table(
            env), util.render_history(env)

    sets = []
    for appliance in env.appliances:
        logger.info("Attempting to retrieve a list of domains for {}".format(
            str(appliance)))
        domains = appliance.domains
        logger.debug("Domains for {} found: {}".format(
            str(appliance), str(domains)))
        sets.append(set(domains))
        print '\n', appliance.hostname
        print '=' * len(appliance.hostname)
        for domain in appliance.domains:
            print '\t', domain

    common = sets[0].intersection(*sets[1:])
    logger.info("domains common to {}: {}".format(
        str(env.appliances), str(common)))
    print '\n', 'Common'
    print '======'
    for domain in common:
        print '\t', domain


@cli.command('add-domain', category='domains')
def add_domain(appliances=[], credentials=[],
               timeout=120, domain_name=None,
               save_config=False, no_check_hostname=False, web=False):
    """Adds a domain to the specified appliances

Parameters:

* domain_name - The name of the domain to add
* save_config - If specified the configuration on the appliances will be
saved"""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)

    logger.info("Attempting to add domain {} to {}".format(
        domain_name, str(env.appliances)))
    kwargs = {'name': domain_name}
    responses = env.perform_async_action('add_domain', **kwargs)
    logger.debug("Responses received: {}".format(str(responses)))

    if web:
        output = util.render_boolean_results_table(
            responses, suffix="add_domain")

    kwargs = {'domain': 'default'}
    if save_config:
        logger.info(
            "Attempting to save configuration of default domain on {}".format(
                str(env.appliances)))
        responses = env.perform_async_action('SaveConfig', **kwargs)
        logger.debug("Responses received: {}".format(str(responses)))
        if web:
            output += util.render_boolean_results_table(
                responses,
                suffix="save_config")
    if web:
        return output, util.render_history(env)


@cli.command('del-domain', category='domains')
def del_domain(appliances=[], credentials=[],
               timeout=120, Domain="",
               save_config=False, no_check_hostname=False, web=False):
    """Removes a domain from the specified appliances

Parameters:

* Domain - The name of the domain to remove
* save_config - If specified the configuration on the appliances will be
saved"""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)

    logger.info("Attempting to remove domain {} from {}".format(
        Domain, str(env.appliances)))
    kwargs = {'name': Domain}
    responses = env.perform_async_action('del_domain', **kwargs)
    logger.debug("Responses received: {}".format(str(responses)))

    if web:
        output = util.render_boolean_results_table(responses)

    kwargs = {'domain': 'default'}
    if save_config:
        logger.info(
            "Attempting to save configuration of default domain for {}".format(
                str(env.appliances)))
        responses = env.perform_async_action('SaveConfig', **kwargs)
        logger.debug("Responses received: {}".format(str(responses)))
        if web:
            output += util.render_boolean_results_table(
                responses, suffix="del_domain")
    if web:
        return output, util.render_history(env)


@cli.command('quiesce-domain', category='domains')
def quiesce_domain(appliances=[], credentials=[],
               timeout=120, Domain="",
               quiesce_timeout=60, no_check_hostname=False, web=False):
    """Quiesces a domain on the specified appliances

Parameters:

* Domain - The domain to quiesce
* quiesce_timeout - The timeout before quiescing the domain"""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    logger.info("Attempting to quiesce domain {} for {}".format(
        Domain, str(env.appliances)))
    kwargs = {'name': Domain, 'timeout': str(quiesce_timeout), 'domain': Domain}
    responses = env.perform_async_action('DomainQuiesce', **kwargs)
    logger.debug("Responses received: {}".format(str(responses)))
    if web:
        return (
            util.render_boolean_results_table(
                responses, suffix="DomainQuiesce"), util.render_history(env))


@cli.command('unquiesce-domain', category='domains')
def unquiesce_domain(appliances=[], credentials=[],
               timeout=120, Domain="", no_check_hostname=False, web=False):
    """Unquiesces a domain on the specified appliances

Parameters:

* Domain - The domain to unquiesce"""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    logger.info("Attempting to unquiesce domain {} on {}".format(
        Domain, env.appliances))
    kwargs = {'name': Domain}
    responses = env.perform_async_action('DomainUnquiesce', **kwargs)
    logger.debug("Responses received: {}".format(str(responses)))

    if web:
        return util.render_boolean_results_table(
            responses, suffix="unquiesce_domain"), util.render_history(env)


@cli.command('disable-domain', category='domains')
def disable_domain(appliances=[], credentials=[],
               timeout=120, Domain=[],
               save_config=False, no_check_hostname=False, web=False):
    """Disables a domain on the specified appliances

Parameters:

* Domain - The domain to disable
* save_config - If specified the configuration on the appliances will
be saved

    >>> result = system.disable_domain(
    ...     appliances=["localhost"],
    ...     credentials=["user:pass"],
    ...     timeout=120,
    ...     Domain=["testdomain1"],
    ...     save_config=True,
    ...     web=False)
    >>> print result
    None
    >>> print len(APPLIANCES[0]._history)
    2
    >>> result = system.disable_domain(
    ...     appliances=["localhost"],
    ...     credentials=["user:pass"],
    ...     timeout=120,
    ...     Domain=["all-domains"],
    ...     save_config=True,
    ...     web=False)
    >>> print len(APPLIANCES[1]._history)
    7
"""
    logger = make_logger("mast.system")
    if isinstance(Domain, basestring):
        Domain = Domain
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)

    logger.info("Attempting to disable domains {} on {}".format(
        str(Domain), str(env.appliances)))
    output = ""
    resp = {}
    for appliance in env.appliances:
        domains = Domain
        if "all-domains" in domains:
            domains = appliance.domains
            domains.remove("default")
        for domain in domains:
            logger.info("Attempting to disable {} on {}".format(
                domain, appliance.hostname))
            resp[appliance.hostname] = appliance.disable_domain(domain)
            logger.debug(
                "Response received: {}".format(resp[appliance.hostname]))

            if web:
                output += util.render_boolean_results_table(
                    resp, suffix="disable_domain_{}_{}".format(
                        appliance.hostname, domain))

    if save_config:
        for appliance in env.appliances:
            domains = Domain
            if "all-domains" in domains:
                domains = appliance.domains
            for domain in domains:
                logger.info(
                    "Attempting to save configuration of {} on {}".format(
                        domain, appliance))
                resp[appliance.hostname] = appliance.SaveConfig(domain=domain)
                logger.debug("Response received: {}".format(
                    resp[appliance.hostname]))

                if web:
                    output += util.render_boolean_results_table(
                        resp, suffix="save_config_{}_{}".format(
                            appliance.hostname, domain))
    if web:
        return output, util.render_history(env)


@cli.command('enable-domain', category='domains')
def enable_domain(appliances=[], credentials=[],
               timeout=120, Domain=[],
               save_config=False, no_check_hostname=False, web=False):
    """Enables a domain on the specified appliances

Parameters:

* Domain - The name of the domain to enable
* save-config - If specified the configuration on the appliances
will be saved

    >>> result = system.enable_domain(
    ...     appliances=["localhost"],
    ...     credentials=["user:pass"],
    ...     timeout=120,
    ...     Domain=["testdomain1"],
    ...     save_config=True,
    ...     web=False)
    >>> print result
    None
    >>> print len(APPLIANCES[0]._history)
    2
    >>> result = system.enable_domain(
    ...     appliances=["localhost"],
    ...     credentials=["user:pass"],
    ...     timeout=120,
    ...     Domain=["testdomain1"],
    ...     save_config=False,
    ...     web=False)
    >>> print len(APPLIANCES[1]._history)
    1
"""
    logger = make_logger("mast.system")
    if isinstance(Domain, basestring):
        Domain = [Domain]
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)

    logger.info("Attempting to enable domains {} on {}".format(
        str(Domain), str(env.appliances)))
    output = ""
    resp = {}
    for appliance in env.appliances:
        domains = Domain
        if "all-domains" in domains:
            domains = appliance.domains
            domains.remove("default")
        for domain in domains:
            logger.info("Attempting to enable domain {} on {}".format(
                domain, appliance.hostname))
            resp[appliance.hostname] = appliance.enable_domain(domain)
            logger.debug("Response received: {}".format(
                str(resp[appliance.hostname])))

            if web:
                output += util.render_boolean_results_table(
                    resp, suffix="enable_domain_{}_{}".format(
                        appliance.hostname, domain))

    if save_config:
        for appliance in env.appliances:
            domains = Domain
            if "all-domains" in domains:
                domains = appliance.domains
            for domain in domains:
                logger.info(
                    "Attempting to save configuration of {} on {}".format(
                        domain, appliance.hostname))
                resp[appliance.hostname] = appliance.SaveConfig(domain=domain)
                logger.debug("Response received: {}".format(
                    resp[appliance.hostname]))

                if web:
                    output += util.render_boolean_results_table(
                        resp, suffix="save_config_{}_{}".format(
                            appliance.hostname, domain))
    if web:
        return output, util.render_history(env)
#
#~#~#~#~#~#~#~#

#~#~#~#~#~#~#~#
# appliances
# ==========
#
# These functions are meant to affect the DataPower appliances
# as a whole.
#
# current commands
# ----------------
# quiesce-appliance - Quiesce the specified DataPower appliances
# unquiesce-appliance - Unquiesce the specified DataPower appliances
# reboot-appliance - Reboot the specified appliance.
# shutdown-appliance - Shutdown the specified appliance.


@cli.command('quiesce-appliance', category='appliances')
def quiesce_appliance(appliances=[], credentials=[],
               timeout=120, quiesce_timeout=60, no_check_hostname=False, web=False):
    """Quiesce the specified appliances

Parameters:

* quiesce-timeout - The timeout before quiescing the domain

    >>> result = system.quiesce_appliance(
    ...     appliances=["localhost"],
    ...     credentials=["user:pass"],
    ...     timeout=120,
    ...     quiesce_timeout=60,
    ...     web=False)
    <BLANKLINE>
    localhost
    *********
    <BLANKLINE>
    <env:Envelope xmlns:dp="http://www.datapower.com/schemas/management" \
xmlns:env="http://schemas.xmlsoap.org/soap/envelope/">
      <env:Body>
        <dp:response>
          <dp:timestamp>2015-01-12T17:20:26-05:00</dp:timestamp>
          <dp:result>      OK     </dp:result>
        </dp:response>
      </env:Body>
    </env:Envelope>
    <BLANKLINE>
    >>> print result
    None
    >>> print len(APPLIANCES[0]._history)
    1
"""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    logger.info("Attempting to quiesce appliances {}".format(
        str(env.appliances)))
    kwargs = {'timeout': str(quiesce_timeout)}
    responses = env.perform_action('QuiesceDP', **kwargs)
    logger.debug("Responses received: {}".format(str(responses)))

    if web:
        return util.render_boolean_results_table(
            responses, suffix="quiesce_dp"), util.render_history(env)

    for host, resp in responses.items():
        print '\n', host, '\n', '*' * len(host), '\n'
        print resp.pretty


@cli.command('unquiesce-appliance', category='appliances')
def unquiesce_appliance(appliances=[], credentials=[],
                        timeout=120, no_check_hostname=False, web=False):
    """Unquiesce the specified appliances"""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    logger.info("Attempting to unquiesce {}".format(str(env.appliances)))
    responses = env.perform_action('UnquiesceDP')
    logger.debug("Responses received: {}".format(str(responses)))

    if web:
        return util.render_boolean_results_table(
            responses, suffix="unquiesce_dp"), util.render_history(env)

    for host, resp in responses.items():
        print '\n', host, '\n', '*' * len(host), '\n'
        print resp.pretty


@cli.command('reboot-appliance', category='appliances')
def reboot_appliance(appliances=[], credentials=[],
               timeout=120, delay=10, wait=1200, no_check_hostname=False, web=False):
    """Reboot the specified appliances

Parameters:

* delay - The delay before rebooting
* wait - The amount of time to wait for all appliances
to come back up

    >>> result = system.reboot_appliance(
    ...     appliances=["localhost"],
    ...     credentials=["user:pass"],
    ...     timeout=120,
    ...     delay=1,
    ...     wait=120,
    ...     web=False)  # doctest: +NORMALIZE_WHITESPACE
        All appliances are back up
    >>> print result
    None
    >>> print len(APPLIANCES[0]._history)
    2
"""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    logger.info("Attempting to reboot {}".format(str(env.appliances)))
    kwargs = {'Mode': 'reboot', 'Delay': str(delay)}
    responses = env.perform_action('Shutdown', **kwargs)
    logger.debug("Responses received: {}".format(str(responses)))

    sleep(delay)
    start = time()
    while True:
        reachable_appliances = []
        for appliance in env.appliances:
            if appliance.is_reachable():
                logger.info('{} is Back online.'.format(appliance.hostname))
                reachable_appliances.append(appliance.hostname)
            else:
                logger.info('No response from {}'.format(appliance.hostname))
        if len(env.appliances) == len(reachable_appliances):
            logger.info("All appliances are back online")
            print "\tAll appliances are back up"
            break
        else:
            if (time() - start) >= wait:
                logger.warn(
                    "a timeout accurred waiting for"
                    " all appliances to come back up")
                break
        sleep(5)

    if web:
        return util.render_boolean_results_table(
            responses, suffix="reboot_appliance"), util.render_history(env)


@cli.command('shutdown-appliance', category='appliances')
def shutdown_appliance(appliances=[], credentials=[],
               timeout=120, delay=10, no_check_hostname=False, web=False):
    """Shutdown the specified appliances

Parameters:

* delay - The delay before shutting down"""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)

    logger.info("Attempting to shutdown {}".format(str(env.appliances)))
    kwargs = {'Mode': 'halt', 'Delay': str(delay)}
    responses = env.perform_action('Shutdown', **kwargs)
    logger.debug("Responses received: {}".format(str(responses)))

    if web:
        return util.render_boolean_results_table(
            responses, suffix="shutdown-appliance"), util.render_history(env)

    for host, resp in responses.items():
        print '\n', host, '\n', '*' * len(host), '\n'
        print resp.pretty


@cli.command('reload-appliance', category='appliances')
def reload_appliance(appliances=[], credentials=[],
                 timeout=120, delay=10, wait=180, no_check_hostname=False, web=False):
    """Reload the specified appliances

Parameters:

* delay - The delay before shutting down
* wait - The amount of time to wait for the appliance to come back up"""
    logger = make_logger("mast.system")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)

    kwargs = {'Mode': 'reload', 'Delay': str(delay)}

    resp = {}
    for appliance in env.appliances:
        logger.info("Attempting to reload {}".format(appliance.hostname))
        resp[appliance.hostname] = appliance.Shutdown(**kwargs)
        logger.debug("Response received: {}".format(resp[appliance.hostname]))
        sleep(delay)
        start = time()
        while True:
            if appliance.is_reachable():
                logger.info("Appliance {} is back online".format(
                    appliance.hostname))
                break
            sleep(3)
            if (time() - start) > wait:
                logger.warn(
                    "appliance {} failed to come back online within the specified timeout".format(appliance.hostname))
                resp[appliance.hostname] = False
                break

    if web:
        return util.render_boolean_results_table(
            resp, suffix="reload_appliance"), util.render_history(env)

    for host, _resp in resp.items():
        print '\n', host, '\n', '*' * len(host), '\n'
        if _resp is False:
            print "Appliance did not come back up"
        else:
            print _resp.pretty


@cli.command('firmware-upgrade', category='appliances')
def firmware_upgrade(appliances=[], credentials=[], timeout=1200,
                     file_in=None, accept_license=False,
                     out_dir="tmp", quiesce_timeout=120,
                     reboot_delay=5, reboot_wait=1200,
                     boot_delete=True, no_check_hostname=False, web=False):
    """This will attempt to upgrade the firmware of the specified
appliances.

Parameters:

* file_in - The patch (upgrade script usually *.scrypt4, *.scrypt3 etc...)
* accept_license - Whether to accept the license of the new firmware
(You **MUST** Leave this checked or the upgrade will not work)
* reload - Whether to reload the appliance"""
    logger = make_logger("mast.system")
    if web:
        from backups import get_normal_backup
    else:
        #lint:disable
        from bin.backups import get_normal_backup
        #lint:enable
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)

    logger.info("Attempting to upgrade the firmware of {}".format(
        str(env.appliances)))
    if web:
        output = ""
        history = ""

    for appliance in env.appliances:

        # TODO: Clean-up filesystem > make optional
        logger.info("Cleaning up the filesystem of {}".format(
            appliance.hostname))
        resp, hist = clean_up(
            appliance.hostname,
            appliance.credentials,
            "default",
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            timeout,
            out_dir,
            web)
        logger.debug("responses received: {}".format(str(resp)))

        if web:
            output += resp
            history += hist

        if boot_delete:
            logger.info("Attempting to perform boot delete on {}".format(
                appliance.hostname))
            appliance.ssh_connect()
            r = appliance.ssh_issue_command("co")
            r += appliance.ssh_issue_command("flash")
            r += appliance.ssh_issue_command("boot delete")
            r += appliance.ssh_issue_command("exit")
            r += appliance.ssh_issue_command("exit")
            r += appliance.ssh_issue_command("exit")
            logger.debug("Responses received: {}".format(str(r)))

        # TODO: Get all-domains backup > make optional
        logger.info("Attempting to perform all-domains backup on {}".format(
            appliance.hostname))
        resp, hist = get_normal_backup(
            appliance.hostname,
            appliance.credentials,
            timeout,
            "all-domains",
            "pre-firmware_upgrade_backup",
            out_dir,
            web=web)
        logger.debug("Responses received: {}".format(str(resp)))

        if web:
            output += resp
            history += hist

        # TODO: Clean-up filesystem > make optional

        logger.info("Cleaning up the filesystem of {}".format(
            appliance.hostname))
        resp, hist = clean_up(
            appliance.hostname,
            appliance.credentials,
            "default",
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            timeout,
            out_dir,
            web)
        logger.debug("responses received: {}".format(str(resp)))

        if web:
            output += resp
            history += hist

        # TODO: save the config > make optional
        logger.info(
            "Attempting to save the configuration of all-domains on {}".format(
                appliance.hostname))
        resp, hist = save_config(
            appliance.hostname,
            appliance.credentials,
            timeout,
            ["all-domains"],
            web)
        logger.debug("Responses received: {}".format(resp))

        if web:
            output += resp
            history += hist

        # TODO: quiesce appliance > make optional
        logger.info("Attempting to quiesce appliance {}".format(
            appliance.hostname))
        resp, hist = quiesce_appliance(
            appliance.hostname,
            appliance.credentials,
            timeout,
            quiesce_timeout,
            web)
        logger.debug("Response received: {}".format(resp))

        if web:
            output += resp
            history += hist

        sleep(quiesce_timeout)

        # TODO: disable all domains except default > make optional
        for domain in appliance.domains:
            if domain not in "default":
                logger.info("Attempting to disable domain {} on {}".format(
                    domain, appliance.hostname))
                resp, hist = disable_domain(
                    appliance.hostname,
                    appliance.credentials,
                    timeout,
                    domain,
                    False,
                    web)
                logger.debug("Response received: {}".format(resp))

                if web:
                    output += resp
                    history += hist

        # TODO: Save the config > make optional
        logger.info(
            "Attempting to save configuration of all-domains on {}".format(
                appliance.hostname))
        resp, hist = save_config(
            appliance.hostname,
            appliance.credentials,
            timeout,
            "all-domains",
            web)
        logger.debug("Responses received: {}".format(resp))

        if web:
            output += resp
            history += hist

        # TODO: reboot > make optional
        logger.info("Attempting to reboot {}".format(appliance.hostname))
        resp, hist = reboot_appliance(
            appliance.hostname,
            appliance.credentials,
            timeout,
            reboot_delay,
            reboot_wait,
            web)
        logger.debug("Responses received: {}".format(resp))

        if web:
            output += resp
            history += hist

        # TODO: set the firmware image > make optional
        logger.info("Attempting to set firmware on {}".format(
            appliance.hostname))
        resp = appliance.set_firmware(
            file_in,
            accept_license,
            timeout)
        logger.debug("Responses received: {}".format(resp))

        resp = util.render_boolean_results_table({appliance.hostname: resp})

        if web:
            output += resp
            history += hist

        sleep(60)

        logger.debug("Waiting for {} to come back online".format(
            appliance.hostname))
        start = time()
        while True:
            if appliance.is_reachable():
                logger.info("Appliance is back up.")
                break
            if time() - start > timeout:
                logger.error(
                    "Appliance did not come back up within specified time"
                    "Aborting the remaining firmware upgrades!")

        # TODO: verify version
        # Not implemented yet

        # TODO: enable domains > make optional
        for domain in appliance.domains:
            if domain not in "default":
                logger.info("Attempting to enable domain {} on {}".format(
                    domain, appliance.hostname))
                resp, hist = enable_domain(
                    appliance.hostname,
                    appliance.credentials,
                    timeout,
                    domain,
                    False,
                    web)
                logger.debug("Response received: {}".format(resp))

                if web:
                    output += resp
                    history += hist

    if web:
        return output, history
#
#~#~#~#~#~#~#~#

#~#~#~#~#~#~#~#
# file management
# ===============
#
# These functions are meant to facilitate common filesystem related tasks
# such as setting a file, removing a file, fetching a file or getting a file
# to/from the specified appliances
#


@cli.command('get-encrypted-filesystem', category='file management')
def get_encrypted_filesystem(appliances=[], credentials=[], timeout=120,
    out_dir="tmp", no_check_hostname=False, web=False):
    """This will get a directory listing of all locations within the
encrypted filesystem."""
    logger = make_logger("mast.system")
    t = Timestamp()
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)

    logger.info("Attempting to get a listing of encrypted filesystem")
    resp = env.perform_action("get_encrypted_filesystem")
    logger.info("Response received: {}".format(resp))

    out_dir = os.path.join(out_dir, t.timestamp)
    os.makedirs(out_dir)

    for host, r in resp.items():
        filename = os.path.join(
            out_dir, "{}-encrypted-filesystem.xml".format(host))
        logger.info("Writing directory listing to {}".format(filename))
        with open(filename, 'wb') as fout:
            fout.write(r.pretty)

    if web:
        return util.render_see_download_table(
            resp, suffix="get_encrypted_filesystem"), util.render_history(env)


@cli.command('get-temporary-filesystem', category='file management')
def get_temporary_filesystem(appliances=[], credentials=[],
                             timeout=120, out_dir="tmp",
                             no_check_hostname=False, web=False):
    """This will get a directory listing of all locations within the
temporary filesystem"""

    logger = make_logger("mast.system")
    t = Timestamp()
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)

    logger.info(
        "Attempting to get a listing of temporary filesystem of {}".format(
            str(env.appliances)))
    resp = env.perform_action("get_temporary_filesystem")
    logger.debug("response received: {}".format(resp))

    out_dir = os.path.join(out_dir, t.timestamp)
    os.makedirs(out_dir)

    for host, r in resp.items():
        filename = os.path.join(
            out_dir, "{}-temporary-filesystem.xml".format(host))
        logger.info("Writing listing of temporary filesystem to {}".format(
            filename))
        with open(filename, 'wb') as fout:
            fout.write(r.pretty)

    if web:
        return util.render_see_download_table(
            resp, suffix="get_temporary_filesystem"), util.render_history(env)


@cli.command('get-filestore', category='file management')
def get_filestore(appliances=[], credentials=[],
                  timeout=120, Domain="",
                  location="local:", out_dir="tmp",
                  no_check_hostname=False, web=False):
    """This will get the directory listing of the specified location."""

    logger = make_logger("mast.system")
    t = Timestamp()
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)

    logger.info("Attempting to retrieve directory listing of {} in {}".format(
        str(env.appliances), location))
    resp = env.perform_action(
        "get_filestore",
        domain=Domain,
        location=location)
    logger.debug("Response received: {}".format(resp))

    out_dir = os.path.join(out_dir, t.timestamp)
    os.makedirs(out_dir)

    for host, r in resp.items():
        filename = os.path.join(
            out_dir, "{}-get-filestore.xml".format(host))
        logger.info("Writing directory listing of {} to {}".format(
            str(env.appliances), filename))
        with open(filename, 'wb') as fout:
            fout.write(r.pretty)

    if web:
        return util.render_see_download_table(
            resp, suffix="get_filestore"), util.render_history(env)


@cli.command('copy-file', category='file management')
def copy_file(appliances=[], credentials=[], timeout=120,
    Domain="", src="", dst="", overwrite=True, no_check_hostname=False, web=False):
    """Copies a file from src to dst (both src and dst are on the appliance)
optionally overwriting dst.

Parameters:
* Domain - The domain for both src and dst
* src - The path to the source file (on the appliance(s))
* dst - The destination of the copied file (on the appliances)
* overwrite - Whether to overwrite dst if it exists
"""
    logger = make_logger("mast.system")
    import base64
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)

    resp = {}
    for appliance in env.appliances:
        logger.info("Attempting to copy file on {} from {} to {}".format(
            appliance.hostname,
            src,
            dst))
        fin = appliance.getfile(domain=Domain, filename=src)
        fout = base64.encodestring(fin)
        resp[appliance.hostname] = appliance._set_file(
            fout, dst, Domain, overwrite)
        logger.debug("Response received: {}".format(resp[appliance.hostname]))
    if web:
        return util.render_boolean_results_table(resp), util.render_history(env)
    for host, r in resp.items():
        print host
        print "=" * len(host)
        if r:
            print "Success"
        else:
            print "Failed"


@cli.command('set-file', category='file management')
def set_file(appliances=[], credentials=[], timeout=120,
             file_in=None, destination=None, Domain='default',
             overwrite=True, no_check_hostname=False, web=False):
    """Uploads a file to the specified appliances

Parameters:

* file-in - The path and filename of the file to upload
* destination - Should be the path and filename of the file
once uploaded to the DataPower **NOTE: file_out should contain
the filename ie. local:/test.txt**
* Domain - The domain to which to upload the file"""
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)
    kwargs = {
        'file_in': file_in,
        'file_out': destination,
        'domain': Domain,
        'overwrite': overwrite}
    resp = env.perform_async_action('set_file', **kwargs)

    if web:
        return util.render_boolean_results_table(
            resp, suffix="set_file"), util.render_history(env)


@cli.command('get-file', category='file management')
def get_file(appliances=[], credentials=[], timeout=120,
             location=None, Domain='default', out_dir='tmp',
             no_check_hostname=False, web=False):
    """Uploads a file to the specified appliances

Parameters:

* location - The location of the file (on DataPower) you would
like to get
* Domain - The domain from which to get the file
* out-dir - (NOT NEEDED IN THE WEB GUI)The directory you would like to
save the file to"""

    t = Timestamp()
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)
    kwargs = {'domain': Domain, 'filename': location}
    responses = env.perform_async_action('getfile', **kwargs)

    if not os.path.exists(out_dir) or not os.path.isdir(out_dir):
        os.makedirs(out_dir)

    for hostname, fin in list(responses.items()):
        filename = location.split('/')[-1]
        filename = os.path.join(
            out_dir,
            '%s-%s-%s' % (hostname, t.timestamp, filename))
        with open(filename, 'wb') as fout:
            fout.write(fin)
    if web:
        return util.render_see_download_table(
            responses, suffix="get_file"), util.render_history(env)


@cli.command('del_file', category="file management")
def delete_file(appliances=[], credentials=[], timeout=120,
    Domain="", filename="", backup=False, out_dir="tmp",
    no_check_hostname=False, web=False):
        """
        Deletes a file from the specified appliances.
        """
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)
    if backup:
        resp = {}
        for appliance in env.appliances:
            _out_dir = os.path.join(out_dir, appliance.hostname)
            if not os.path.exists(_out_dir):
                os.makedirs(_out_dir)
            resp[appliance.hostname] = appliance.del_file(
                filename=filename, domain=Domain,
                backup=True, local_dir=_out_dir)
    else:
        resp = env.perform_action("del_file", filename=filename, domain=Domain)
    if web:
        return util.render_boolean_results_table(resp), util.render_history(env)
    for host, response in resp.items():
        print host
        print "=" * len(host)
        if response:
            print "Success"
        else:
            print "Error"
        print


@cli.command('get-error-reports', category='file management')
def get_error_reports(appliances=[], credentials=[], timeout=120,
                      out_dir="tmp", no_check_hostname=False, web=False):
    """This will attempt to retireve any error reports from the
currently configured location on the DataPower appliances"""
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)

    t = Timestamp()
    _pmr_create_dirs(env.appliances, out_dir, t.timestamp)
    ers = _pmr_get_error_report_settings(env.appliances)
    _pmr_download_error_reports(env.appliances, out_dir, ers, t.timestamp)

    # Quick hack to let render_see_download_table() to get the appliance names
    _ = {}
    for appliance in env.appliances:
        _[appliance.hostname] = None
    if web:
        return util.render_see_download_table(
            _, suffix="get_error_reports"), util.render_history(env)


@cli.command('copy-directory', category='file management')
def copy_directory(appliances=[], credentials=[], timeout=120,
                   location="", out_dir="tmp", Domain="",
                   recursive=False, no_check_hostname=False, web=False):
    """This will get all of the files from a directory on the appliances
in the specified domain."""
    t = Timestamp()
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)

    for appliance in env.appliances:
        _out_dir = os.path.join(out_dir, t.timestamp, appliance.hostname)
        if not os.path.exists(_out_dir) or not os.path.isdir(_out_dir):
            os.makedirs(_out_dir)
        appliance.copy_directory(
            location, _out_dir, Domain, recursive=recursive)

    # Quick hack to let render_see_download_table() to get the appliance names
    _ = {}
    for appliance in env.appliances:
        _[appliance.hostname] = None
    if web:
        return util.render_see_download_table(
            _, suffix="copy_directory"), util.render_history(env)
#
#~#~#~#~#~#~#~#

#~#~#~#~#~#~#~#
# auditing
# ========
#
# These functions are meant to help with accountability. They invlove
# log files as well as object auditing and gathering information necessary
# in order to submit a PMR
#
# current commands
# ----------------
# fetch-logs - Retrieves a copy of all log files on the appliance
# get-pmr-info - Retrieves the information necessary to submit a PMR
# object-audit - Retrieves a diff of the running and persisted configurations


@cli.command('fetch-logs', category='auditing')
def fetch_logs(appliances=[], credentials=[],
               timeout=120, out_dir='tmp', no_check_hostname=False, web=False):
    """Fetch all log files from the specified appliances"""
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)
    kwargs = {'log_dir': out_dir}
    resp = env.perform_async_action('get_all_logs', **kwargs)

    if web:
        return util.render_see_download_table(
            resp, suffix="fetch_logs"), util.render_history(env)


@cli.command('get-pmr-info', category='auditing')
def get_pmr_info(appliances=[], credentials=[],
                 timeout=120, out_dir='tmp', no_check_hostname=False, web=False):
    """Get all posible troubleshooting information from the
specified appliances"""
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)

    t = Timestamp()
    _pmr_create_dirs(env.appliances, out_dir, t.timestamp)
    ers = _pmr_get_error_report_settings(env.appliances)
    _pmr_conditionally_save_internal_state(env.appliances, ers, t.timestamp)
    _pmr_generate_error_reports(env.appliances)
    _pmr_backup_all_domains(env.appliances, out_dir, t.timestamp)
    _pmr_query_status_providers(env.appliances, out_dir, t.timestamp)
    _pmr_download_error_reports(env.appliances, out_dir, ers, t.timestamp)
    _pmr_cleanup(env.appliances, out_dir, t.timestamp)

    # Quick hack to let render_see_download_table() to get the appliance names
    resp = {}
    for appliance in env.appliances:
        resp[appliance.hostname] = None
    if web:
        return util.render_see_download_table(
            resp, suffix="get_pmr_info"), util.render_history(env)


@cli.command('object-audit', category='auditing')
def objects_audit(appliances=[], credentials=[],
               timeout=120, out_dir='tmp', no_check_hostname=False, web=False):
    """Get a "diff" of the current and persisted configuration"""
    t = Timestamp()
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)
    results = env.perform_async_action('object_audit')

    for hostname, audit in list(results.items()):
        filename = os.path.join(out_dir, hostname, 'object_audit', t.timestamp)
        os.makedirs(filename)
        filename = os.path.join(filename, 'object-audit.xml')
        with open(filename, 'w') as fout:
            fout.write(audit)
    if web:
        return util.render_see_download_table(
            results, suffix="object_audit"), util.render_history(env)


#@cli.command('memory-must-gather', category='auditing')
#def must_gather(appliances=[], credentials=[],
                #out_dir='tmp', mem_report_dest="local:///nbleak-usage.txt"):
    #env = datapower.Environment(appliances, credentials)
    #t = Timestamp()
    #command_list = ['top', 'show clock', 'show load', 'show cpu',
         #'show throughput', 'show tcp', 'show int',
         #'diag', 'show memory', 'show memory details',
         #'show connections', 'show handles', 'show activity 50',
         #'show memory live', "save memory report %s" % (mem_report_dest),
         #'exit']

    #for appliance in env.appliances:
        #filename = os.path.join(
            #out_dir, appliance.hostname, 'must-gather', t.timestamp)
        #os.makedirs(filename)
        #filename = os.path.join(filename, 'MemoryGrowth-MustGather.txt')
        #with open(filename, 'w') as fout:
            #fout.write(
                #appliance.ssh_connect().replace(
                    #appliance.credentials.split(':')[-1],
                    #''))
            #asic = appliance.ssh_issue_command
            #fout.write(asic("top"))
            #fout.write(asic("diag"))
            #fout.write(asic("set-memory nbleak immediate"))
            #fout.write(asic("set-tracing on memory"))
            #_r = asic("show status")
            #assert 'Memory Module: nbleak' in _r
            #assert 'Memory accounting: enabled' in _r
            #fout.write(_r)
            #for command in command_list:
                #fout.write(asic(command))
            #appliance.ssh_disconnect()
        #filename = '%s-nbleak-usage-%s.txt' % (appliance.hostname, t.timestamp)
        #filename = os.path.join(out_dir, filename)
        #with open(filename, 'w') as fout:
            #fout.write(appliance.getfile('default', mem_report_dest))


@cli.command('get-status', category='auditing')
def get_status(appliances=[], credentials=[],
               timeout=120, StatusProvider=[],
               Domain='default', out_file=None,
               machine=False, no_check_hostname=False, web=False):
    """This will query the status of the specified appliances in
in the specified Domain for the specified StatusProviders.

Parameters:

* StatusProvider - A list of status providers to query
* Domain - The domain from which to query the status providers"""
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)

    if not web:
        if out_file is not None:
            out_file = open(out_file, 'w')
        else:
            out_file = sys.stdout

    if web:
        output = ""

    for provider in StatusProvider:
        t = Timestamp()

        kwargs = {'provider': provider, 'domain': Domain}
        results = env.perform_async_action('get_status', **kwargs)
        if web:
            output += util.render_status_results_table(
                results, suffix="get_status")

        for hostname, response in results.items():
            if machine:
                status = repr(response)
            else:
                status = str(response)

            header = '\n\n%s - %s - %s\n\n' % (hostname, provider, t.timestamp)
            if not web:
                out_file.write(header + status + '\n')

    if web:
        return output, util.render_history(env)
    if out_file != sys.stdout:
        out_file.close()


@cli.command('get-config', category='auditing')
def get_config(appliances=[], credentials=[],
               timeout=120, ObjectClass="",
               obj_name=None, recursive=False,
               persisted=False, Domain='default',
               out_file=None, no_check_hostname=False, machine=False, web=False):
    """This will get the config of obj_name from the specified
domain on the specified appliances.

Parameters:

* ObjectClass - The class of the object who's config you wish to get
* obj_name - If given, the configuration will be gotten for that object,
otherwise, all objects of class ObjectClass will be provided
* recursive - Whether to recursively get the configuration
* persisted - Whether to get the persisted configuration,
otherwise the running configuration will be provided
* Domain - The domain from which to get the configuration"""
    t = Timestamp()

    if out_file is not None:
        out_file = open(out_file, 'w')
    else:
        out_file = sys.stdout

    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)

    kwargs = {
        '_class': ObjectClass,
        'name': obj_name,
        'recursive': recursive,
        'persisted': persisted,
        'domain': Domain}
    results = env.perform_async_action('get_config', **kwargs)

    if web:
        return util.render_config_results_table(
            results, suffix="get_config"), util.render_history(env)

    for hostname, response in results.items():
        if machine:
            resp = repr(response)
        else:
            resp = str(response)
        header = '\n\n%s - %s - %s\n\n' % (hostname, ObjectClass, t.timestamp)
        out_file.write(header + resp + '\n')

    if out_file != sys.stdout:
        out_file.close()
#
#~#~#~#~#~#~#~#

#~#~#~#~#~#~#~#
# maintenance
# ===========
#
# These functions are meant to perform routine maintenance on the specified
# appliances
#
# current commands
# ----------------
# clean-up - Cleans the filesystem.


@cli.command('clean-up', category='maintenance')
def clean_up(appliances=[], credentials=[],
             Domain='default', checkpoints=False,
             export=False, error_reports=False,
             recursive=False, logtemp=False,
             logstore=False, backup_files=True,
             timeout=120, out_dir='tmp', no_check_hostname=False, web=False):
    """
    ## system.clean_up

    This will clean up the specified appliances filesystem.

Parameters:

* Domain - The domain who's filesystem you would like to clean up
* checkpoints - Whether to cleanup the checkpoints: directory
* export - Whether to clean up the export directory
* logtemp - Whether to clean up the logtemp: directory
* logstore - Whether to clean up the logstore directory
* error-reports - Whether to clean up the error reports
* recursive - Whether to recurse through sub-directories
* backup_files - Whether to backup files before deleting them

    >>> result = system.clean_up(
    ...     ["localhost"],
    ...     ["user:pass"],
    ...     checkpoints=True,
    ...     export=True,
    ...     error_reports=True,
    ...     recursive=True,
    ...     logtemp=True,
    ...     logstore=True,
    ...     backup_files=True)  # doctest: +NORMALIZE_WHITESPACE
        localhost - chkpoints:/ -  Cleaned
        localhost - export:/ -  Cleaned
        localhost - logtemp:/ -  Cleaned
        localhost - logstore:/ -  Cleaned
        localhost - ErrorReports - Cleaned
    >>> print result
    None
    >>> print len(APPLIANCES[0]._history)
    427
    >>> result = system.clean_up(
    ...     ["localhost"],
    ...     ["user:pass"],
    ...     checkpoints=True,
    ...     export=True,
    ...     error_reports=True,
    ...     recursive=True,
    ...     logtemp=True,
    ...     logstore=True,
    ...     backup_files=False)  # doctest: +NORMALIZE_WHITESPACE
        localhost - chkpoints:/ -  Cleaned
        localhost - export:/ -  Cleaned
        localhost - logtemp:/ -  Cleaned
        localhost - logstore:/ -  Cleaned
        localhost - ErrorReports - Cleaned
    >>> print len(APPLIANCES[1]._history)
    247
    >>> result = system.clean_up(
    ...     ["localhost"],
    ...     ["user:pass"],
    ...     checkpoints=False,
    ...     export=False,
    ...     error_reports=False,
    ...     recursive=False,
    ...     logtemp=False,
    ...     logstore=False,
    ...     backup_files=False)
    >>> print len(APPLIANCES[2]._history)
    0
    """
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)

    t = Timestamp()
    dirs = []
    if checkpoints:
        dirs.append('chkpoints:/')
    if export:
        dirs.append('export:/')
    if logtemp:
        dirs.append('logtemp:/')
    if logstore:
        dirs.append('logstore:/')

    if web:
        rows = []
    for appliance in env.appliances:
        if web:
            rows.append((appliance.hostname, ))
        for _dir in dirs:
            _clean_dir(
                appliance,
                _dir,
                Domain,
                recursive,
                backup_files,
                t.timestamp,
                out_dir)
            if web:
                rows.append(("", _dir, "Cleaned"))
            else:
                print '\t', appliance.hostname, "-", _dir, "-", " Cleaned"
        if error_reports:
            _clean_error_reports(
                appliance, Domain,
                backup_files, t.timestamp,
                out_dir)
            if web:
                rows.append(("", "ErrorReports", "Cleaned"))
            else:
                print '\t', appliance.hostname, "-", "ErrorReports - Cleaned"
    if web:
        return flask.render_template(
            "results_table.html",
            header_row=["Appliance", "Location", "Action"],
            rows=rows), util.render_history(env)


def _clean_dir(appliance, _dir, domain, recursive, backup, timestamp, out_dir):
    if backup:
        local_dir = os.path.sep.join(
            os.path.sep.join(_dir.split(':/')).split('/'))
        local_dir = os.path.join(
            out_dir,
            appliance.hostname,
            timestamp,
            domain,
            local_dir)
        os.makedirs(local_dir)
    # if not recursive don't include_directories
    files = appliance.ls(_dir, domain=domain, include_directories=recursive)
    for file in files:
        if ':/' in file:
            _clean_dir(
                appliance,
                file.rstrip("/"),
                domain,
                recursive,
                backup,
                timestamp,
                out_dir)
        else:
            filename = '{}/{}'.format(_dir, file)
            if backup:
                fout = open(os.path.join(local_dir, file), 'wb')
                contents = appliance.getfile(domain, filename)
                fout.write(contents)
                fout.close
            appliance.DeleteFile(domain=domain, File=filename)


# def _clean_error_reports(appliance, domain, backup, timestamp, out_dir):
#     if backup:
#         local_dir = os.path.join(
#             out_dir,
#             appliance.hostname,
#             timestamp,
#             domain,
#             'temporary')
#         os.makedirs(local_dir)
#     files = appliance.ls(
#         'temporary:/',
#         domain=domain,
#         include_directories=False)
#     files = [f for f in files if 'error-report' in f]
#     for _file in files:
#         filename = 'temporary:/{}'.format(_file)
#         if backup:
#             fout = open(os.path.join(local_dir, _file), 'wb')
#             contents = appliance.getfile(domain, filename)
#             fout.write(contents)
#             fout.close
#         appliance.DeleteFile(domain=domain, File=filename)

def _clean_error_reports(appliance, domain, backup, timestamp, out_dir):
    protocol_xpath = datapower.CONFIG_XPATH + "/ErrorReportSettings/Protocol"
    raid_path_xpath = datapower.CONFIG_XPATH + "/ErrorReportSettings/RaidPath"

    if backup:
        local_dir = os.path.join(
            out_dir,
            appliance.hostname,
            timestamp,
            domain,
            'temporary')
        os.makedirs(local_dir)
    ers = appliance.get_config("ErrorReportSettings")
    protocol = ers.xml.find(protocol_xpath).text

    if protocol == 'temporary':
        path = 'temporary:'
        filestore = appliance.get_filestore('default', path)
        _dir = filestore.xml.find('.//location[@name="%s"]' % (path))

    elif protocol == 'raid':
        try:
            path = ers.xml.find(raid_path_xpath).text
        except AttributeError:
            path = ''
        path = "{}/{}".format(appliance.raid_directory, path)
        path = path.rstrip("/")

        filestore = appliance.get_filestore('default', 'local:')
        _dir = filestore.xml.find('.//directory[@name="%s"]' % (path))

    else:
        appliance.log_warn(''.join(
                ('\tThe failure notification looks like it is set for ',
                protocol,
                ', which we do not currently support. Failing back',
                'to temporary:...\n')))
        path = 'temporary:'
        filestore = appliance.get_filestore('default', path)
        _dir = filestore.xml.find('.//location[@name="%s"]' % (path))

    if not _dir:
        appliance.log_warn("There were no error reports found.")
        return

    files = []
    for node in _dir.findall('.//*'):
        if node.tag == "file" and 'error-report' in node.get('name'):
            files.append(node.get('name'))

    for f in files:
        fqp = '%s/%s' % (path, f)
        filename = '%s-%s' % (appliance.hostname, f)
        if backup:
            local_dir = os.path.join(
                out_dir,
                appliance.hostname,
                timestamp,
                domain,
                path.replace(":", "").replace("/", os.path.sep))
            if not os.path.exists(local_dir):
                os.makedirs(local_dir)
            filename = os.path.join(local_dir, filename)
            with open(filename, 'wb') as fout:
                fout.write(appliance.getfile('default', fqp))
        appliance.DeleteFile(domain="default", File=fqp)


def get_data_file(f):
    _root = os.path.dirname(__file__)
    path = os.path.join(_root, "data", f)
    with open(path, "rb") as fin:
        return fin.read()

from mast.plugins.web import Plugin
import mast.plugin_utils.plugin_functions as pf
from functools import partial, update_wrapper


class WebPlugin(Plugin):
    def __init__(self):
        self.route = partial(pf.handle, "system")
        self.route.__name__ = "system"
        self.html = partial(pf.html, "mast.datapower.system")
        update_wrapper(self.html, pf.html)

    def css(self):
        return get_data_file('plugin.css')

    def js(self):
        return get_data_file('plugin.js')
#
#~#~#~#~#~#~#~#

if __name__ == '__main__':
    try:
        cli.Run()
    except AttributeError, e:
        if "'NoneType' object has no attribute 'app'" in e:
            raise NotImplementedError(
                "HTML formatted output is not supported on the CLI")

