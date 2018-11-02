#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import json
import os
import pwd
import glob
import ssl
import socket
import subprocess

import tomcat_util
import util

# @notice we don't use HOME env. variable ( os.path.expanduser("~") or os.getenv('HOME') ) since when this script gets called with 'sudo'
# it may, depending on the system security policy, give us home directory of the original caller, which is in most cases not what we want.
# For example HOME env. variable (~) is set to target's user in Debian 8
# ('sudo' acts as 'sudo -H') but is preserved in Ubuntu 16 ('sudo' acts as
# 'sudo -E')
HOME_DIR = pwd.getpwuid(os.getuid()).pw_dir
TMP_DIR = os.path.join(HOME_DIR, 'tmp')
KEYSTORE_DIR = os.path.join(HOME_DIR, '.keytalk/keystore')
CONFIG_FILE_PATH = '/etc/keytalk/tomcat.ini'
KTCLIENT_APP_PATH = '/usr/local/bin/keytalk/ktclient'
LOG_FILE_PATH = os.path.join(TMP_DIR, 'kttomcatcertrenewal.log')
CRON_LOG_FILE_PATH = os.path.join(TMP_DIR, 'cron.kttomcatcertrenewal.log')
KTCLIENT_LOG_PATH = os.path.join(HOME_DIR, '.keytalk/ktclient.log')
Logger = util.init_logger(
    'keytalk', LOG_FILE_PATH, "KeyTalk Tomcat certificate renewal", "DEBUG", "INFO")
OS_NAME = util.run_cmd('lsb_release --id --short')

# Globals
error_messages = []
warning_messages = []
all_error_messages = []
all_warning_messages = []
force_arg = '--force'


def is_cert_renewal_needed(site):
    host = site['Host']
    server_name = site.get('ServerName')
    os_name = util.run_cmd('lsb_release --id --short')
    os_major = util.run_cmd(
        'echo $(lsb_release --release --short | egrep -o [0-9]+ | sed -n \'1p\')')

    hostname, port = tomcat_util.parse_connection_address_from_host(host)
    if os_name in ['CentOS', 'RedHatEnterpriseServer'] and os_major == '6':
        try:
            pem_cert = ssl.get_server_certificate((hostname, port), ssl_version=ssl.PROTOCOL_TLSv1)
        except socket.error as e:
            raise Exception(
                'Could not retrieve server certificate from "{}:{}": {}'.format(hostname, port, e))
    else:
        try:
            pem_cert = ssl.get_server_certificate((hostname, port))
        except socket.error as e:
            raise Exception(
                'Could not retrieve server certificate from "{}:{}": {}'.format(hostname, port, e))

    # Check whether the cert is expired
    cert_expired, cert_expiration_utc = util.is_cert_expired(
        pem_cert, host, site['KeyTalkProvider'], site['KeyTalkService'], Logger)
    if cert_expired:
        Logger.info("Certificate for {} {} effectively expires at {} UTC and needs renewal".format(
            host, server_name or '', cert_expiration_utc))
        return True

    # Check whether the cert is revoked
    if util.is_cert_revoked(pem_cert, Logger):
        Logger.info("Certificate for {} {} has been revoked and needs renewal".format(
            host, server_name or ''))
        return True

    # The cert doesn't need renewal
    Logger.info(
        "Certificate for {} {} effectively expires at {} UTC and does not require renewal (run with {} to renew anyway)".format(
            host,
            server_name or '',
            cert_expiration_utc,
            force_arg))
    return False


def get_cert(site):
    quoted_site = util.shellquoted_site(site)
    Logger.info(
        'Retrieving SSL certificate for host at {Host}. Provider {KeyTalkProvider}, service {KeyTalkService}, user {KeyTalkUser}'.format(
            **site))
    cmd = KTCLIENT_APP_PATH + \
        ' --provider {KeyTalkProvider} --service {KeyTalkService} --user {KeyTalkUser}'.format(
            **quoted_site)
    if site['KeyTalkPassword'] is not None:
        cmd += ' --password {KeyTalkPassword} --save-pfx'.format(**quoted_site)

    try:
        util.run_cmd(cmd, Logger, censored_text_list=[site['KeyTalkPassword']])
    except tomcat_util.CmdFailedException as ex:
        if ex.retval == tomcat_util.AUTH_DELAY:
            raise Exception(
                'Authentication to service "{}" of provider "{}" unsuccessful. Invalid credentials, delay before reattempt possible, message: "{}" "{}"'.format(
                    site['KeyTalkService'],
                    site['KeyTalkProvider'],
                    ex.stderr,
                    ex.stdout))
        elif ex.retval == tomcat_util.AUTH_USER_LOCKED:
            raise Exception(
                'Authentication to service "{}" of provider "{}" unsuccessful. User locked out, message: "{}" "{}"'.format(
                    site['KeyTalkService'],
                    site['KeyTalkProvider'],
                    ex.stderr,
                    ex.stdout))
        elif ex.retval == tomcat_util.PASSWD_EXPIRED:
            raise Exception(
                'Authentication to service "{}" of provider "{}" unsuccessful. Password expired, message: "{}" "{}"'.format(
                    site['KeyTalkService'],
                    site['KeyTalkProvider'],
                    ex.stderr,
                    ex.stdout))
        else:
            raise
    pem_cert_key_path = max(glob.glob(KEYSTORE_DIR + '/*.pem'), key=os.path.getctime)
    Logger.debug('Retrieved KeyTalk certificate at ' + pem_cert_key_path)
    return pem_cert_key_path


def log_error(message, summary_message=None):
    error_messages.append(summary_message or message)
    all_error_messages.append(summary_message or message)
    Logger.error(message)


def print_error_summary(errors, warnings):
    if errors:
        Logger.error('Errors summary:')
        for message in errors:
            for line in message.splitlines():
                Logger.error('    %s', line)
        Logger.error(
            'Please check configuration file "%s" and your Tomcat site configurations.',
            CONFIG_FILE_PATH)

    if warnings:
        Logger.error('Warning summary:')
        for message in warnings:
            for line in message.splitlines():
                Logger.error('    %s', line)
        Logger.error(
            'Please check configuration file "%s" and your Tomcat configurations.',
            CONFIG_FILE_PATH)


def make_validation_error_message(validation_errors, host):
    error_summary = []
    if validation_errors:
        error_summary.append('Errors in Host "%s" configuration:' % host)

        for message in validation_errors:
            error_summary.append('\t' + message)

        error_summary.append(
            'Skipping certificate renewal for Host "%s" due to configuration errors' %
            host)
    return "\n".join(error_summary)


def validate_site_configuration(site, valid_vhosts):
    validation_errors = []
    if site['Host'] is not None:
        host = tomcat_util.parse_connection_address_from_host(site['Host'])
        if host not in valid_vhosts:
            if OS_NAME in ["Debian", "Ubuntu"]:
                validation_errors.append(
                    'Tomcat Host "{}:{}" not found.'.format(host[0], host[1]))
            if OS_NAME in ["RedHatEnterpriseServer", "CentOS"]:
                validation_errors.append(
                    'Tomcat Host "{}:{}" not found.'.format(host[0], host[1]))

    keytalk_provider = site['KeyTalkProvider']
    keytalk_service = site['KeyTalkService']
    if keytalk_provider and keytalk_provider not in util.get_keytalk_providers():
        validation_errors.append('Unknown KeyTalkProvider "%s".' % (keytalk_provider))
    elif keytalk_service and keytalk_service not in util.get_keytalk_services(keytalk_provider):
        validation_errors.append(
            'Unknown KeyTalkService "%s" for KeyTalkProvider "%s"."' %
            (keytalk_service, keytalk_provider))

    return validation_errors


def process_host(
        site_configuration,
        current_host_string,
        current_host_name,
        keystore_password,
        keystore_location,
        force_renew_certs):
    global error_messages
    global warning_messages

    current_site = site_configuration
    try:
        # Validation
        parsed_site, validation_errors = util.parse_settings(
            current_site, tomcat_util.TOMCAT_RENEWAL_SETTINGS)
        # parsed_site either contains correctly parsed site settings with populated defaults or None (and a non-empty validation error list).
        # Even if parsing failed, we want to present the user with a complete
        # error list. So for purposes of further validation
        current_site = parsed_site or util.populate_defaults(
            current_site, tomcat_util.TOMCAT_RENEWAL_SETTINGS)

        # validation_errors.extend(validate_site_configuration(current_site, tomcat_hosts.keys()))
        if validation_errors:
            message = make_validation_error_message(validation_errors,
                                                    current_host_string)
            log_error(message)
            raise Exception(
                'Errors during validation of Host "{}, {}".'.format(
                    current_host_string, current_host_name))

        if not os.path.isfile(keystore_location) or\
           force_renew_certs or\
           is_cert_renewal_needed(current_site):
            get_cert(current_site)
            util.run_cmd(
                '/usr/local/bin/keytalk/tomcat.sh {} {}'.format(keystore_password, keystore_location), Logger)

    except Exception as e:
        # Log error, but continue processing the next Host
        log_error(
            'Host "{}, {}": {} {} {}'.format(
                current_host_string,
                current_host_name,
                type(e),
                e,
                util.format_traceback()),
            'Host "{}, {}": {} {}'.format(
                current_host_string,
                current_host_name,
                type(e),
                e))
        return False
    finally:
        error_messages = []
        warning_messages = []

    return True


def main():
    try:
        if os.geteuid() != 0:
            Logger.error('{} must be run as root.'.format(sys.argv[0]))
            sys.exit(1)

        current_host_string = None
        current_host_name = None

        force_renew_certs = len(sys.argv) == 2 and sys.argv[1] == force_arg

        Logger.debug(
            "Starting Tomcat SSL certificate renewal script. Force renewal: {}".format(
                'yes' if force_renew_certs else 'no'))

        with open(CONFIG_FILE_PATH) as f:
            config = util.strip_json_comments(f.read())
            try:
                sites = json.loads(config)
            except Exception as ex:
                raise Exception(
                    'Could not parse configuration file "{}": {}'.format(
                        CONFIG_FILE_PATH, ex))

        for site_index, site in enumerate(sites):
            current_host_string = site.get(
                'Host', 'Host configuration number {}'.format(
                    site_index + 1))
            current_host_name = site.get('ServerName', '')
            keystore_password = site.get('KeystorePassword', '')
            keystore_location = site.get('KeystoreLocation', '')

            process_host(
                site,
                current_host_string,
                current_host_name,
                keystore_password,
                keystore_location,
                force_renew_certs)

    except Exception as e:
        log_error(
            'Host "{}, {}": {} {} {}'.format(
                current_host_string,
                current_host_name,
                type(e),
                e,
                util.format_traceback()),
            'Host "{}, {}": {} {}'.format(
                current_host_string,
                current_host_name,
                type(e),
                e))
        sys.exit(1)
    finally:
        print_error_summary(all_error_messages, all_warning_messages)
        util.close_logger(Logger)
        if all_error_messages:
            sys.exit(1)


#
# Entry point
#
if __name__ == "__main__":
    main()
