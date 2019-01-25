#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import logging
import logging.handlers
import os
import traceback
import sys
import subprocess
import datetime
import time
import codecs
import glob
import smtplib
import tempfile
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
import shutil
import pipes
import OpenSSL

KT_CONFIG_TOOL_PATH = "/usr/local/bin/keytalk/ktconfigtool"
AUTH_DELAY = 2
AUTH_USER_LOCKED = 3
PASSWD_EXPIRED = 4

APACHE_RENEWAL_SETTINGS = {'VHost': {'required': True,
                                     'dependencies': []},

                           'ServerName': {'required': False,
                                          'dependencies': []},

                           'KeyTalkProvider': {'required': True,
                                               'dependencies': []},

                           'KeyTalkService': {'required': True,
                                              'dependencies': []},

                           'KeyTalkUser': {'required': True,
                                           'dependencies': []},

                           'KeyTalkPassword': {'required': False,
                                               'dependencies': []},

                           'EmailNotifications': {'required': False,
                                                  'dependencies': [],
                                                  'default_value': False},

                           'EmailFrom': {'required': True,  # If 'EmailNotifications' present, this field is required
                                         'dependencies': ['EmailNotifications']},

                           'EmailTo': {'required': True,  # If 'EmailNotifications' present, this field is required
                                       'dependencies': ['EmailNotifications']},

                           'EmailSubject': {'required': False,
                                            'dependencies': ['EmailNotifications'],
                                            'default_value': 'Apache certificate renewal'},

                           'EmailServer': {'required': False,
                                           'dependencies': ['EmailNotifications'],
                                           'default_value': 'localhost'}}


class CmdFailedException(Exception):

    def __init__(self, cmd, retval, stdout, stderr):
        super(
            CmdFailedException,
            self).__init__(
            u"{0} finished with code {1}. Stdout: {2}. Stderr: {3}".format(
                cmd,
                retval,
                stdout,
                stderr))
        self.cmd = cmd
        self.retval = retval
        self.stdout = stdout
        self.stderr = stderr


def write_file(path, data):
    with open(path, 'w') as f:
        return f.write(data)


def strip_json_comments(s):
    """Remove one-line comments starting with # or // from JSON-like content and return valid JSON."""
    # we intentionally substitute comment with empty line i.o. removing them
    # in order to preserve line numbers when reporting errors by JSON parser further on
    return re.sub(r"(?m)^\s*(#|//).*$", "", s)


def _parse_log_level(aLevelNameStr):
    for lev in [logging.CRITICAL, logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG]:
        if logging.getLevelName(lev) == aLevelNameStr:
            return lev
    raise Exception("{} is not a valid logging level".format(aLevelNameStr))


def format_traceback():
    tb = traceback.format_tb(sys.exc_info()[2])
    fmt = '\nTraceback:\n'
    for tb_frame in tb:
        fmt = fmt + tb_frame.replace('\n', '').replace('  ', ' ') + '\n'
    return fmt


def init_logger(
        aLoggerName,
        aLogFileName,
        anAppName,
        aFileLogLevelStr="DEBUG",
        aConsoleLogLevelStr="WARNING"):
    log_directory = os.path.dirname(aLogFileName)
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)

    myLogger = logging.getLogger(aLoggerName)
    # @tricky in order to configure per-handler log level we have to set global log level to the most talkative one first
    myLogger.setLevel(logging.DEBUG)

    # log to a file and to the console
    max_log_bytes = 1 * 1024 * 1024
    myFileHandler = logging.handlers.RotatingFileHandler(
        aLogFileName, maxBytes=max_log_bytes, backupCount=5)
    myFileHandler.setFormatter(logging.Formatter('%(asctime)s <' +
                                                 str(os.getpid()) +
                                                 '> [%(levelname)s] %(funcName)s: %(message)s'))
    myFileHandler.setLevel(_parse_log_level(aFileLogLevelStr))

    myConsoleHandler = logging.StreamHandler()
    myConsoleHandler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s]: %(message)s'))
    myConsoleHandler.setLevel(_parse_log_level(aConsoleLogLevelStr))

    myLogger.addHandler(myFileHandler)
    myLogger.addHandler(myConsoleHandler)

    myLogger.info('******************** %s. Logging Started ********************', anAppName)
    return myLogger


def close_logger(aLogger):
    aLogger.info('******************** Logging Finished ********************')


def censor_string(string, censored_text_list):
    """Return a string in which all instances of the censored words are replaced by '<erased>'."""
    censored_string = string
    for censored_text in censored_text_list:
        if censored_text:
            censored_string = censored_string.replace(censored_text, '<erased>')
    return censored_string


def run_cmd(cmd, logger=None, censored_text_list=None):
    """
    Invoke a command and return the standard output on completion.

    In case of errors, exceptions are thrown.
    Note that all occurrences of censored strings are replaced by "<erased>"
    :param cmd: the command to be executed
    :param censored_text_list: a list of strings to be censored in the output of the command and reported exceptions.
    """
    censored = censored_text_list or []
    censored_cmd = censor_string(cmd, censored)

    if logger:
        logger.debug("Executing command: " + str(censored_cmd))

    try:
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        raise Exception("Failed to execute {0}. {1}".format(censored_cmd, e))

    try:
        retval = p.wait()
    except Exception as e:
        raise Exception("Failed to wait for {0} finishes. {1}".format(censored_cmd, e))

    stdout = p.stdout.read().decode('utf-8').strip()
    stderr = p.stderr.read().decode('utf-8').strip()
    if retval == 0:
        return censor_string(stdout, censored)

    raise CmdFailedException(censored_cmd, retval, stdout, stderr)


def is_backup_file_path(path):
    """:returns: True if the given file ends with the backup file suffix."""
    if re.match(r'.*\.orig\.[0-9]+[-][0-9]+', path):
        return True
    return False


def save_to_file(data, target_file, backup=False):
    if backup and os.path.isfile(target_file):
        now = time.time()
        time_string = datetime.datetime.fromtimestamp(now).strftime('%Y%m%d-%H%M%S')
        backup_file = '{0}.orig.{1}'.format(target_file, time_string)
        shutil.copy(target_file, backup_file)

        # Remove old backup files (only keep max_backup_count)
        max_backup_count = 10
        backup_files = sorted(
            glob.glob(
                '{0}.orig.*'.format(target_file)),
            key=lambda x: time.ctime(
                os.path.getctime(x)))
        old_files = backup_files[:-max_backup_count]
        for old_file in old_files:
            os.remove(old_file)

    write_file(target_file, data)


def get_keytalk_providers(logger=None):
    stdout = run_cmd("{0} provider list".format(KT_CONFIG_TOOL_PATH), logger)
    return [provider.strip() for provider in stdout.splitlines() if provider.strip() != '']


def get_keytalk_services(provider, logger=None):
    stdout = run_cmd('{0} service list "{1}"'.format(KT_CONFIG_TOOL_PATH, provider), logger)
    return [provider.strip() for provider in stdout.splitlines() if provider.strip() != '']


def parse_certs(pem_file, logger=None):
    """Return X.509 certificates contained in PEM file."""
    try:
        with codecs.open(pem_file, 'rb', encoding='utf-8', errors='ignore') as f:
            pem = f.read()
            certs = re.findall(
                r"-----BEGIN CERTIFICATE-----\r?\n.+?\r?\n-----END CERTIFICATE-----\r?\n?",
                pem,
                re.DOTALL)
            if logger:
                logger.debug("{0} certificates found in {1}".format(len(certs), pem_file))
            return [cert.strip() for cert in certs]
    except Exception:
        if logger:
            logger.debug("No certificates found in {0}".format(pem_file))
        return []


def parse_keys(pem_file, logger=None):
    """Return non-password protected private keys contained in PEM file."""
    try:
        with codecs.open(pem_file, 'rb', encoding='utf-8', errors='ignore') as f:
            pem = f.read()
            keys = [
                m.group(0) for m in re.finditer(
                    r"-----BEGIN ([A-Z ]*?)PRIVATE KEY-----\r?\n.+?\r?\n-----END \1PRIVATE KEY-----\r?\n?",
                    pem,
                    re.DOTALL)]
            if logger:
                logger.debug("{0} keys found in {1}".format(len(keys), pem_file))
            return [key.strip() for key in keys]
    except Exception:
        if logger:
            logger.debug("No keys found in {0}".format(pem_file))
        return []


def parse_cas(logger=None):
    cas = []
    for pem_file in glob.glob('/etc/keytalk/.keystore/intca/*.pem'):
        cas += parse_certs(pem_file, logger)
    for pem_file in glob.glob('/etc/keytalk/.keystore/rootca/*.pem'):
        cas += parse_certs(pem_file, logger)
    return cas


def same_file(path1, path2):
    """
    Check if two files refer to the same inode.

    :returns: True if both files refer (either as a hard- or a symbolic link) to the same inode represented by a regular file
    :returns: False otherwise
    """
    path1 = path1.strip()
    path2 = path2.strip()

    # resolve symlinks if any
    if os.path.islink(path1):
        path1 = os.readlink(path1)
    if os.path.islink(path2):
        path2 = os.readlink(path2)

    if not os.path.isfile(path1) or not os.path.isfile(path2):
        return False

    if path1 == path2:
        return True

    # same inode (covers hardlinks as well)
    return os.stat(path1).st_ino == os.stat(path2).st_ino


def get_cert_validity(provider, service, logger=None):
    stdout = run_cmd(
        "{0} service getparam {1} {2} CertValidity".format(
            KT_CONFIG_TOOL_PATH,
            provider,
            service),
        logger)
    return stdout


def is_cert_revoked(pem_cert, logger):
    try:
        temp_dir = tempfile.mkdtemp()
        pem_cert_path = os.path.join(temp_dir, "ssl.pem")
        write_file(pem_cert_path, pem_cert)
        stdout = run_cmd(
            "{0} cert is-revoked {1}".format(KT_CONFIG_TOOL_PATH, pem_cert_path), logger)
        return stdout == "revoked"
    finally:
        if temp_dir is not None:
            shutil.rmtree(temp_dir)


def _cert_duration_seconds(not_after, not_before):
    cert_duration = not_after - not_before
    try:
        return cert_duration.total_seconds()
    except AttributeError:
        # python prior to 2.7
        return float(cert_duration.microseconds + (cert_duration.seconds +
                                                   cert_duration.days * 24 * 3600) * 10**6) / float(10**6)


def _parse_cert_validity(validity_str):
    for suffix in ['s', '%']:
        if (validity_str.endswith(suffix)):
            cert_validity = int(validity_str[0:-len(suffix)])
            if (suffix == '%' and (cert_validity < 0 or cert_validity > 100)):
                raise Exception(
                    'Invalid value {0} in the certificate validity string {1}. The value should be between 0 and 100'.format(
                        cert_validity, validity_str))
            return cert_validity, suffix
    # Suffix not recognized
    raise Exception(
        'Failed to get validity value for string {0}. Suffix not found'.format(validity_str))


def is_cert_expired(pem_cert, vhost, provider, service, logger):
    ''' return (cert-expired, cert-expiration-utc) '''
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert)
    not_before = datetime.datetime.strptime(x509.get_notBefore(), "%Y%m%d%H%M%SZ")
    not_after = datetime.datetime.strptime(x509.get_notAfter(), "%Y%m%d%H%M%SZ")
    logger.debug(
        "Certificate validity for {0} : {1} UTC -> {2} UTC".format(vhost, not_before, not_after))

    cert_validity = get_cert_validity(provider, service, logger)
    cert_validity_value, cert_validity_type = _parse_cert_validity(cert_validity)
    if (cert_validity_type == 's'):
        cert_validity_margin_seconds = cert_validity_value
    elif (cert_validity_type == '%'):
        cert_validity_margin_seconds = int(
            (float(cert_valididy_value) / 100) * _cert_duration_seconds(not_after, not_before))
    cert_expiration_utc = not_after - datetime.timedelta(seconds=cert_validity_margin_seconds)

    cert_expired = cert_expiration_utc <= datetime.datetime.utcnow()

    return (cert_expired, cert_expiration_utc)


def send_email(smtp_server_addr, sender, recipients, subject, message, attachments=None):
    """
    Send an e-mail to the specified address.

    :param smtp_server_addr: Address of the SMTP server to use to send this message
    :param sender: Sender e-mail with optional name. (e.g. "John Doe <john@doe.com>" or "john@doe.com")
    :param recipients: List of recipients. (e.g. ["John Doe <john@doe.com>", "Jane Doe <jane@doe.com>"])
    :param subject: E-mail subject
    :param message: The message body
    """
    msg = MIMEMultipart()
    msg['To'] = ', '.join(recipients)
    msg['From'] = sender
    msg['Subject'] = subject

    msg.attach(MIMEText(message, 'plain'))

    atts = attachments or []
    for attachment_name, attached_content in atts:
        msg.attach(MIMEApplication(
            attached_content,
            Content_Disposition='attachment; filename="%s"' % os.path.basename(attachment_name),
            Name=attachment_name
        ))

    server = smtplib.SMTP(smtp_server_addr)
    try:
        server.sendmail(sender, recipients, msg.as_string())
    except smtplib.SMTPException as ex:
        raise Exception(
            'Could not send email to "{0}" via SMTP server "{1}": {2}'.format(
                recipients, smtp_server_addr, ex))
    finally:
        server.quit()


def populate_defaults(settings, scheme):
    """
    Populate a dict with default values from the specified known settings.

    :param settings: dict containing the settings which is updated with default value
    :param scheme: dict containing the possible setting names and setting parameters (see parse_settings documentation for example)
    """
    results = settings.copy()
    for setting_name, props in scheme.iteritems():
        dependencies_met = True
        for dependency in props['dependencies']:
            dependency_met = dependency in settings and settings[dependency] is not None
            dependencies_met &= dependency_met

        if setting_name not in results:
            if 'default_value' in props and dependencies_met:
                results[setting_name] = props['default_value']
            else:
                results[setting_name] = None
    return results


def validate_unknown_settings(settings, scheme):
    """
    Check that all settings in settings are known settings in the given scheme.

    for an example scheme see the documentation of parse_settings.
    :param settings: dict containing the settings
    :param scheme: dict containing the possible setting names and setting parameters (see function documentation for example)
    """
    validation_errors = []
    known_settings = scheme.keys()
    for setting in settings.keys():
        if setting not in known_settings:
            validation_errors.append(
                'Unknown setting "{0}" encountered". Known settings: {1}'.format(
                    setting, known_settings))
    return validation_errors


def parse_settings(settings, scheme):
    """
    Return (settings, []) or (None, validation_errors) upon error.

    All known settings (found in scheme) are defined in the output dict.
    (e.g. None or default value if undefined in input dict)

    An example for the known settings is:
    scheme = {'VHost': {'required': True,
                                 'dependencies': []},

                      'ServerName': {'required': False,
                                     'dependencies': []},

                      'EmailNotifications': {'required': False,
                                             'dependencies': [],
                                             'default_value': False},

                      'EmailSubject': {'required': False,
                                       'dependencies': ['EmailNotifications'],
                                       'default_value': 'Apache certificate renewal'}}
    :param settings: dict containing the settings
    :param scheme: dict containing the possible setting names and setting parameters (see function documentation for example)
    """
    validation_errors = []
    validation_errors.extend(validate_unknown_settings(settings, scheme))
    validation_errors.extend(validate_setting_dependencies(settings, scheme))
    if validation_errors:
        return (None, validation_errors)

    return (populate_defaults(settings, scheme), validation_errors)


def validate_setting_dependencies(settings, scheme):
    """
    Return a list of errors for the given settings dict.

    Note that if a setting has dependencies on optional settings, but is required,
    this means that if all its dependencies are met.

    For example: if the "EmailFrom" setting depends on the "EmailNotifications"
    setting, then this setting is required.

    for an example scheme see the documentation of parse_settings.
    :param settings: dict containing the settings
    :param scheme: dict containing the possible setting names and setting parameters (see function documentation for example)
    """
    validation_errors = []
    for setting_name, props in scheme.iteritems():
        dependencies_met = True
        for dependency in props['dependencies']:
            dependency_met = dependency in settings and settings[dependency] is not None
            dependencies_met &= dependency_met
            if setting_name in settings and settings[
                    setting_name] is not None and not dependency_met:
                validation_errors.append(
                    'Setting "{0}" is required when using "{1}".'.format(
                        dependency, setting_name))

        if props['required'] and (setting_name not in settings or settings[setting_name] is None):
            if not props['dependencies']:
                validation_errors.append('Required setting "{0}" not found.'.format(setting_name))
            elif props['dependencies'] and dependencies_met:
                validation_errors.append(
                    'The current configuration requires setting "{0}".'.format(setting_name))

    return validation_errors


def has_executable(executable_name):
    try:
        run_cmd('which {0}'.format(pipes.quote(executable_name)))
    except Exception:
        return False

    return True


def shellquoted_site(site):
    newdict = {}
    for key, val in site.iteritems():
        if isinstance(val, basestring):
            newdict[key] = pipes.quote(val)
        else:
            newdict[key] = val
    return newdict
