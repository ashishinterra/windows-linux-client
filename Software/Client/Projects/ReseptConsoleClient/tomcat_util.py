#!/usr/bin/env python
# -*- coding: utf-8 -*-

KT_CONFIG_TOOL_PATH = "/usr/local/bin/keytalk/ktconfigtool"
AUTH_DELAY = 2
AUTH_USER_LOCKED = 3
PASSWD_EXPIRED = 4

TOMCAT_RENEWAL_SETTINGS = {'Host': {'required': True,
                                    'dependencies': []},

                           'ServerName': {'required': False,
                                          'dependencies': []},

                           'Port': {'required': False,
                                    'dependencies': []},

                           'KeystoreLocation': {'required': False,
                                                'dependencies': []},

                           'KeystorePassword': {'required': False,
                                                'dependencies': []},

                           'KeyTalkProvider': {'required': True,
                                               'dependencies': []},

                           'KeyTalkService': {'required': True,
                                              'dependencies': []},

                           'KeyTalkUser': {'required': True,
                                           'dependencies': []},

                           'KeyTalkPassword': {'required': False,
                                               'dependencies': []}}


class CmdFailedException(Exception):

    def __init__(self, cmd, retval, stdout, stderr):
        super(
            CmdFailedException,
            self).__init__(
            u"{} finished with code {}. Stdout: {}. Stderr: {}".format(
                cmd,
                retval,
                stdout,
                stderr))
        self.cmd = cmd
        self.retval = retval
        self.stdout = stdout
        self.stderr = stderr


def is_tomcat_port(port_string):
    return port_string.isdigit() or port_string.strip() == '*'


def parse_connection_address_from_host(host_string):
    """
    Return the connection address of the specified Host string.

    Examples:
        "localhost:8080" -> (localhost, 8080)
        "localhost" -> (localhost, 8443)
        "localhost:something" -> (localhost, 8443)
    :parm host_string: A string representing the connection address of a host (e.g. localhost:8080)
    """
    groups = host_string.split(':')
    if len(groups) == 1 or not is_tomcat_port(groups[-1]):
        host, port = ':'.join(groups), 8443
    else:
        host, port = ':'.join(groups[:-1]), groups[-1]

    host = "localhost" if host in ("*", "_default_") else host
    try:
        port = int(port)
    except Exception:        # best-effort
        port = 8443
    return (host, port)
