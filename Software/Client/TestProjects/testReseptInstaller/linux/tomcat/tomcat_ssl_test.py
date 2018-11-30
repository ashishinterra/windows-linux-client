#!/usr/bin/env python
# -*- coding: utf-8 -*-


import urllib2
import unittest
import time
import ssl
import os
import re
import sys
from subprocess import Popen, PIPE
import OpenSSL

"""
To run specific test case:
python -m unittest test_module_name.TestClass.test_method
"""


# monkey-patch old version of Python (typically before 2.7)
# to force using more secure SSL protocol version to connect to the webserver
# iso the dated SSLv2 which would cause the webserver to cut connection

if sys.version_info < (2, 7):
    from functools import wraps
    def sslwrap(func):
        @wraps(func)
        def bar(*args, **kw):
            kw['ssl_version'] = ssl.PROTOCOL_TLSv1
            return func(*args, **kw)
        return bar
    ssl.wrap_socket = sslwrap(ssl.wrap_socket)

class TestTomcatSsl(unittest.TestCase):

    def setUp(self):
        # notice we don't use setUpClass() as it is not supported on Python 2.6
        tomcat = ""

        if os.path.isfile("/usr/sbin/tomcat"):
            tomcat = "tomcat"
        elif os.path.isfile("/etc/init.d/tomcat"):
            tomcat = "tomcat"
        elif os.path.isfile("/etc/init.d/tomcat9"):
            tomcat = "tomcat9"
        elif os.path.isfile("/etc/init.d/tomcat8"):
            tomcat = "tomcat8"
        elif os.path.isfile("/etc/init.d/tomcat7"):
            tomcat = "tomcat7"
        elif os.path.isfile("/etc/init.d/tomcat6"):
            tomcat = "tomcat6"
        else:
            tomcat = "tomcat"  # if tomcat is installed from source on any Linux platform and not found under /etc/init.d

        print("Setting up Tomcat SSL test ({0})".format(tomcat))
        if os.system('service {0} status > /dev/null 2>&1 || service {0} start'.format(tomcat)) != 0:
            raise Exception("Failed to start Tomcat")

    def test_ssl_cert_is_renewal_for_host(self):
        # given
        renew_ssl_cert_cmd = '/usr/local/bin/keytalk/renew_tomcat_ssl_cert'
        force_renew_ssl_cert_cmd = renew_ssl_cert_cmd + " --force"
        host = {'host': 'localhost', 'port': 8443, 'renew_enabled': True}
        # when
        print("Forcibly renewing Tomcat SSL certificates")
        p = Popen(force_renew_ssl_cert_cmd, stdout=PIPE, stderr=PIPE, shell=True)
        # then
        out, err = p.communicate()
        self.assertEquals(p.returncode, 0, "Stdout: {0}, Stderr: {1}".format(out, err))
        # wait to renew certificates and restart tomcat
        time.sleep(10)
        print("Checking {host}:{port}, renew enabled: {renew_enabled}".format(**host))
        conn = urllib2.urlopen('https://{host}:{port}'.format(**host))
        html_contents = conn.read()
        self.assertTrue(
            re.search(
                "<h1>(It works !|Index of /)</h1>|<h2>If you're seeing this, you've successfully installed Tomcat. Congratulations!</h2>|If you're seeing this page via a web browser, it means you've setup Tomcat successfully. Congratulations!",
                html_contents) is not None,
            html_contents)
        cert = ssl.get_server_certificate((host['host'], host['port']))
        # save site state for further testing
        host['html_contents'] = html_contents
        host['x509'] = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

        print("Renewing valid Tomcat SSL certificates")
        # wait a bit to notice certificate time difference
        time.sleep(2)
        p = Popen(renew_ssl_cert_cmd, stdout=PIPE, stderr=PIPE, shell=True)
        # then we expect no certificates get renewed because they are still valid
        out, err = p.communicate()
        self.assertEquals(p.returncode, 0, "Stdout: {0}, Stderr: {1}".format(out, err))
        print("Checking {host}:{port}, renew enabled: {renew_enabled}".format(**host))
        conn = urllib2.urlopen('https://{host}:{port}'.format(**host))
        html_contents = conn.read()
        cert = ssl.get_server_certificate((host['host'], host['port']))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        self.assertEquals(html_contents, host['html_contents'])
        self.assertEquals(x509.get_subject(), host['x509'].get_subject())
        self.assertEquals(x509.get_issuer(), host['x509'].get_issuer())
        self.assertEquals(x509.get_serial_number(), host['x509'].get_serial_number())
        self.assertEquals(x509.digest(b"sha1"), host['x509'].digest(b"sha1"))
        self.assertEquals(x509.get_notBefore(), host['x509'].get_notBefore())
        self.assertEquals(x509.get_notAfter(), host['x509'].get_notAfter())

        print("Forcibly renewing Tomcat SSL certificates")
        # wait a bit to notice certificate time difference
        time.sleep(2)
        p = Popen(force_renew_ssl_cert_cmd, stdout=PIPE, stderr=PIPE, shell=True)
        # then we expect the certificates will be renewed because we enforce that
        out, err = p.communicate()
        self.assertEquals(p.returncode, 0, "Stdout: {0}, Stderr: {1}".format(out, err))
        # wait a bit to renew certificates and restart tomcat
        time.sleep(10)
        print("Checking {host}:{port}, renew enabled: {renew_enabled}".format(**host))
        conn = urllib2.urlopen('https://{host}:{port}'.format(**host))
        html_contents = conn.read()
        cert = ssl.get_server_certificate((host['host'], host['port']))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        self.assertEquals(html_contents, host['html_contents'])
        self.assertEquals(x509.get_subject(), host['x509'].get_subject())
        self.assertEquals(x509.get_issuer(), host['x509'].get_issuer())
        if host['renew_enabled']:
            # certificate serial, digest and validity should change
            self.assertNotEquals(x509.get_serial_number(), host['x509'].get_serial_number())
            self.assertNotEquals(x509.digest(b"sha1"), host['x509'].digest(b"sha1"))
            self.assertTrue(time.strptime(x509.get_notBefore(), "%Y%m%d%H%M%SZ") >
                            time.strptime(host['x509'].get_notBefore(), "%Y%m%d%H%M%SZ"))
            self.assertTrue(time.strptime(x509.get_notAfter(), "%Y%m%d%H%M%SZ") >
                            time.strptime(host['x509'].get_notAfter(), "%Y%m%d%H%M%SZ"))
        else:
            # no cert change expected
            self.assertEquals(x509.get_serial_number(), host['x509'].get_serial_number())
            self.assertEquals(x509.digest(b"sha1"), host['x509'].digest(b"sha1"))
            self.assertEquals(x509.get_notBefore(), host['x509'].get_notBefore())
            self.assertEquals(x509.get_notAfter(), host['x509'].get_notAfter())


if __name__ == '__main__':
    unittest.main()
