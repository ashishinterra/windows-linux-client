#!/usr/bin/env python
# -*- coding: utf-8 -*-


import urllib2
import unittest
import time
import ssl
import os
import re
from shutil import copyfile
from subprocess import Popen, PIPE
import OpenSSL

"""
To run specific test case:
python -m unittest test_module_name.TestClass.test_method
"""


class TestApacheSsl(unittest.TestCase):

    def setUp(self):
        # notice we don't use setUpClass() as it is not supported on Python 2.6
        ca_file = 'localhost-ssl-cert/cas.pem'

        if os.system('which apache2 > /dev/null 2>&1') == 0:
            # Debian, Ubuntu
            print("Setting up Apache2 SSL test")
            copyfile(ca_file, "/usr/local/share/ca-certificates/localhost-ssl-cas.crt")
            if os.system('update-ca-certificates') != 0:
                raise Exception("Failed to install localhost SSL CA trust")
            if os.system('service apache2 status > /dev/null 2>&1 || service apache2 start') != 0:
                raise Exception("Failed to start Apache2")

        elif os.system('which httpd > /dev/null 2>&1') == 0:
            # CentOS, RHEL
            print("Setting up Apache (httpd) SSL test")
            copyfile(ca_file, "/etc/pki/ca-trust/source/anchors/localhost-ssl-cas.crt")
            if os.system('update-ca-trust') != 0:
                raise Exception("Failed to install localhost SSL CA trust")
            if os.system('service httpd status > /dev/null 2>&1 || service httpd start') != 0:
                raise Exception("Failed to start Apache (httpd)")

        else:
            raise Exception("No Apache installation detected")

    def test_ssl_cert_is_renewal_for_multiple_vhosts(self):
        # given
        renew_ssl_cert_cmd = '/usr/local/bin/keytalk/renew_apache_ssl_cert'
        force_renew_ssl_cert_cmd = renew_ssl_cert_cmd + " --force"
        vhost_configurations = [
            {'host': 'localhost', 'port': 3000, 'renew_enabled': True},
            {'host': 'localhost', 'port': 3001, 'renew_enabled': False},
            {'host': 'localhost', 'port': 3002, 'renew_enabled': True},
            {'host': 'a.example.com', 'port': 3003, 'renew_enabled': True},
            {'host': 'b.example.com', 'port': 3003, 'renew_enabled': True},
        ]
        # when
        print("Forcibly renewing Apache SSL certificates")
        p = Popen(force_renew_ssl_cert_cmd, stdout=PIPE, stderr=PIPE, shell=True)
        # then
        out, err = p.communicate()
        self.assertEquals(p.returncode, 0, "Stdout: {0}, Stderr: {1}".format(out, err))
        for vhost in vhost_configurations:
            print("Checking {host}:{port}, renew enabled: {renew_enabled}".format(**vhost))
            conn = urllib2.urlopen('https://{host}:{port}'.format(**vhost))
            html_contents = conn.read()
            self.assertTrue(
                re.search(
                    r"<h1>(It works!|Index of /)</h1>|If you can read this page, it means that the Apache HTTP server installed at\s+this site is working properly",
                    html_contents) is not None,
                html_contents)
            cert = ssl.get_server_certificate((vhost['host'], vhost['port']))
            # save site state for further testing
            vhost['html_contents'] = html_contents
            vhost['x509'] = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

        # when
        print("Renewing valid Apache SSL certificates")
        # sleep for at least a second to notice certificate time difference
        time.sleep(1)
        p = Popen(renew_ssl_cert_cmd, stdout=PIPE, stderr=PIPE, shell=True)
        # then we expect no certificates get renewed because they are still valid
        out, err = p.communicate()
        self.assertEquals(p.returncode, 0, "Stdout: {0}, Stderr: {1}".format(out, err))
        for vhost in vhost_configurations:
            print("Checking {host}:{port}, renew enabled: {renew_enabled}".format(**vhost))
            conn = urllib2.urlopen('https://{host}:{port}'.format(**vhost))
            html_contents = conn.read()
            cert = ssl.get_server_certificate((vhost['host'], vhost['port']))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            self.assertEquals(html_contents, vhost['html_contents'])
            self.assertEquals(x509.get_subject(), vhost['x509'].get_subject())
            self.assertEquals(x509.get_issuer(), vhost['x509'].get_issuer())
            self.assertEquals(x509.get_serial_number(), vhost['x509'].get_serial_number())
            self.assertEquals(x509.digest(b"sha1"), vhost['x509'].digest(b"sha1"))
            self.assertEquals(x509.get_notBefore(), vhost['x509'].get_notBefore())
            self.assertEquals(x509.get_notAfter(), vhost['x509'].get_notAfter())

        # when
        print("Forcibly renewing Apache SSL certificates")
        # sleep for at least a second to notice certificate time difference
        time.sleep(1)
        p = Popen(force_renew_ssl_cert_cmd, stdout=PIPE, stderr=PIPE, shell=True)
        # then we expect the certificates will be renewed because we enforce that
        out, err = p.communicate()
        self.assertEquals(p.returncode, 0, "Stdout: {0}, Stderr: {1}".format(out, err))
        for vhost in vhost_configurations:
            print("Checking {host}:{port}, renew enabled: {renew_enabled}".format(**vhost))
            conn = urllib2.urlopen('https://{host}:{port}'.format(**vhost))
            html_contents = conn.read()
            cert = ssl.get_server_certificate((vhost['host'], vhost['port']))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            self.assertEquals(html_contents, vhost['html_contents'])
            self.assertEquals(x509.get_subject(), vhost['x509'].get_subject())
            self.assertEquals(x509.get_issuer(), vhost['x509'].get_issuer())
            if vhost['renew_enabled']:
                # certificate serial, digest and validity should change
                self.assertNotEquals(x509.get_serial_number(), vhost['x509'].get_serial_number())
                self.assertNotEquals(x509.digest(b"sha1"), vhost['x509'].digest(b"sha1"))
                self.assertTrue(time.strptime(x509.get_notBefore(), "%Y%m%d%H%M%SZ") >
                                time.strptime(vhost['x509'].get_notBefore(), "%Y%m%d%H%M%SZ"))
                self.assertTrue(time.strptime(x509.get_notAfter(), "%Y%m%d%H%M%SZ") >
                                time.strptime(vhost['x509'].get_notAfter(), "%Y%m%d%H%M%SZ"))
            else:
                # no cert change expected
                self.assertEquals(x509.get_serial_number(), vhost['x509'].get_serial_number())
                self.assertEquals(x509.digest(b"sha1"), vhost['x509'].digest(b"sha1"))
                self.assertEquals(x509.get_notBefore(), vhost['x509'].get_notBefore())
                self.assertEquals(x509.get_notAfter(), vhost['x509'].get_notAfter())


if __name__ == '__main__':
    unittest.main()
