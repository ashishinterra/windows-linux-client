#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import unittest

sys.path.insert(0, '/usr/local/bin/keytalk')
import tomcat_util


class TestTomcatUtil(unittest.TestCase):

    def test_parse_connection_address_from_host(self):
        self.assertEqual(tomcat_util.parse_connection_address_from_host(
            "192.168.1.1:3001"), ("192.168.1.1", 3001))
        self.assertEqual(tomcat_util.parse_connection_address_from_host(
            "*:3001"), ("localhost", 3001))
        self.assertEqual(tomcat_util.parse_connection_address_from_host(
            "_default_:8080"), ("localhost", 8080))
        self.assertEqual(tomcat_util.parse_connection_address_from_host(
            "_default_:*"), ("localhost", 8443))
        self.assertEqual(tomcat_util.parse_connection_address_from_host(
            "192.168.1.1"), ("192.168.1.1", 8443))
        self.assertEqual(tomcat_util.parse_connection_address_from_host(
            "[2001:4860:4860::8888]"), ("[2001:4860:4860::8888]", 8443))
        self.assertEqual(tomcat_util.parse_connection_address_from_host(
            "[2001:4860:4860::8888]:8443"), ("[2001:4860:4860::8888]", 8443))


if __name__ == '__main__':
    unittest.main()
