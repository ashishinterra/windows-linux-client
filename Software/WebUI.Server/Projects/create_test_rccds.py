#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Script will create test RCCDs
# usage ./$0 [keytalk-server-ip]

import sys
import os
import os.path
import re
from urllib.request import build_opener, HTTPCookieProcessor, Request
from urllib.parse import urljoin, urlencode
from http.cookiejar import CookieJar

# THIS IS DIRTY MONKEY PATCHING to bypass server SSL certificate verification
import ssl
ssl._create_default_https_context = ssl._create_unverified_context


class RccdRequestor:

    def __init__(self, keytalk_svr_ip=None):
        self._cookie_jar = CookieJar()
        self._username = 'admin'
        self._password = 'change!'
        if keytalk_svr_ip is not None:
            self._keytalk_svr_ip = keytalk_svr_ip
        else:
            self._keytalk_svr_ip = RccdRequestor._retrieve_self_ip()
            os.system('service lighttpd restart && sleep 1')
        self._keytalk_svr_ip_login_url = 'https://' + self._keytalk_svr_ip + ':3000/login'

    @staticmethod
    def _retrieve_self_ip():
        ip = os.popen(
            r"ifconfig | grep 'inet addr' | grep -v '127.0.0.1' -m 1 | awk '{ print $2 }' | awk -F: '{ print $2 }'").read().strip()
        return ip

    def _initiate_rccd_creation_request(self, services):
        post_params = {
            'create_rccd_with_selected_services_btn.x': '0',
        }
        for service in services:
            post_params[service + '_chckbox'] = 'on'
        return self._open_page('rccd', **post_params)

    # output RCCD as settings.<Provider>.<user|admin>[.<Suffix>].rccd
    def _save_rccd(self, contents, provider_name, is_admin, suffix=''):
        out_dir = 'Export'
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)
        rccd_path = '%s/settings.%s.%s%s.rccd' % (out_dir,
                                                  provider_name,
                                                  ('admin' if is_admin else 'user'),
                                                  ('.' + suffix if suffix else ''))
        f = open(rccd_path, 'wb')
        f.write(contents)
        f.close()
        return rccd_path

    def _parse_serialized_rccd_request(self, html_contents):
        result = re.search(
            rb'input\s*type="hidden"\s*name="serialized_rccd_request_input"\s*value="(.*?)">',
            html_contents,
            re.MULTILINE | re.DOTALL)
        if result:
            return result.group(1)
        else:
            raise Exception("Cannot find RCCD request in HTML: {}".format(html_contents))

    def _create_rccd(self, serialized_rccd_request, provider):
        post_params = {
            'rccd_create_btn_input.x': '0',
            'serialized_rccd_request_input': serialized_rccd_request,
            'provider_name_input': provider['name'],
            'content_version_input': provider['content_version'],
            'server_address_input': provider['server_address'],
        }
        if provider['allow_overwrite_server_address']:
            post_params['allow_overwrite_server_address_chckbox'] = 'on'

        return self._open_page('rccd', **post_params)

    def _login(self):
        opener = build_opener(HTTPCookieProcessor(self._cookie_jar))

        post_params = {'login_id_input': self._username,
                       'login_password_input': self._password,
                       'login_submit_btn.x': '0'}

        req = Request(self._keytalk_svr_ip_login_url, urlencode(post_params).encode('utf-8'))

        conn = opener.open(req)
        self._cookie_jar.extract_cookies(conn, req)
        conn.close()

    def _open_page(self, page_path, **post_params):
        opener = build_opener(HTTPCookieProcessor(self._cookie_jar))
        if post_params:
            req = Request(urljoin(self._keytalk_svr_ip_login_url, page_path),
                          urlencode(post_params).encode('utf-8'))
        else:
            req = Request(urljoin(self._keytalk_svr_ip_login_url, page_path))

        conn = opener.open(req)
        self._cookie_jar.extract_cookies(conn, req)
        html_contents = conn.read()
        conn.close()
        return html_contents

    def create_rccd(self, provider_name, content_version, is_admin, suffix=''):
        self._login()

        services = ['CUST_ANO_INTERNAL_TESTUI',
                    'CUST_PASSWD_INTERNAL_TESTUI',
                    'CUST_PIN_PASSWD_INTERNAL_TESTUI',
                    'CUST_ANO_INTERNAL_GLOBALSIGN',
                    'CUST_PASSWD_AD',
                    ]
        provider = {'name': provider_name,
                    'content_version': content_version,
                    'server_address': "demo.keytalkdemo.com",
                    'allow_overwrite_server_address': not is_admin,
                    }
        print('Creating {} RCCD for provider {} and services {}'.format(
            'admin' if is_admin else 'user', provider['name'], services))

        html_resp = self._initiate_rccd_creation_request(services)
        serialized_rccd_request = self._parse_serialized_rccd_request(html_resp)
        rccd = self._create_rccd(serialized_rccd_request, provider)
        self._save_rccd(rccd, provider_name, is_admin, suffix)


if __name__ == '__main__':
    if len(sys.argv) == 2:
        keytalk_svr_ip = sys.argv[1]
        rccdRequestor = RccdRequestor(keytalk_svr_ip)
    else:
        rccdRequestor = RccdRequestor()

    rccdRequestor.create_rccd(provider_name='DemoProvider',
                              content_version='2011032901', is_admin=False)
    rccdRequestor.create_rccd(provider_name='DemoProvider',
                              content_version='2011032901', is_admin=True)
    rccdRequestor.create_rccd(provider_name='DemoProvider',
                              content_version='11', is_admin=False, suffix='11'
                              )
    rccdRequestor.create_rccd(provider_name='DemoProvider',
                              content_version='12', is_admin=False, suffix='12'
                              )
    rccdRequestor.create_rccd(provider_name='DemoProvider',
                              content_version='13', is_admin=True, suffix='13')

    rccdRequestor.create_rccd(provider_name='DemoProvider2',
                              content_version='2011032901', is_admin=False)
    rccdRequestor.create_rccd(provider_name='DemoProvider2',
                              content_version='2011032901', is_admin=True)
    rccdRequestor.create_rccd(provider_name='DemoProvider2',
                              content_version='21', is_admin=True, suffix='21')
    rccdRequestor.create_rccd(provider_name='DemoProvider2',
                              content_version='22', is_admin=True, suffix='22')
    rccdRequestor.create_rccd(provider_name='DemoProvider2',
                              content_version='23', is_admin=False, suffix='23'
                              )
