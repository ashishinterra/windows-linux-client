#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# Sample Proof-of-concept KeyTalk client capable of retrieving a certificate from KeyTalk 5.x server using different authentication methods
#

# Requires Python 3.4 and higher

######################################################################################
# RCDPv2 flow.
# Goes over HTTPS.
#
# client ---------> hello -----------------> server
# client <--------- hello <----------------- server
# client ---------> handshake -------------> server
# client <--------- handshake <------------- server
# client ---------> auth-requirements -----> server
# client <--------- auth-requirements <----- server
# client ---------> authentication --------> server
# client <--------- auth-result <----------- server
# client ---------> last-messages ---------> server
# client <--------- last-messages <--------- server
# client ---------> cert ------------------> server
# client <--------- cert <------------------ server
# client ---------> eoc -------------------> server
# client <--------- eoc <------------------- server

# eoc (end-of-communication) and error can be sent by any party at any time
##########################################################################################

import http.client
import ssl
import urllib.request
import urllib.parse
import urllib.error
import json
import datetime
import base64
import pprint
import hashlib
import socket
import OpenSSL

import common_config as conf


###################################################################################

#
# Global settings
#
VERBOSE = False

# HACK to bypass checking KeyTalk server hostname during SSL handshake;
# useful for quick testing e.g. when KeyTalk server is IP address iso FQDN
BYPASS_HTTPS_VALIDATION = True

#
# These settings should come from RCCD
#
if BYPASS_HTTPS_VALIDATION:
    KEYTALK_SERVER = '192.168.33.111'
else:
    KEYTALK_SERVER = 'demo.keytalkdemo.com'

SERVER_VERIFICATION_CA_CHAIN = [
    'commcacert.pem',
    'pcacert.pem'
]
LAST_MESSAGES_FROM_UTC = None

UMTS_USERNAME = 'UMTS_2_354162120787078'
GSM_USERNAME = 'GSM_2_354162120787078'


##############################################################################

def debug(msg):
    if VERBOSE:
        print(msg)


def log(msg):
    print(msg)


def fetch_url(url):
    debug("Fetching URL " + url)
    try:
        with urllib.request.urlopen(url) as response:
            payload = response.read()
            return payload
    except Exception as e:
        log("Error opening URL {}. {}".format(url, e))
        return None


def is_true(dict, key):
    return (key in dict) and (dict[key].lower() == 'true')


def is_false(dict, key):
    return (key in dict) and (dict[key].lower() == 'false')


class BadRequestError(Exception):
    pass


class CertRetrievalApi(object):

    def __init__(self):
        self.version = conf.RCDP_VERSION_2_3
        self.conn = None
        self.cookie = None

    #
    # Private API
    #

    @staticmethod
    def _parse_rcdp_response(conn, request_name, expected_status):
        response = conn.getresponse()
        response_payload = response.read().decode()
        if response.status != 200:
            raise Exception(
                'Unexpected response HTTP status {} received on {} request.'.format(
                    response.status, request_name))

        payload = json.loads(response_payload)
        debug("{} -> {} {}.\n{}".format(request_name, response.status,
                                        response.reason, pprint.pformat(payload)))

        status = payload[conf.RCDPV2_RESPONSE_PARAM_NAME_STATUS]
        if status != expected_status:
            if status == conf.RCDPV2_RESPONSE_ERROR:
                code = int(payload[conf.RCDPV2_RESPONSE_PARAM_NAME_ERROR_CODE])
                info = payload[conf.RCDPV2_RESPONSE_PARAM_NAME_ERROR_DESCRIPTION]
                if code == int(conf.RCDP_ERR_CODE["ErrTimeOutOfSync"]):
                    delta_seconds = int(info)
                    if delta_seconds > 0:
                        raise Exception(
                            'Client time is {} seconds ahead the server time'.format(delta_seconds))
                    else:
                        raise Exception(
                            'Client time is {} seconds behind the server time'.format(-delta_seconds))
                else:
                    raise Exception(
                        'Received error {} for response on {}. Extra info: {}'.format(
                            code, request_name, info))
            else:
                raise Exception(
                    'Expected {} response on {} request but received {} instead'.format(
                        expected_status, request_name, status))

        cookie = response.getheader('set-cookie', None)
        return (payload, cookie)

    @staticmethod
    def _calc_hwsig(formula):
        # @todo implement for real for the given formula
        return "HWSIG-123456"

    @staticmethod
    def _get_system_hwdescription():
        # @todo implement for real
        return "Windows 7, BIOS s/n 1234567890"

    @staticmethod
    def _resolve_host(uri):
        hostname = urllib.parse.urlparse(uri).hostname
        log("Resolving " + hostname)
        ips = []
        try:
            for addr in socket.getaddrinfo(
                    hostname,
                    port=None,
                    family=socket.AF_INET,
                    type=socket.SOCK_STREAM):
                ips.append(addr[4][0])
        except Exception:
            pass
        try:
            for addr in socket.getaddrinfo(
                    hostname,
                    port=None,
                    family=socket.AF_INET6,
                    type=socket.SOCK_STREAM):
                ips.append(addr[4][0])
        except Exception:
            pass
        if not ips:
            raise Exception("Failed to resolve " + hostname)
        return ips

    @staticmethod
    def _calc_digest(path):
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()

    @staticmethod
    def is_cr_authentication(auth_requirements):
        return conf.CRED_RESPONSE in auth_requirements[conf.RCDPV2_RESPONSE_PARAM_NAME_CRED_TYPES]

    @staticmethod
    def is_password_expiring(password_validity_sec):
        """quick&dirty but good enough for tests; see ta::SyfInfo::isUserPasswordExpiring() for proper implementation"""
        seconds_in_day = 24 * 60 * 60
        max_validity_days = 7
        return password_validity_sec >= 0 and\
            password_validity_sec < max_validity_days * seconds_in_day

    @staticmethod
    def calc_responses(username, challenges, response_names):
        if username == UMTS_USERNAME:
            # expect only 2 challenges and 3 responses
            responses = [
                {
                    conf.RCDPV2_REQUEST_PARAM_NAME_NAME: response_names[0],
                    conf.RCDPV2_REQUEST_PARAM_NAME_VALUE: "02020202020202020202020202020202"
                },
                {
                    conf.RCDPV2_REQUEST_PARAM_NAME_NAME: response_names[1],
                    conf.RCDPV2_REQUEST_PARAM_NAME_VALUE: "03030303030303030303030303030303"
                },
                {
                    conf.RCDPV2_REQUEST_PARAM_NAME_NAME: response_names[2],
                    conf.RCDPV2_REQUEST_PARAM_NAME_VALUE: "04040404040404040404040404040404"
                }
            ]
        elif username == GSM_USERNAME:
            # 3 rounds of request-response
            if challenges['GSM RANDOM'] == '101112131415161718191a1b1c1d1e1f':
                responses = [
                    {
                        conf.RCDPV2_REQUEST_PARAM_NAME_NAME: response_names[0],
                        conf.RCDPV2_REQUEST_PARAM_NAME_VALUE: "d1d2d3d4"
                    },
                    {
                        conf.RCDPV2_REQUEST_PARAM_NAME_NAME: response_names[1],
                        conf.RCDPV2_REQUEST_PARAM_NAME_VALUE: "a0a1a2a3a4a5a6a7"
                    }
                ]
            elif challenges['GSM RANDOM'] == '202122232425262728292a2b2c2d2e2f':
                responses = [
                    {
                        conf.RCDPV2_REQUEST_PARAM_NAME_NAME: response_names[0],
                        conf.RCDPV2_REQUEST_PARAM_NAME_VALUE: "e1e2e3e4"
                    },
                    {
                        conf.RCDPV2_REQUEST_PARAM_NAME_NAME: response_names[1],
                        conf.RCDPV2_REQUEST_PARAM_NAME_VALUE: "b0b1b2b3b4b5b6b7"
                    }
                ]
            elif challenges['GSM RANDOM'] == '303132333435363738393a3b3c3d3e3f':
                responses = [
                    {
                        conf.RCDPV2_REQUEST_PARAM_NAME_NAME: response_names[0],
                        conf.RCDPV2_REQUEST_PARAM_NAME_VALUE: "f1f2f3f4"
                    },
                    {
                        conf.RCDPV2_REQUEST_PARAM_NAME_NAME: response_names[1],
                        conf.RCDPV2_REQUEST_PARAM_NAME_VALUE: "c0c1c2c3c4c5c6c7"
                    }
                ]
        else:
            # expect only challenge and one response;
            challenge_value = next(iter(challenges.values()))
            response_name = response_names[0]
            response_value = hashlib.sha1(
                (username + challenge_value).encode()).hexdigest()[:8].upper()
            responses = [
                {
                    conf.RCDPV2_REQUEST_PARAM_NAME_NAME: response_name,
                    conf.RCDPV2_REQUEST_PARAM_NAME_VALUE: response_value
                }
            ]

        return {conf.RCDPV2_REQUEST_PARAM_NAME_RESPONSES: json.dumps(responses)}

    @staticmethod
    def request_auth_credentials(auth_requirements, username, password=None, pincode=None):
        required_cred_types = auth_requirements[conf.RCDPV2_RESPONSE_PARAM_NAME_CRED_TYPES]
        creds = {}
        if conf.CRED_USERID in required_cred_types:
            creds[conf.CRED_USERID] = username
        if conf.CRED_PASSWD in required_cred_types:
            creds[conf.CRED_PASSWD] = password
        if conf.CRED_PIN in required_cred_types:
            creds[conf.CRED_PIN] = pincode
        if conf.CRED_HWSIG in required_cred_types:
            creds[conf.CRED_HWSIG] = CertRetrievalApi._calc_hwsig(
                auth_requirements[conf.RCDPV2_RESPONSE_PARAM_NAME_HWSIG_FORMULA])

        service_uris = auth_requirements.get(conf.RCDPV2_RESPONSE_PARAM_NAME_SERVICE_URIS, None)

        if is_true(auth_requirements,
                   conf.RCDPV2_RESPONSE_PARAM_NAME_RESOLVE_SERVICE_URIS):
            ips = []
            for service_uri in service_uris:
                ips.append({conf.RCDPV2_REQUEST_PARAM_NAME_URI: service_uri,
                            conf.RCDPV2_REQUEST_PARAM_NAME_IPS: CertRetrievalApi._resolve_host(service_uri)})
            creds[conf.RCDPV2_REQUEST_PARAM_NAME_RESOLVED] = json.dumps(ips)

        if is_true(auth_requirements,
                   conf.RCDPV2_RESPONSE_PARAM_NAME_CALC_SERVICE_URIS_DIGEST):
            digests = []
            for service_uri in service_uris:
                digests.append({conf.RCDPV2_REQUEST_PARAM_NAME_URI: service_uri,
                                conf.RCDPV2_REQUEST_PARAM_NAME_DIGEST: CertRetrievalApi._calc_digest(service_uri)})
            creds[conf.RCDPV2_REQUEST_PARAM_NAME_DIGESTS] = json.dumps(digests)

        return creds

    @staticmethod
    def gen_csr(requirements):
        key_size = int(requirements[conf.RCDPV2_RESPONSE_PARAM_NAME_KEY_SIZE])
        signing_algo = requirements[conf.RCDPV2_RESPONSE_PARAM_NAME_SIGNING_ALGO]
        subject = requirements[conf.RCDPV2_RESPONSE_PARAM_NAME_SUBJECT]

        log("Generating {}-bit RSA keypair".format(key_size))
        keypair = OpenSSL.crypto.PKey()
        keypair.generate_key(OpenSSL.crypto.TYPE_RSA, key_size)
        log("Creating CSR with subject {} and signed by {}".format(subject, signing_algo))
        req = OpenSSL.crypto.X509Req()
        CertRetrievalApi._set_subject_on_req(req, subject)
        req.set_pubkey(keypair)
        req.sign(keypair, signing_algo)
        pkcs10_req = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, req)
        return pkcs10_req

    @staticmethod
    def _set_subject_on_req(req, subject):
        subj = req.get_subject()
        for key, value in subject.items():
            if key == "cn":
                setattr(subj, "CN", value)
            if key == "c":
                setattr(subj, "C", value)
            if key == "st":
                setattr(subj, "ST", value)
            if key == "l":
                setattr(subj, "L", value)
            if key == "o":
                setattr(subj, "O", value)
            if key == "ou":
                setattr(subj, "OU", value)
            if key == "e":
                setattr(subj, "emailAddress", value)

    @staticmethod
    def _save_cert(cert, passphrase, format):
        pass_path = 'certkey-password.txt'
        if format == conf.CERT_FORMAT_PEM:
            cert_path = 'cert.pem'
        elif format == conf.CERT_FORMAT_P12:
            cert_path = 'cert.pfx'
        else:
            raise Exception('Unexpected certificate format ' + format)

        with open(cert_path, 'wb') as cert_file:
            cert_file.write(cert)
        with open(pass_path, 'w') as pass_file:
            pass_file.write(passphrase)

        log("The certificate has been saved to {}, passphrase has been saved to {}".format(
            cert_path, pass_path))
        if format == conf.CERT_FORMAT_PEM:
            log("Use the following command if you with to decrypt the key:\nopenssl rsa -in {} -out key.pem -passin pass:{}".format(
                cert_path, passphrase))
        elif format == conf.CERT_FORMAT_P12:
            log("Use the following command if you wish to decrypt the PKCS#12 package:\nopenssl pkcs12 -nodes -in {} -out certkey.pem -passin pass:{}".format(
                cert_path, passphrase))

        return cert_path, pass_path

    @staticmethod
    def _save_pem_cert_only(cert):
        cert_path = 'cert.pem'
        with open(cert_path, 'wb') as cert_file:
            cert_file.write(cert)
        log("The certificate has been saved to {}".format(cert_path))
        return cert_path

    def _request(self, action, params={}, method='GET', send_cookie=True):
        if VERBOSE:
            self.conn.set_debuglevel(1)

        url = "/{}/{}/{}".format(conf.RCDPV2_HTTP_REQUEST_URI_PREFIX,
                                 self.version,
                                 action)
        headers = {}
        body = None

        if method == 'GET':
            # HTTP GET params are sent in URL
            if params:
                url += '?' + urllib.parse.urlencode(params)
        elif method == 'POST':
            # HTTP POST params are sent in body
            body = urllib.parse.urlencode(params)
            headers["Content-type"] = "application/x-www-form-urlencoded"
        else:
            raise Exception('Unsupported HTTP request method {}'.format(method))

        if send_cookie:
            headers["Cookie"] = self.cookie

        self.conn.request(method, url, body, headers)

    def _get_cert_passphrase(self):
        parsed_cookie = self.cookie.split('=')
        if len(parsed_cookie) != 2 or parsed_cookie[0] != conf.RCDPV2_HTTP_SID_COOKIE_NAME:
            raise Exception('Cannot parse RCDP session cookie from ' + self.cookie)
        sid = parsed_cookie[1]
        passphrase = sid[:conf.RCDP_PACKAGED_CERT_EXPORT_PASSWDSIZE]
        return passphrase

    @staticmethod
    def _load_verification_ca_chain():
        cadata = ''
        for file in SERVER_VERIFICATION_CA_CHAIN:
            cadata += open(file).read()
        return cadata

    #
    # Public API
    #

    def eoc(self):
        self._request(conf.RCDPV2_REQUEST_EOC)

    def hello(self):
        log("Connecting RCDP to KeyTalk server at " + KEYTALK_SERVER + "...")

        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        # without explicitly supplying EC curve SSL connection will fail on python-3.5.3
        # with SSL Handshake error
        ssl_ctx.set_ecdh_curve('secp384r1')

        if BYPASS_HTTPS_VALIDATION:
            ssl_ctx.verify_mode = ssl.CERT_NONE
        else:
            ssl_ctx.verify_mode = ssl.CERT_REQUIRED
            ssl_ctx.load_verify_locations(cadata=CertRetrievalApi._load_verification_ca_chain())

        conn = http.client.HTTPSConnection(
            KEYTALK_SERVER, conf.RCDPV2_LISTEN_PORT, context=ssl_ctx)

        self.conn = conn
        request_params = {
            conf.RCDPV2_REQUEST_PARAM_NAME_CALLER_APP_DESCRIPTION: 'Test KeyTalk Python client'}
        self._request(conf.RCDPV2_REQUEST_HELLO, request_params, send_cookie=False)
        response_payload, cookie = CertRetrievalApi._parse_rcdp_response(
            conn, conf.RCDPV2_REQUEST_HELLO, conf.RCDPV2_RESPONSE_HELLO)
        if response_payload[conf.RCDPV2_RESPONSE_PARAM_NAME_VERSION] != self.version:
            raise Exception(
                'Unexpected response received on hello request: {}'.format(response_payload))
        self.cookie = cookie

    def handshake(self):
        request_params = {conf.RCDPV2_REQUEST_PARAM_NAME_CALLER_UTC:
                          datetime.datetime.utcnow().isoformat() + 'Z'}
        self._request(conf.RCDPV2_REQUEST_HANDSHAKE, request_params)
        response_payload, _ = CertRetrievalApi._parse_rcdp_response(
            self.conn, conf.RCDPV2_REQUEST_HANDSHAKE, conf.RCDPV2_RESPONSE_HANDSHAKE)
        return response_payload

    def get_auth_requirements(self, service):
        request_params = {conf.RCDPV2_REQUEST_PARAM_NAME_SERVICE: service}
        self._request(conf.RCDPV2_REQUEST_AUTH_REQUIREMENTS, request_params)
        response_payload, _ = CertRetrievalApi._parse_rcdp_response(
            self.conn, conf.RCDPV2_REQUEST_AUTH_REQUIREMENTS, conf.RCDPV2_RESPONSE_AUTH_REQUIREMENTS)
        return response_payload

    def authenticate(self, creds, service=None):
        """authenticate with the given set of credentials
        return password-validity-in-seconds when ok is received or -1 if the password is expired
        return (challenges, response-names) when challenge is received
        raise exception otherwise"""
        if service is not None:
            request_params = {
                conf.RCDPV2_REQUEST_PARAM_NAME_SERVICE: service,
                conf.RCDPV2_REQUEST_PARAM_NAME_CALLER_HW_DESCRIPTION: CertRetrievalApi._get_system_hwdescription(),
            }
            request_params.update(creds)
        else:
            # normally this means that we have already submitted service name on the first authentication
            # request and now we are on the challenge phase
            request_params = creds

        debug("Sending authentication request: " + pprint.pformat(request_params))

        self._request(conf.RCDPV2_REQUEST_AUTHENTICATION, request_params, method='POST')
        response_payload, _ = CertRetrievalApi._parse_rcdp_response(
            self.conn, conf.RCDPV2_REQUEST_AUTHENTICATION, conf.RCDPV2_RESPONSE_AUTH_RESULT)
        auth_status = response_payload[conf.RCDPV2_RESPONSE_PARAM_NAME_AUTH_STATUS]
        if auth_status == conf.AUTH_OK:
            if conf.RCDPV2_RESPONSE_PARAM_NAME_PASSWORD_VALIDITY in response_payload:
                password_validity = int(
                    response_payload[conf.RCDPV2_RESPONSE_PARAM_NAME_PASSWORD_VALIDITY])
            else:
                password_validity = None
            log("Authenticated successfully")
            return password_validity
        elif auth_status == conf.AUTH_CHALLENGE:
            log("Challenge received")
            challenges = {}
            for challenge in response_payload[conf.RCDPV2_RESPONSE_PARAM_NAME_CHALLENGES]:
                challenges[challenge[conf.RCDPV2_RESPONSE_PARAM_NAME_NAME]] = challenge[
                    conf.RCDPV2_RESPONSE_PARAM_NAME_VALUE]
            response_names = response_payload.get(
                conf.RCDPV2_RESPONSE_PARAM_NAME_RESPONSE_NAMES, None)
            return challenges, response_names
        elif auth_status == conf.AUTH_EXPIRED:
            log("Password expired")
            return -1
        else:
            raise Exception(
                'Got {} trying to authenticate against service {}.'.format(auth_status, service))

    def change_password(self, old_password, new_password):
        request_params = {
            conf.RCDPV2_REQUEST_PARAM_NAME_OLD_PASSWORD: old_password,
            conf.RCDPV2_REQUEST_PARAM_NAME_NEW_PASSWORD: new_password
        }
        debug("Changing user password")
        self._request(conf.RCDPV2_REQUEST_CHANGE_PASSWORD, request_params, method='POST')
        response_payload, _ = CertRetrievalApi._parse_rcdp_response(
            self.conn, conf.RCDPV2_REQUEST_CHANGE_PASSWORD, conf.RCDPV2_RESPONSE_AUTH_RESULT)
        auth_status = response_payload[conf.RCDPV2_RESPONSE_PARAM_NAME_AUTH_STATUS]
        if auth_status == conf.AUTH_OK:
            log("Password successfully changed")
        else:
            raise Exception(
                'Got {} trying to change user password.'.format(auth_status))

    def get_last_messages(self):
        request_params = {}
        if LAST_MESSAGES_FROM_UTC is not None:
            request_params[
                conf.RCDPV2_REQUEST_PARAM_NAME_LAST_MESSAGES_FROM_UTC] = LAST_MESSAGES_FROM_UTC
        self._request(conf.RCDPV2_REQUEST_LAST_MESSAGES, request_params)
        response_payload, _ = CertRetrievalApi._parse_rcdp_response(
            self.conn, conf.RCDPV2_REQUEST_LAST_MESSAGES, conf.RCDPV2_RESPONSE_LAST_MESSAGES)
        messages = response_payload[conf.RCDPV2_RESPONSE_PARAM_NAME_LAST_MESSAGES] or []
        if len(messages) > 0:
            log("Received {} user messages:\n{}".format(len(messages), pprint.pformat(messages)))
        return response_payload

    def get_csr_requirements(self):
        self._request(conf.RCDPV2_REQUEST_CSR_REQUIREMENTS)
        response_payload, _ = CertRetrievalApi._parse_rcdp_response(
            self.conn, conf.RCDPV2_REQUEST_CSR_REQUIREMENTS, conf.RCDPV2_RESPONSE_CSR_REQUIREMENTS)
        return response_payload

    def get_cert(self, format, include_chain, out_of_band=False):
        request_params = {
            conf.RCDPV2_REQUEST_PARAM_NAME_CERT_FORMAT: format,
            conf.RCDPV2_REQUEST_PARAM_NAME_CERT_INCLUDE_CHAIN: include_chain,
            conf.RCDPV2_REQUEST_PARAM_NAME_CERT_OUT_OF_BAND: out_of_band,
        }

        self._request(conf.RCDPV2_REQUEST_CERT, request_params)
        response_payload, _ = CertRetrievalApi._parse_rcdp_response(
            self.conn, conf.RCDPV2_REQUEST_CERT, conf.RCDPV2_RESPONSE_CERT)

        if out_of_band:
            cert_url_templ = response_payload[conf.RCDPV2_RESPONSE_PARAM_NAME_CERT_URL_TEMPL]
            cert_url = cert_url_templ.replace(
                "$(" + conf.CERT_DOWNLOAD_URL_HOST_PLACEHOLDER + ")", KEYTALK_SERVER)
            cert = fetch_url(cert_url)
            assert not fetch_url(cert_url), "the given certificate can only be downloaded once"
        else:
            cert = bytes(response_payload[conf.RCDPV2_RESPONSE_PARAM_NAME_CERT], 'utf-8')
            if format == conf.CERT_FORMAT_P12:
                cert = base64.b64decode(cert)

        cert_passphrase = self._get_cert_passphrase()
        log("Successfully received {} certificate {} chain".format(
            format, "with" if include_chain else "without"))
        cert_path, cert_pass_path = CertRetrievalApi._save_cert(cert, cert_passphrase, format)
        return cert_path, cert_pass_path

    def sign_csr(self, csr, include_chain, out_of_band=False):
        request_params = {
            conf.RCDPV2_REQUEST_PARAM_NAME_CSR: csr,
            conf.RCDPV2_REQUEST_PARAM_NAME_CERT_INCLUDE_CHAIN: include_chain,
            conf.RCDPV2_REQUEST_PARAM_NAME_CERT_OUT_OF_BAND: out_of_band,
        }

        self._request(conf.RCDPV2_REQUEST_CERT, request_params, method='POST')
        response_payload, _ = CertRetrievalApi._parse_rcdp_response(
            self.conn, conf.RCDPV2_REQUEST_CERT, conf.RCDPV2_RESPONSE_CERT)

        if out_of_band:
            cert_url_templ = response_payload[conf.RCDPV2_RESPONSE_PARAM_NAME_CERT_URL_TEMPL]
            cert_url = cert_url_templ.replace(
                "$(" + conf.CERT_DOWNLOAD_URL_HOST_PLACEHOLDER + ")", KEYTALK_SERVER)
            cert = fetch_url(cert_url)
            assert not fetch_url(cert_url), "the given certificate can only be downloaded once"
        else:
            cert = bytes(response_payload[conf.RCDPV2_RESPONSE_PARAM_NAME_CERT], 'utf-8')

        log("Successfully generated PEM certificate {} chain from client CSR".format(
            "with" if include_chain else "without"))
        cert_path = CertRetrievalApi._save_pem_cert_only(cert)
        return cert_path

    def reset_user_password(self, password):
        pass


class CaApi(object):

    def __init__(self):
        self.port = conf.CA_API_AND_CERT_DOWNLOAD_LISTEN_PORT
        self.script = conf.CA_API_REQUEST_SCRIPT_NAME
        self.version = conf.CA_API_VERSION_1_0

    def _url(self, ca_name):
        return "http://{}:{}/{}/{}/{}".format(KEYTALK_SERVER,
                                              self.port,
                                              self.script,
                                              self.version,
                                              ca_name)

    def fetch_ca(self, ca_name):
        url = self._url(ca_name)
        return fetch_url(url)


class PublicApi(object):

    def __init__(self):
        self.conn = None

    def _request(self, action, params={}, method='GET'):
        log("Connecting public API to KeyTalk server at " + KEYTALK_SERVER + "...")

        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        # without explicitly supplying EC curve SSL connection will fail on python-3.5.3
        # with SSL Handshake error
        ssl_ctx.set_ecdh_curve('secp384r1')

        if BYPASS_HTTPS_VALIDATION:
            ssl_ctx.verify_mode = ssl.CERT_NONE
        else:
            ssl_ctx.verify_mode = ssl.CERT_REQUIRED
            ssl_ctx.load_verify_locations(cadata=CertRetrievalApi._load_verification_ca_chain())

        self.conn = http.client.HTTPSConnection(
            KEYTALK_SERVER, conf.PUBLIC_API_LISTEN_PORT, context=ssl_ctx)

        if VERBOSE:
            self.conn.set_debuglevel(1)

        url = "/{}/{}/{}".format(conf.PUBLIC_API_REQUEST_SCRIPT_NAME,
                                 conf.PUBLIC_API_VERSION_1_0,
                                 action)
        headers = {}
        body = None

        if method == 'GET':
            # HTTP GET params are sent in URL
            if params:
                url += '?' + urllib.parse.urlencode(params)
        elif method == 'POST':
            # HTTP POST params are sent in body
            body = urllib.parse.urlencode(params)
            headers["Content-type"] = "application/x-www-form-urlencoded"
        else:
            raise Exception('Unsupported HTTP request method {}'.format(method))

        self.conn.request(method, url, body, headers)

    @staticmethod
    def _parse_response(conn, request_name, expected_status):
        '''
        raise BadRequestError for request errors
        '''
        response = conn.getresponse()
        response_payload = response.read().decode()
        if response.status not in (200, 400):
            raise Exception(
                'Unexpected response HTTP status {} received on {} request.'.format(
                    response.status, request_name))

        payload = json.loads(response_payload)
        debug("{} -> {} {}.\n{}".format(request_name, response.status,
                                        response.reason, pprint.pformat(payload)))

        status = payload[conf.PUBLIC_API_RESPONSE_PARAM_NAME_STATUS]
        if response.status == 400:
            if status != conf.PUBLIC_API_RESPONSE_ERROR:
                raise Exception(
                    "Unexpected status {} received in HTTP 400 response received on {} request".format(
                        status, request_name))
            error_msg = payload[conf.PUBLIC_API_RESPONSE_PARAM_NAME_ERROR]
            raise BadRequestError(error_msg)

        if status != expected_status:
            raise Exception(
                'Expected {} response on {} request but received {} instead'.format(
                    expected_status, request_name, status))

        return payload

    def is_self_service_available(self, cert):
        self._request(conf.PUBLIC_API_REQUEST_SELF_SERVICE_AVAILABILITY,
                      {conf.PUBLIC_API_REQUEST_PARAM_NAME_CERT: cert},
                      method='POST')
        response_payload = PublicApi._parse_response(
            self.conn,
            conf.PUBLIC_API_REQUEST_SELF_SERVICE_AVAILABILITY,
            conf.PUBLIC_API_RESPONSE_SELF_SERVICE_AVAILABILITY)
        if is_true(response_payload, conf.PUBLIC_API_RESPONSE_PARAM_NAME_AVAILABLE):
            return True
        elif is_false(response_payload, conf.PUBLIC_API_RESPONSE_PARAM_NAME_AVAILABLE):
            return False
        else:
            raise Exception("Failed to parse boolean from {} key of the response {}".format(
                conf.PUBLIC_API_RESPONSE_PARAM_NAME_AVAILABLE, response_payload))

    def retrieve_address_books(self, service):
        self._request(conf.PUBLIC_API_REQUEST_ADDRESS_BOOK_LIST,
                      {conf.PUBLIC_API_REQUEST_PARAM_NAME_SERVICE: service},
                      method='GET')
        response_payload = PublicApi._parse_response(
            self.conn,
            conf.PUBLIC_API_REQUEST_ADDRESS_BOOK_LIST,
            conf.PUBLIC_API_RESPONSE_ADDRESS_BOOK_LIST)
        books = response_payload[conf.PUBLIC_API_RESPONSE_PARAM_NAME_ADDRESS_BOOKS] or []
        return books


#
# Test cases
#

def request_cert_with_password_authentication(cert_format, cert_with_chain):
    service = "CUST_PASSWD_INTERNAL_TESTUI"
    username = 'DemoUser'
    password = 'secret'

    api = CertRetrievalApi()
    # handshake
    api.hello()
    api.handshake()
    # authenticate
    auth_requirements = api.get_auth_requirements(service)
    assert not CertRetrievalApi.is_cr_authentication(
        auth_requirements), "Non-CR authentication is expected for service {}".format(service)
    creds = CertRetrievalApi.request_auth_credentials(auth_requirements, username, password)
    api.authenticate(creds, service)
    # get service
    api.get_last_messages()
    api.get_cert(cert_format, cert_with_chain)
    # close connection
    api.eoc()


def request_cert_from_csr_with_password_authentication(cert_with_chain):
    service = "CUST_PASSWD_INTERNAL_TESTUI"
    username = 'DemoUser'
    password = 'secret'

    api = CertRetrievalApi()
    # handshake
    api.hello()
    api.handshake()
    # authenticate
    auth_requirements = api.get_auth_requirements(service)
    assert not CertRetrievalApi.is_cr_authentication(
        auth_requirements), "Non-CR authentication is expected for service {}".format(service)
    creds = CertRetrievalApi.request_auth_credentials(auth_requirements, username, password)
    api.authenticate(creds, service)
    # get service
    api.get_last_messages()
    csr_requirements = api.get_csr_requirements()
    csr = CertRetrievalApi.gen_csr(csr_requirements)
    api.sign_csr(csr, cert_with_chain)
    # close connection
    api.eoc()


def request_out_of_band_cert_with_password_authentication(cert_format, cert_with_chain):
    service = "CUST_PASSWD_INTERNAL_TESTUI"
    username = 'DemoUser'
    password = 'secret'

    api = CertRetrievalApi()
    # handshake
    api.hello()
    api.handshake()
    # authenticate
    auth_requirements = api.get_auth_requirements(service)
    assert not CertRetrievalApi.is_cr_authentication(
        auth_requirements), "Non-CR authentication is expected for service {}".format(service)
    creds = CertRetrievalApi.request_auth_credentials(auth_requirements, username, password)
    api.authenticate(creds, service)
    # get service
    api.get_last_messages()
    api.get_cert(cert_format, cert_with_chain, out_of_band=True)
    # close connection
    api.eoc()


def request_cert_with_password_and_pincode_authentication(cert_format, cert_with_chain):
    service = "CUST_PIN_PASSWD_INTERNAL_TESTUI"
    username = 'DemoUser'
    password = 'secret'
    pincode = '1234'

    api = CertRetrievalApi()
    # handshake
    api.hello()
    api.handshake()
    # authenticate
    auth_requirements = api.get_auth_requirements(service)
    assert not CertRetrievalApi.is_cr_authentication(
        auth_requirements), "Non-CR authentication is expected for service {}".format(service)
    creds = CertRetrievalApi.request_auth_credentials(
        auth_requirements, username, password, pincode)
    api.authenticate(creds, service)
    # get service
    api.get_last_messages()
    api.get_cert(cert_format, cert_with_chain)
    # close connection
    api.eoc()


def request_cert_with_challenge_response_authentication(cert_format, cert_with_chain):
    service = "CUST_CR_INTERNAL_TESTUI"
    username = 'DemoUser'

    api = CertRetrievalApi()
    # handshake
    api.hello()
    api.handshake()
    # authenticate
    auth_requirements = api.get_auth_requirements(service)
    assert CertRetrievalApi.is_cr_authentication(
        auth_requirements), "CR authentication is expected for service {}".format(service)
    creds = CertRetrievalApi.request_auth_credentials(auth_requirements, username)
    challenges, response_names = api.authenticate(creds, service)
    creds = CertRetrievalApi.calc_responses(username, challenges, response_names)
    api.authenticate(creds)
    # get service
    api.get_last_messages()
    api.get_cert(cert_format, cert_with_chain)
    # close connection
    api.eoc()


def request_cert_with_radius_securid_authentication(cert_format, cert_with_chain):
    service = "CUST_PASSWD_RADIUS"
    username = 'SecuridNewUserPinUser'
    initial_tokencode = '666666'
    new_pin = '234567'
    new_tokencode = '777777'

    api = CertRetrievalApi()
    # handshake
    api.hello()
    api.handshake()
    # authenticate
    auth_requirements = api.get_auth_requirements(service)
    assert not CertRetrievalApi.is_cr_authentication(
        auth_requirements), "Non-CR authentication is expected for service {}".format(service)
    creds = CertRetrievalApi.request_auth_credentials(
        auth_requirements, username, initial_tokencode)
    api.authenticate(creds, service)
    creds = CertRetrievalApi.request_auth_credentials(auth_requirements, username, new_pin)
    api.authenticate(creds, service)
    creds = CertRetrievalApi.request_auth_credentials(auth_requirements, username, new_pin)
    api.authenticate(creds, service)
    creds = CertRetrievalApi.request_auth_credentials(auth_requirements, username, new_tokencode)
    api.authenticate(creds, service)
    # get service
    api.get_last_messages()
    api.get_cert(cert_format, cert_with_chain)
    # close connection
    api.eoc()


def request_cert_with_radius_eap_aka_authentication(cert_format, cert_with_chain):
    service = "CUST_EAP_CR_RADIUS"

    api = CertRetrievalApi()
    # handshake
    api.hello()
    api.handshake()
    # authenticate
    auth_requirements = api.get_auth_requirements(service)
    assert CertRetrievalApi.is_cr_authentication(
        auth_requirements), "CR authentication is expected for service {}".format(service)
    creds = CertRetrievalApi.request_auth_credentials(auth_requirements, UMTS_USERNAME)
    challenges, response_names = api.authenticate(creds, service)
    creds = CertRetrievalApi.calc_responses(UMTS_USERNAME, challenges, response_names)
    api.authenticate(creds)
    # get service
    api.get_last_messages()
    api.get_cert(cert_format, cert_with_chain)
    # close connection
    api.eoc()


def request_cert_with_radius_eap_sim_authentication(cert_format, cert_with_chain):
    service = "CUST_EAP_CR_RADIUS"

    api = CertRetrievalApi()
    # handshake
    api.hello()
    api.handshake()
    # authenticate
    auth_requirements = api.get_auth_requirements(service)
    assert CertRetrievalApi.is_cr_authentication(
        auth_requirements), "CR authentication is expected for service {}".format(service)
    creds = CertRetrievalApi.request_auth_credentials(auth_requirements, GSM_USERNAME)
    challenges, response_names = api.authenticate(creds, service)
    creds = CertRetrievalApi.calc_responses(GSM_USERNAME, challenges, response_names)
    challenges, response_names = api.authenticate(creds)
    creds = CertRetrievalApi.calc_responses(GSM_USERNAME, challenges, response_names)
    challenges, response_names = api.authenticate(creds)
    creds = CertRetrievalApi.calc_responses(GSM_USERNAME, challenges, response_names)
    api.authenticate(creds)
    # get service
    api.get_last_messages()
    api.get_cert(cert_format, cert_with_chain)
    # close connection
    api.eoc()


def change_password_and_request_cert(cert_format, cert_with_chain):
    service = "CUST_PASSWD_AD"
    username = 'TestUser'
    old_password = 'Sioux2010'
    new_password = 'Sioux2011'

    api = CertRetrievalApi()
    # handshake
    api.hello()
    api.handshake()
    # authenticate
    auth_requirements = api.get_auth_requirements(service)
    assert not CertRetrievalApi.is_cr_authentication(
        auth_requirements), "Non-CR authentication is expected for service {}".format(service)
    creds = CertRetrievalApi.request_auth_credentials(auth_requirements, username, old_password)
    password_validity_sec = api.authenticate(creds, service)
    assert CertRetrievalApi.is_password_expiring(
        password_validity_sec), "Password for user {} and service {} is not yet expiring (still valid for {} seconds)".format(username, service, password_validity_sec)
    api.change_password(old_password, new_password)
    creds[conf.CRED_PASSWD] = new_password
    api.authenticate(creds, service)
    # get service
    api.get_last_messages()
    api.get_cert(cert_format, cert_with_chain)
    # reset password back
    api.change_password(new_password, old_password)
    creds[conf.CRED_PASSWD] = old_password
    api.authenticate(creds, service)
    # close connection
    api.eoc()


def fetch_ca_certs():
    api = CaApi()

    cert = api.fetch_ca(conf.CA_API_SIGNING_CA)
    debug(
        "Fetched Signing CA. Subject: {}".format(
            OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM,
                cert).get_subject()))

    cert = api.fetch_ca(conf.CA_API_PRIMARY_CA)
    debug(
        "Fetched Primary CA. Subject: {}".format(
            OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM,
                cert).get_subject()))

    assert not api.fetch_ca(conf.CA_API_ROOT_CA), "Root CA is not expected to be present"


def check_self_service_availability():

    api = PublicApi()

    # given, get the cert for which self-service should be available
    request_cert_with_password_authentication(conf.CERT_FORMAT_PEM, False)
    cert = open('cert.pem').read()
    # when-then
    assert api.is_self_service_available(cert)

    # given, cert that doesn't correspond to DevID user hence no self-service
    cert = open(SERVER_VERIFICATION_CA_CHAIN[0]).read()
    # when-then
    assert not api.is_self_service_available(cert)

    try:
        api.is_self_service_available("invalid-cert")
        assert False, "Invalid certificate is not reported as bad request"
    except BadRequestError:
        pass


def retrieve_address_books():

    api = PublicApi()

    assert api.retrieve_address_books(service="CUST_ANO_INTERNAL") == []
    assert api.retrieve_address_books(
        service="CUST_PASSWD_AD") == [
        {
            'ldap_svr_url': 'ldaps://WIN2012-RESEPT-AD.Resept.2012.local',
            'search_base': 'dc=Resept,dc=2012,dc=local'},
        {
            'ldap_svr_url': 'ldap://addressbook.example.com',
            'search_base': 'people,dc=example,dc=com'},
    ]

    try:
        api.retrieve_address_books(service="NON_EXISTING_SERVICE")
        assert False, "Non-existing service is not reported as bad request"
    except BadRequestError:
        pass


#
# Entry point
#
if __name__ == "__main__":
    for cert_format in conf.CERT_FORMAT_STRINGS:
        for cert_with_chain in [True, False]:
            request_cert_with_password_authentication(cert_format, cert_with_chain)
            request_cert_with_password_and_pincode_authentication(cert_format, cert_with_chain)
            request_cert_with_challenge_response_authentication(cert_format, cert_with_chain)
            request_cert_with_radius_securid_authentication(cert_format, cert_with_chain)
            request_cert_with_radius_eap_aka_authentication(cert_format, cert_with_chain)
            request_cert_with_radius_eap_sim_authentication(cert_format, cert_with_chain)
            request_cert_from_csr_with_password_authentication(cert_with_chain)
            request_out_of_band_cert_with_password_authentication(cert_format, cert_with_chain)
            change_password_and_request_cert(cert_format, cert_with_chain)

    fetch_ca_certs()
    check_self_service_availability()
    retrieve_address_books()
