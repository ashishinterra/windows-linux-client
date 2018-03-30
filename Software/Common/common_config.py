#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# KeyTalk common constants
#
COMPANY_NAME = "KeyTalk"
PRODUCT_NAME = "KeyTalk"

MAX_PROVIDER_LENGTH = 64
MAX_SERVICE_LENGTH = 64
MAX_USER_ID_LENGTH = 255
MAX_CLIENT_DESC_LENGTH = 64
MAX_PASSWORD_LENGTH = 64
MAX_CHALLENGE_LENGTH = 64
MAX_RESPONSE_LENGTH = 64
MAX_PINCODE_LENGTH = 64

SUPPORT_EMAIL = "support@keytalk.com"

# @note hardcoded CS for formula "0" as calculated by the client, hardcoded because it is used by the server which cannot call client's CS calculation routines
ZERO_CS = "CS-F7B11509F4D675C3C44F0DD37CA830BB02E8CFA58F04C46283C4BFCBDCE1FF45"

# Credential types
CRED_USERID = "USERID"
CRED_HWSIG = "HWSIG"
CRED_PASSWD = "PASSWD"
CRED_PIN = "PIN"
CRED_RESPONSE = "RESPONSE"
CREDENTIAL_STRINGS = [CRED_USERID, CRED_HWSIG, CRED_PASSWD, CRED_PIN, CRED_RESPONSE]

CERT_FORMAT_P12 = "P12"
CERT_FORMAT_PEM = "PEM"
CERT_FORMAT_STRINGS = [CERT_FORMAT_P12, CERT_FORMAT_PEM]

AUTH_OK = "OK"
AUTH_DELAY = "DELAY"
AUTH_LOCKED = "LOCKED"
AUTH_EXPIRED = "EXPIRED"
AUTH_CHALLENGE = "CHALLENGE"
AUTH_RESULT_STRINGS = [AUTH_OK, AUTH_DELAY, AUTH_LOCKED, AUTH_EXPIRED, "_NOT_USED_", AUTH_CHALLENGE]

#
# RCDP common constants
#

RCDP_PACKAGED_CERT_EXPORT_PASSWDSIZE = 30
RCDP_PASSWORD_NEVER_EXPIRES = -1

RCDP_ERR_CODE = \
    {
        # Sent by the server when none of IPs  resolved by the client and by the server match.
        "ErrResolvedIpInvalid": 1001,
        # Sent by server when the client’s calculated executable digest does not
        # much the digest stored on the server.
        "ErrDigestInvalid": 1002,
        # Sent by the server when the client time is out of sync with the server’s time.
        "ErrTimeOutOfSync": 1003,
        # Sent by the server when no certificate can be supplied because the max
        # number of licensed users has been reached
        "ErrMaxLicensedUsersReached": 1004,
        # Sent by the server when the password of the user trying to authenticate
        # is expired but the client is not supposed to start password change
        # procedure
        "ErrPasswordExpired": 1005
    }

#
# RCDPv1 constants
#

RCDP_VERSION_1_4 = "1.4"
RCDP_VERSION_1_5 = "1.5"

SERVER_SUPPORTED_RCDPV1_VERSIONS = [RCDP_VERSION_1_4, RCDP_VERSION_1_5]

RCDPV1_RESEPT_SVR_PATH = "resept"
RCDPV1_HTTP_SID_COOKIE_NAME = "reseptcookie"
RCDPV1_HTTP_MSG_VAL_PREFIX = "RCDP_"
RCDPV1_LAST_MSG_REQUEST_ALL = "ALL"

RCDPV1_AES_GCM_TAG_SIZE = 16
RCDPV1_AES_GCM_IV_SIZE = 16

RCDPV1_NOTSUP_CODE = \
    {
        "NotSupAuthReqRenew": 2001,
        "NotSupAuthMethod": 2002,
    }


# phase 1 messages
RCDPV1_MSG_VSMREQ = "VSMREQ"
RCDPV1_MSG_VSMACK = "VSMACK"

# phase 2 messages
RCDPV1_MSG_CT = "CT"
RCDPV1_MSG_R3USE = "R3USE"
RCDPV1_MSG_R3RESP = "R3RESP"
RCDPV1_MSG_R3OK = "R3OK"
RCDPV1_MSG_ECUSE = "ECUSE"
RCDPV1_MSG_ECRESP = "ECRESP"
RCDPV1_MSG_ECOK = "ECOK"

# phase 2 constants
RCDPV1_KEY_AGREEMENT_R3 = "R3"
RCDPV1_KEY_AGREEMENT_EC = "EC"

# phase 3 messages
RCDPV1_MSG_AUTH = "AUTH"
RCDPV1_MSG_AUTHREQ = "AUTHREQ"
RCDPV1_MSG_AUTHRESP = "AUTHRESP"
RCDPV1_MSG_AUTHRESULT = "AUTHRESULT"
RCDPV1_MSG_LDAPCHANGEPWD = "LDAPCHANGEPWD"
RCDPV1_MSG_LDAPCHANGEPWDRESULT = "LDAPCHANGEPWDRESULT"
RCDPV1_MSG_LDAPCHANGEPWD = "LDAPCHANGEPWD"
RCDPV1_MSG_LDAPCHANGEPWDRESULT = "LDAPCHANGEPWDRESULT"

# phase 3 constants
RCDPV1_AUTH_RENEW = "RENEW"
RCDPV1_AUTH_SYNC = "SYNC"

# phase 4 messages
RCDPV1_MSG_LASTMSG = "LASTMSG"
RCDPV1_MSG_NEWMSG = "NEWMSG"
RCDPV1_MSG_LICENSE = "LICENSE"

# phase 4 constants
RCDPV1_MSG_LASTMSG_ALL = RCDPV1_LAST_MSG_REQUEST_ALL

# phase 5 messages
RCDPV1_MSG_FORMAT = "FORMAT"
RCDPV1_MSG_URL = "URL"
RCDPV1_MSG_RESOLVED = "RESOLVED"
RCDPV1_MSG_CERT = "CERT"
RCDPV1_MSG_EXEC = "EXEC"
RCDPV1_MSG_DIGEST = "DIGEST"
RCDPV1_MSG_FIN = "FIN"


# cross-phase Messages
RCDPV1_MSG_EOC = "EOC"
RCDPV1_MSG_ERR = "ERR"
RCDPV1_MSG_NOTSUP = "NOTSUP"

RCDPV1_REQUEST_STRINGS = [RCDPV1_MSG_EOC, RCDPV1_MSG_VSMREQ, RCDPV1_MSG_CT, RCDPV1_MSG_R3RESP, RCDPV1_MSG_ECRESP, RCDPV1_MSG_AUTH, RCDPV1_MSG_AUTHRESP, RCDPV1_MSG_LICENSE,
                          RCDPV1_MSG_LASTMSG, RCDPV1_MSG_FORMAT, RCDPV1_MSG_RESOLVED, RCDPV1_MSG_DIGEST, RCDPV1_MSG_FIN, RCDPV1_MSG_ERR, RCDPV1_MSG_NOTSUP, RCDPV1_MSG_LDAPCHANGEPWD]
RCDPV1_RESPONSE_STRINGS = [RCDPV1_MSG_EOC, RCDPV1_MSG_VSMACK, RCDPV1_MSG_R3USE, RCDPV1_MSG_R3OK, RCDPV1_MSG_ECUSE, RCDPV1_MSG_ECOK, RCDPV1_MSG_AUTHREQ, RCDPV1_MSG_AUTHRESULT,
                           RCDPV1_MSG_LICENSE, RCDPV1_MSG_NEWMSG, RCDPV1_MSG_URL, RCDPV1_MSG_EXEC, RCDPV1_MSG_CERT, RCDPV1_MSG_FIN, RCDPV1_MSG_ERR, RCDPV1_MSG_NOTSUP, RCDPV1_MSG_LDAPCHANGEPWDRESULT]
RCDPV1_KEY_AGREEMENT_STRINGS = [RCDPV1_KEY_AGREEMENT_R3, RCDPV1_KEY_AGREEMENT_EC]
RCDPV1_AUTH_REQUEST_OPT_STRINGS = [RCDPV1_AUTH_RENEW, RCDPV1_AUTH_SYNC]
RCDPV1_FORMAT_REQUEST_CHAIN = "chain"

RCDPV1_STATE_STRINGS = ["closed", "handshake", "encryption_started",
                        "encryption_established", "authentication_started", "authentication_established", "service"]

# LDAP Change password constants
RCDPV1_CHANGEPWD_USERID = CRED_USERID
RCDPV1_CHANGEPWD_PASSWD = CRED_PASSWD
RCDPV1_CHANGEPWD_NEWPASSWD = "NEWPASSWD"

#
# RCDP v2 constants
#

RCDP_VERSION_2_0 = "2.0.0"

SERVER_SUPPORTED_RCDPV2_VERSIONS = [RCDP_VERSION_2_0]
CLIENT_SUPPORTED_RCDPV2_VERSIONS = [RCDP_VERSION_2_0]

RCDPV2_HTTP_REQUEST_URI_PREFIX = "rcdp"
RCDPV2_HTTP_SID_COOKIE_NAME = "keytalkcookie"

#
# requests
#
RCDPV2_REQUEST_EOC = "eoc"
RCDPV2_REQUEST_ERROR = "error"
RCDPV2_REQUEST_HELLO = "hello"
RCDPV2_REQUEST_HANDSHAKE = "handshake"
RCDPV2_REQUEST_AUTH_REQUIREMENTS = "auth-requirements"
RCDPV2_REQUEST_AUTHENTICATION = "authentication"
RCDPV2_REQUEST_CHANGE_PASSWORD = "change-password"
RCDPV2_REQUEST_LAST_MESSAGES = "last-messages"
RCDPV2_REQUEST_CERT = "cert"

RCDPV2_REQUEST_STRINGS = [RCDPV2_REQUEST_EOC,
                          RCDPV2_REQUEST_ERROR,
                          RCDPV2_REQUEST_HELLO,
                          RCDPV2_REQUEST_HANDSHAKE,
                          RCDPV2_REQUEST_AUTH_REQUIREMENTS,
                          RCDPV2_REQUEST_AUTHENTICATION,
                          RCDPV2_REQUEST_CHANGE_PASSWORD,
                          RCDPV2_REQUEST_LAST_MESSAGES,
                          RCDPV2_REQUEST_CERT,
                          ]

RCDPV2_REQUEST_PARAM_NAME_CALLER_APP_DESCRIPTION = "caller-app-description"
RCDPV2_REQUEST_PARAM_NAME_CALLER_HW_DESCRIPTION = "caller-hw-description"
RCDPV2_REQUEST_PARAM_NAME_ERROR_CODE = "code"
RCDPV2_REQUEST_PARAM_NAME_ERROR_DESCRIPTION = "description"
RCDPV2_REQUEST_PARAM_NAME_REASON = "reason"
RCDPV2_REQUEST_PARAM_NAME_CALLER_UTC = "caller-utc"
RCDPV2_REQUEST_PARAM_NAME_SERVICE = "service"
RCDPV2_REQUEST_PARAM_NAME_LAST_MESSAGES_FROM_UTC = "from-utc"
RCDPV2_REQUEST_PARAM_NAME_KEYPAIR = "keypair"
RCDPV2_REQUEST_PARAM_NAME_PUBKEY = "pubkey"
RCDPV2_REQUEST_PARAM_NAME_PRIVKEY = "privkey"
RCDPV2_REQUEST_PARAM_NAME_CERT_FORMAT = "format"
RCDPV2_REQUEST_PARAM_NAME_CERT_INCLUDE_CHAIN = "include-chain"
RCDPV2_REQUEST_PARAM_NAME_RESOLVED = "resolved"
RCDPV2_REQUEST_PARAM_NAME_DIGESTS = "digests"
RCDPV2_REQUEST_PARAM_NAME_URI = "uri"
RCDPV2_REQUEST_PARAM_NAME_IPS = "ips"
RCDPV2_REQUEST_PARAM_NAME_DIGEST = "digest"
RCDPV2_REQUEST_PARAM_NAME_RESPONSES = "responses"
RCDPV2_REQUEST_PARAM_NAME_NAME = "name"
RCDPV2_REQUEST_PARAM_NAME_VALUE = "value"
RCDPV2_REQUEST_PARAM_NAME_OLD_PASSWORD = "old-password"
RCDPV2_REQUEST_PARAM_NAME_NEW_PASSWORD = "new-password"

#
# responses
#
RCDPV2_RESPONSE_EOC = "eoc"
RCDPV2_RESPONSE_ERROR = "error"
RCDPV2_RESPONSE_HELLO = "hello"
RCDPV2_RESPONSE_HANDSHAKE = "handshake"
RCDPV2_RESPONSE_AUTH_REQUIREMENTS = "auth-requirements"
RCDPV2_RESPONSE_AUTH_RESULT = "auth-result"
RCDPV2_RESPONSE_LAST_MESSAGES = "last-messages"
RCDPV2_RESPONSE_CERT = "cert"

RCDPV2_RESPONSE_STRINGS = [RCDPV2_RESPONSE_EOC,
                           RCDPV2_RESPONSE_ERROR,
                           RCDPV2_RESPONSE_HELLO,
                           RCDPV2_RESPONSE_HANDSHAKE,
                           RCDPV2_RESPONSE_AUTH_REQUIREMENTS,
                           RCDPV2_RESPONSE_AUTH_RESULT,
                           RCDPV2_RESPONSE_LAST_MESSAGES,
                           RCDPV2_RESPONSE_CERT,
                           ]

RCDPV2_RESPONSE_PARAM_NAME_STATUS = "status"
RCDPV2_RESPONSE_PARAM_NAME_ERROR_CODE = "code"
RCDPV2_RESPONSE_PARAM_NAME_ERROR_DESCRIPTION = "description"
RCDPV2_RESPONSE_PARAM_NAME_VERSION = "version"
RCDPV2_RESPONSE_PARAM_NAME_REASON = "reason"
RCDPV2_RESPONSE_PARAM_NAME_SERVER_UTC = "server-utc"
RCDPV2_RESPONSE_PARAM_NAME_CRED_TYPES = "credential-types"
RCDPV2_RESPONSE_PARAM_NAME_HWSIG_FORMULA = "hwsig_formula"
RCDPV2_RESPONSE_PARAM_NAME_PASSWORD_PROMPT = "password-prompt"
RCDPV2_RESPONSE_PARAM_NAME_CHALLENGES = "challenges"
RCDPV2_RESPONSE_PARAM_NAME_NAME = "name"
RCDPV2_RESPONSE_PARAM_NAME_VALUE = "value"
RCDPV2_RESPONSE_PARAM_NAME_RESPONSE_NAMES = "response-names"
RCDPV2_RESPONSE_PARAM_NAME_AUTH_STATUS = "auth-status"
RCDPV2_RESPONSE_PARAM_NAME_PASSWORD_VALIDITY = "password-validity"
RCDPV2_RESPONSE_PARAM_NAME_DELAY = "delay"
RCDPV2_RESPONSE_PARAM_NAME_LAST_MESSAGES = "messages"
RCDPV2_RESPONSE_PARAM_NAME_MESSAGE_UTC = "utc"
RCDPV2_RESPONSE_PARAM_NAME_MESSAGE_TEXT = "text"
RCDPV2_RESPONSE_PARAM_NAME_CERT = "cert"
RCDPV2_RESPONSE_PARAM_NAME_SERVICE_URIS = "service-uris"
RCDPV2_RESPONSE_PARAM_NAME_RESOLVE_SERVICE_URIS = "resolve-service-uris"
RCDPV2_RESPONSE_PARAM_NAME_CALC_SERVICE_URIS_DIGEST = "calc-service-uris-digest"
RCDPV2_RESPONSE_PARAM_NAME_EXECUTE_SYNC = "execute-sync"


# state
RCDPV2_STATE_STRINGS = ["closed", "hello", "connected", "pending-response", "authenticated"]
