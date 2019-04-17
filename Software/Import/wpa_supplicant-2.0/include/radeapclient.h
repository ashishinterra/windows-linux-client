#ifndef RADEAPCLIENT_H
#define RADEAPCLIENT_H

#include <stdint.h>

static const char* rad_eap_client_prog_name = "radeapclient";
static const char* rad_eap_client_connect_ipv4 = "127.0.0.1";

enum rad_eap_client_exit_code
{
    rad_eap_client_exit_code_auth_ok = 0,
    rad_eap_client_exit_code_auth_nok,
    rad_eap_client_exit_code_radius_svr_connection_error = 10, // error connecting to RADUIS server (invalid IP/port or secret)
    rad_eap_client_exit_code_default_error = 100
};

static const int32_t rad_eap_client_msg_code_auth_ok = 0;
static const int32_t rad_eap_client_msg_code_auth_nok = 1;
static const int32_t rad_eap_client_msg_code_challenge = 2;
static const int32_t rad_eap_client_msg_code_radius_svr_connection_error = 10;
static const int32_t rad_eap_client_msg_code_default_error = 100;

#endif //RADEAPCLIENT_H
