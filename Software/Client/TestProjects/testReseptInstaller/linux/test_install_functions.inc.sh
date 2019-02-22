#!/bin/bash

# The include file contains misc helper functions used by installation test scripts

DEFAULT_CONTENT_VERSION="2011032901"


if [ -f /etc/redhat-release -a $(lsb_release --release --short | egrep -o [0-9]+ | sed -n '1p') -eq 6 ]; then
    # RHL6, CentOS6 with systemV
    KEYTALK_CA_UPDATER_SERVICE_FILE=/etc/init.d/keytalk-ca-updater
else
    # systemd
    KEYTALK_CA_UPDATER_SERVICE_FILE=/etc/systemd/system/keytalk-ca-updater.service
fi

INSTALLATION_FILES_REQUIRED="\
/usr/local/bin/keytalk/ktclient \
/usr/local/bin/keytalk/ktconfig \
/usr/local/bin/keytalk/ktconfupdater \
/usr/local/bin/keytalk/ktconfigtool \
/usr/local/bin/keytalk/ktprgen \
/usr/local/bin/keytalk/hwutils \
/usr/local/bin/keytalk/renew_apache_ssl_cert \
/usr/local/bin/keytalk/renew_tomcat_ssl_cert \
/usr/local/bin/keytalk/util.py \
/usr/local/bin/keytalk/apache_util.py \
/usr/local/bin/keytalk/tomcat_util.py \
/usr/local/bin/keytalk/tomcat.sh \
/usr/local/bin/keytalk/keytalk_ca_updater.sh \
${KEYTALK_CA_UPDATER_SERVICE_FILE} \
/usr/local/bin/keytalk/uninstall_keytalk \
/usr/local/lib/keytalk/libtalogger.so \
/etc/keytalk/resept.ini \
/etc/keytalk/apache.ini \
/etc/keytalk/tomcat.ini \
/etc/keytalk/version \
/etc/keytalk/devstage \
/etc/keytalk/cr.conf \
/etc/cron.d/keytalk.apache \
/etc/cron.d/keytalk.tomcat \
/usr/share/doc/keytalk/KeyTalk_LinuxClient_for_Apache.txt \
/usr/share/doc/keytalk/KeyTalk_LinuxClient_for_Apache.pdf \
/usr/share/doc/keytalk/KeyTalk_LinuxClient_for_Tomcat.txt \
/usr/share/doc/keytalk/KeyTalk_LinuxClient_for_Tomcat.pdf"

INSTALLATION_DIRS_REQUIRED="\
/usr/local/bin/keytalk \
/usr/local/lib/keytalk \
/etc/keytalk \
/usr/share/doc/keytalk"

PR_FILES_REQUIRED_PATTERN="\
version \
devstage \
user\.ini \
resept\.ini \
apache\.ini \
tomcat\.ini \
etc_cron_d_keytalk_apache \
etc_cron_d_keytalk_tomcat \
apache_ports\.conf \
ktclient\.log \
ktconfig\.log \
ktconfupdater\.log \
ktcaupdater\.log \
signing_ca_[0-9a-f]*\.pem \
comm_ca_[0-9a-f]*\.pem \
primary_ca_[0-9a-f]*\.pem"


function trusted_ca_store_path()
{
    if [ -f /etc/debian_version ]; then
        echo "/usr/local/share/ca-certificates"
        return 0
    elif [ -f /etc/redhat-release ]; then
        echo "/etc/pki/ca-trust/source/anchors"
        return 0
    else
        echo "ERROR: cannot retrieve trusted ca store path" >&2
        return 1
    fi
}

# usage client_platform_file_suffix="$(get_client_platform_file_suffix)"
function get_client_platform_file_suffix()
{
    local distro_name=$(lsb_release --id --short)
    local distro_version_major=$(lsb_release --release --short | egrep -o [0-9]+ | sed -n '1p')
    local arch=$(uname -m)
    local test_platform="${distro_name}-${distro_version_major}-${arch}"
    if [ "${test_platform}" == "Debian-8-x86_64" ]; then
      echo "debian8-x64"
      return 0
    elif [ "${test_platform}" == "Debian-9-x86_64" ]; then
      echo "debian9-x64"
      return 0
    elif [ "${test_platform}" == "Ubuntu-16-x86_64" ]; then
      echo "ubuntu16-x64"
      return 0
    elif [ "${test_platform}" == "Ubuntu-18-x86_64" ]; then
      echo "ubuntu18-x64"
      return 0
    elif [ "${test_platform}" == "CentOS-6-x86_64" ]; then
        echo "centos6-x64"
        return 0
    elif [ "${test_platform}" == "CentOS-7-x86_64" ]; then
        echo "centos7-x64"
        return 0
    elif [ "${test_platform}" == "RedHatEnterpriseServer-6-x86_64" ]; then
        echo "rhel6-x64"
        return 0
    elif [ "${test_platform}" == "RedHatEnterpriseServer-7-x86_64" ]; then
        echo "rhel7-x64"
        return 0
    else
      echo "ERROR: ${test_platform} platform is not supported" >&2
      return 1
    fi
}

#usage cleanup_keytalk_installation [logs-backup-dir]
function cleanup_keytalk_installation()
{
  if pgrep -x ktclient ; then
      echo "WARNING: terminating active ktclient processes"
      killall -v ktclient
  fi
  if pgrep -x ktconfig ; then
      echo "WARNING: terminating active ktconfig processes"
      killall -v ktconfig
  fi

  [ $# -eq 1 ] && copy_keytalk_logs_to "$1"

  rm -rf ~/.keytalk/
  rm -rf ${INSTALLATION_DIRS_REQUIRED}
  rm -f /etc/cron.d/keytalk*

  service keytalk-ca-updater stop > /dev/null 2>&1 || true
  rm -f ${KEYTALK_CA_UPDATER_SERVICE_FILE}
  rm -f $(trusted_ca_store_path)/keytalk_*.crt
  if [ -f /etc/debian_version ]; then
    update-ca-certificates --fresh || true
  elif [ -f /etc/redhat-release ]; then
    update-ca-trust extract || true
  fi
}

# usage parse_rccd_props $rccd_file provider rccd_type content_version
# filename is settings.<ProviderName>.<rccd-type>[.<content-version>].rccd
function parse_rccd_props()
{
    local rccd1_path="$1"
    local filename=$(basename ${rccd1_path})
    eval "$2"=$(echo ${filename} | cut -d . -f 2)
    eval "$3"=$(echo ${filename} | cut -d . -f 3)
    local component4=$(echo ${filename} | cut -d . -f 4)
    local content_version=${DEFAULT_CONTENT_VERSION}
    if [ x"${component4}" != x"rccd" ]; then
        content_version=${component4}
    fi
    eval "$4"=${content_version}
}

# usage find_cert ${dir} ${cn}
function find_cert_with_cn()
{
    local dir="$1"
    local cn="$2"

    for cert in $(ls ${dir}) ; do
        if openssl x509 -subject -noout -in ${cert} | grep -q "CN\s*=\s*${cn}" ; then
            return 0
        fi
    done
    echo "ERROR: No certificate with CN ${cn} found under ${dir}" >&2
    return 1
}

function verify_installation()
{
    for f in ${INSTALLATION_FILES_REQUIRED} ; do
        if [ ! -f ${f} ] ; then
            echo "ERROR: Installation failed. ${f} not found" >&2
            return 1
        fi
    done
}

# usage; verify_customization ${rccd1_path} ${rccd1_provider} ${rccd1_type} [${rccd2_path} ${rccd2_provider} ${rccd2_type}]
function verify_customization()
{
    local rccd_path="$1"
    local rccd_provider="$2"
    local rccd_type="$3"

    local customization_files_required=$(_customization_files_required ${rccd_provider} ${rccd_type})
    for f in ${customization_files_required} ; do
        if [ ! -f ${f} ] ; then
            echo "ERROR: Customization with ${rccd_path} failed. ${f} not found" >&2
            return 1
        fi
    done

    if ! grep -q "\"${rccd_provider}\"" /etc/keytalk/resept.ini ; then
        echo "ERROR: Customization with ${rccd_path} failed. Provider ${rccd_provider} not found in /etc/keytalk/resept.ini" >&2
        return 1
    fi

    # Verify installed CAs (3 at least but there might also be extra CAs from 3rd party signer such as GlobalSign)
    local num
    local ca_store=$(trusted_ca_store_path)
    num=$(ls $ca_store/keytalk_*.crt | wc -l)
    if (( num < 3 )) ; then
        echo "ERROR: Installation failed. Invalid number of intermediate CAs installed. Actual: ${num}, expected at least 3" >&2
        return 1
    fi

    if ! find_cert_with_cn "$ca_store/keytalk_*.crt" "KeyTalk Demo Signing CA" ; then
        return 1
    fi
    if ! find_cert_with_cn "$ca_store/keytalk_*.crt" "KeyTalk Demo CCA" ; then
        return 1
    fi
    if ! find_cert_with_cn "$ca_store/keytalk_*.crt" "KeyTalk Demo PCA" ; then
        return 1
    fi


    if [ $# -eq 6 ] ; then
        verify_customization "$4" "$5" "$6"
    fi
}

# Lean & mean provisioning test
# usage: verify_provisioning ${provider1} [${provider2} ...]
function verify_provisioning()
{
    for provider in "$@"
    do
        rm -rf ~/.keytalk/keystore/*.pem
        if ! /usr/local/bin/keytalk/ktclient --provider ${provider} --service CUST_ANO_INTERNAL_TESTUI --user DemoUser ; then
            echo "ERROR: Provisioning test failed. KeyTalk client is not properly configured" >&2
            return 1
        fi

        num=$(ls ~/.keytalk/keystore/*.pem | wc -l)
        if [ "${num}" -ne "1" ] ; then
            echo "ERROR: Provisioning test failed. No or more than one personal certificates received. Actual: ${num}, expected 1" >&2
            return 1
        fi
        for f in ~/.keytalk/keystore/*.pem ; do
            permissions=$(stat --format '%a' "$f")
            if [ "${permissions}" != "400" ]; then
                echo "ERROR: Invalid permission ${permissions} of the personal certificate ${f}. Expected 400" >&2
                return 1
            fi
        done

    done
}

# Problem report generation test
# usage: verify_pr_generation
function verify_pr_generation()
{
    if ! /usr/local/bin/keytalk/ktprgen ; then
        echo "ERROR: PR generation test failed. KeyTalk PR tool finished with error" >&2
        return 1
    fi
    if [ ! -f ~/keytalk.clnt.pr.dat ]; then
        echo "ERROR: PR generation test failed. No PR file generated at ~/keytalk.clnt.pr.dat" >&2
        return 1
    fi

    local pr_files=$(unzip -lqq ~/keytalk.clnt.pr.dat)
    for expected_file in ${PR_FILES_REQUIRED_PATTERN} ; do
        if ! echo ${pr_files} | grep -oq ${expected_file} ; then
            echo "ERROR: PR generation test failed. No ${expected_file} found in ~/keytalk.clnt.pr.dat" >&2
            echo "PR file listing: ${pr_files}"
            return 1
        fi
    done
}


# usage: files=$(_customization_files_required $provider $rccd_type)
function _customization_files_required()
{
    local provider="$1"
    local rccd_type="$2"

    # notice we use '$HOME' because '~' is not expanded in this construct
    local files="$HOME/.keytalk/user.ini"

    if [ x"${rccd_type}" == x"admin" ]; then
        files+=" /etc/keytalk/master.ini"
    fi

    echo ${files}
}

# usage: copy_keytalk_logs_to $dir
function copy_keytalk_logs_to()
{
    local log_dir="$1"

    [ ! -d "${log_dir}" ] && mkdir -p "${log_dir}"
    [ -f ~/.keytalk/ktclient.log ] && cp -f ~/.keytalk/ktclient.log "${log_dir}/"
    if ls ~/tmp/kt*.log > /dev/null 2>&1 ; then
       cp -f ~/tmp/kt*.log "${log_dir}/"
    fi
}

# usage: configure_apache $site_config_path
function create_apache_ssl_cert_key()
{
    local site_config_path="$1"

    local certs_file_path=$(grep -E '^\s+SSLCertificateFile\s+' ${site_config_path} | awk '{print $2}')
    local key_file_path=$(grep -E '^\s+SSLCertificateKeyFile\s+' ${site_config_path} | awk '{print $2}')
    cat apache/localhost-ssl-cert/cert.pem apache/localhost-ssl-cert/cas.pem > ${certs_file_path}
    cp -f apache/localhost-ssl-cert/key.pem ${key_file_path}
}

# usage: configure_apache $cas-dir
function configure_apache()
{
    echo "Configuring Apache for test"

    local cas_dir="$1"

    cp apache/apache.ini /etc/keytalk/
    cat ${cas_dir}/signingcacert.pem ${cas_dir}/pcacert.pem > apache/localhost-ssl-cert/cas.pem

    if ! grep -q a.example.com /etc/hosts; then
        echo "127.0.0.1 a.example.com" >> /etc/hosts
    fi
    if ! grep -q b.example.com /etc/hosts; then
        echo "127.0.0.1 b.example.com" >> /etc/hosts
    fi

    if which apache2 > /dev/null 2>&1 ; then
        # Apache2

        if ! grep -q "NameVirtualHost \*:3003" /etc/apache2/apache2.conf; then
            echo "NameVirtualHost *:3003" >> /etc/apache2/apache2.conf
        fi


        # disable sites we don't need
        a2dissite default 000-default default-ssl || true > /dev/null

        # setup listen ports
        local newline=$'\n'
        local ports_conf="<IfModule ssl_module>"
        for port in 3000 3001 3002 3003 ; do
            ports_conf+="${newline}Listen ${port}"
        done
        ports_conf+="${newline}</IfModule>"
        echo "${ports_conf}" > /etc/apache2/ports.conf

        # setup port-based virtual hosts on ports 3000, 3001 and 3002
        for port in 3000 3001 3002 ; do
            local site_config_path=/etc/apache2/sites-available/keytalk-test-${port}-ssl.conf
            sed -E "s/\{\{LISTEN_PORT\}\}/${port}/" apache/ssl.conf.templ > ${site_config_path}
            sed -i -E "s/\{\{SERVER_NAME_DIRECTIVE\}\}//" ${site_config_path}
            sed -i -E "s/\{\{DASH_SERVER_NAME\}\}//" ${site_config_path}
            sed -i -E "s/\{\{CERTS_DIR\}\}/\/etc\/ssl\/certs/" ${site_config_path}
            sed -i -E "s/\{\{KEYS_DIR\}\}/\/etc\/ssl\/private/" ${site_config_path}
            a2ensite keytalk-test-${port}-ssl.conf > /dev/null
            create_apache_ssl_cert_key ${site_config_path}
        done

        # setup name-based virtual hosts on port 3003
        for server_name in "a.example.com" "b.example.com" ; do
            local site_config_path=/etc/apache2/sites-available/keytalk-test-3003-${server_name}-ssl.conf
            sed -E "s/\{\{LISTEN_PORT\}\}/3003/" apache/ssl.conf.templ > ${site_config_path}
            sed -i -E "s/\{\{SERVER_NAME_DIRECTIVE\}\}/ServerName $server_name/" ${site_config_path}
            sed -i -E "s/\{\{DASH_SERVER_NAME\}\}/-$server_name/" ${site_config_path}
            sed -i -E "s/\{\{CERTS_DIR\}\}/\/etc\/ssl\/certs/" ${site_config_path}
            sed -i -E "s/\{\{KEYS_DIR\}\}/\/etc\/ssl\/private/" ${site_config_path}
            a2ensite keytalk-test-3003-${server_name}-ssl.conf > /dev/null
            create_apache_ssl_cert_key ${site_config_path}
        done

        # effectuate changes
        if ! service apache2 restart ; then
            echo "ERROR restarting Apache. Recent apache error log:"
            tail -n 50 /var/log/apache2/error.log || true
            return 1
        fi

    elif which httpd > /dev/null 2>&1 ; then
        # httpd


        # cleanup
        rm -f /etc/httpd/conf.d/README
        rm -f /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/welcome.conf
        rm -f /etc/httpd/conf.d/autoindex.conf /etc/httpd/conf.d/userdir.conf
        rm -f /etc/httpd/conf.d/keytalk-test-*.conf.orig.*

        # enable SSL
        echo "LoadModule ssl_module modules/mod_ssl.so" >> /etc/httpd/conf/httpd.conf
        # setup listen ports
        sed -E -i "s/^Listen[[:space:]]+[[:digit:]]+$//" /etc/httpd/conf/httpd.conf
        echo "<IfModule mod_ssl.c>" >> /etc/httpd/conf/httpd.conf
        for port in 3000 3001 3002 3003 ; do
            echo "Listen ${port}" >> /etc/httpd/conf/httpd.conf
        done
        echo "</IfModule>" >> /etc/httpd/conf/httpd.conf

        # setup Named virtual hosts
        if ! grep -q "NameVirtualHost \*:3003" /etc/httpd/conf/httpd.conf; then
            echo "NameVirtualHost *:3003" >> /etc/httpd/conf/httpd.conf
        fi

        # setup port-based virtual hosts on ports 3000, 3001 and 3002
        for port in 3000 3001 3002 ; do
            local site_config_path=/etc/httpd/conf.d/keytalk-test-${port}-ssl.conf
            sed -E "s/\{\{LISTEN_PORT\}\}/${port}/" apache/ssl.conf.templ > ${site_config_path}
            sed -i -E "s/\{\{SERVER_NAME_DIRECTIVE\}\}//" ${site_config_path}
            sed -i -E "s/\{\{DASH_SERVER_NAME\}\}//" ${site_config_path}
            sed -i -E "s/\{\{CERTS_DIR\}\}/\/etc\/pki\/tls\/certs/" ${site_config_path}
            sed -i -E "s/\{\{KEYS_DIR\}\}/\/etc\/pki\/tls\/private/" ${site_config_path}
            create_apache_ssl_cert_key ${site_config_path}
        done

        # setup name-based virtual hosts on port 3003
        for server_name in "a.example.com" "b.example.com" ; do
            local site_config_path=/etc/httpd/conf.d/keytalk-test-3003-${server_name}-ssl.conf
            sed -E "s/\{\{LISTEN_PORT\}\}/3003/" apache/ssl.conf.templ > ${site_config_path}
            sed -i -E "s/\{\{SERVER_NAME_DIRECTIVE\}\}/ServerName $server_name/" ${site_config_path}
            sed -i -E "s/\{\{DASH_SERVER_NAME\}\}/-$server_name/" ${site_config_path}
            sed -i -E "s/\{\{CERTS_DIR\}\}/\/etc\/pki\/tls\/certs/" ${site_config_path}
            sed -i -E "s/\{\{KEYS_DIR\}\}/\/etc\/pki\/tls\/private/" ${site_config_path}
            create_apache_ssl_cert_key ${site_config_path}
        done

        # Include SSL configs created
        sed -E -i "s/^Include[[:space:]]+$//" /etc/httpd/conf/httpd.conf
        echo "Include conf.d/*.conf" >> /etc/httpd/conf/httpd.conf

        # create test page
        cp -f apache/index.html /var/www/html/

        # effectuate changes
        if ! service httpd restart ; then
            echo "ERROR restarting Apache. Recent apache error log:"
            tail -n 50 /var/log/httpd/error.log || true
            return 1
        fi

    else
        echo "ERROR No Apache installation detected"
        return 1
    fi
}

function configure_tomcat()
{
    echo "Configuring Tomcat for test"

    cp tomcat/tomcat.ini /etc/keytalk/

    local tomcat_dir=""

    # Identifying Tomcat directory
    if [ -f /usr/sbin/tomcat ]; then
        tomcat_dir="tomcat"
    elif [ -f /etc/init.d/tomcat ]; then
        tomcat_dir="tomcat"
    elif [ -f /etc/init.d/tomcat9 ]; then
        tomcat_dir="tomcat9"
    elif [ -f /etc/init.d/tomcat8 ]; then
        tomcat_dir="tomcat8"
    elif [ -f /etc/init.d/tomcat7 ]; then
        tomcat_dir="tomcat7"
    elif [ -f /etc/init.d/tomcat6 ]; then
        tomcat_dir="tomcat6"
    else
        tomcat_dir="tomcat"
    fi

    local server_xml_file="/etc/${tomcat_dir}/server.xml"

    # Edit server.xml to enable 8443 port for SSL connection to Tomcat, using certificate stored in JAVA keystore
    if ! grep -q "keystoreFile=\"/etc/keytalk/keystore\"" ${server_xml_file} ; then
        echo "Add KeyTalk SSL connector to TomCat"
        # add "connector" section above the indicated section
        sed -i '/A "Connector" using the shared thread pool/i \\n    <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol" \n        maxThreads="150" SSLEnabled="true" scheme="https" secure="true" \n        clientAuth="false" sslProtocol="TLS" \n        keystoreFile="/etc/keytalk/keystore" keystorePass="changeit" />\n' ${server_xml_file}
    fi

    # Create default page if necessary
    if [ ! -d /var/lib/tomcat/webapps/ROOT ]; then
        mkdir -p /var/lib/tomcat/webapps/ROOT
        cp -f tomcat/index.html /var/lib/tomcat/webapps/ROOT/
    fi

    if ! service ${tomcat_dir} restart ; then
        echo "ERROR restarting Tomcat."
        echo "Check recent tomcat error log in /var/log/${tomcat_dir}/"
        return 1
    fi
}