wpa_supplicant
------------------------

The directory contains wpa_supplicant-2.0 built under Linux Debian 8 with the following modifications:
- radeapclient tool has been added based on eapol_test tool
- radeapclient defines specific exit codes (see radeapclient.h) useful for integrating this command-line tool to other systems (e.g. KeyTalk mod_radius)


Build

    VERSION=2.0
    wget https://w1.fi/releases/wpa_supplicant-${VERSION}.tar.gz
    tar -xzf wpa_supplicant-${VERSION}.tar.gz
    cd wpa_supplicant-${VERSION}/
    cat /keytalk/Software/Import/wpa_supplicant-$VERSION/patches/keytalk.patch | patch -p0
    cd wpa_supplicant/
    make radeapclient

Test (make sure RADIUS is setup)

    ./radeapclient -n -c radeapclient.conf -s testing123

Deploy

    OSSPEC=$(lsb_release --id --short | tr "[:upper:]" "[:lower:]")-$(lsb_release --release --short | egrep -o [0-9]+ | sed -n '1p')-$(uname -m | cut -d '-' -f 1)
    BINDIR=/keytalk/Software/Import/wpa_supplicant-${VERSION}/bin/${OSSPEC}/
    INCDIR=/keytalk/Software/Import/wpa_supplicant-${VERSION}/include
    CONFDIR=/keytalk/Software/Import/wpa_supplicant-${VERSION}/conf
    rm -rf ${BINDIR} ${INCDIR} ${CONFDIR}
    mkdir -p ${BINDIR} ${INCDIR} ${CONFDIR}
    cp -f radeapclient ${BINDIR}
    cp -f radeapclient.h ${INCDIR}
    cp -f radeapclient*.conf ${CONFDIR}

