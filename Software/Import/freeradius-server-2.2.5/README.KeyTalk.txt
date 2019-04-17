freeradius server 2.2.5
------------------------

The directory contains freeradius-2.2.5 built under Linux Ubuntu-16.04 x64 with the following modifications:
- added support for EAP-AKA via eap-sim-aka/eap-sim-aka (taken from https://code.google.com/p/seek-for-android/wiki/EapSimAka) front-end modules and sim-files as backend module
- enabled and stubbed securid module


Build instructions
--------------------

    wget https://github.com/FreeRADIUS/freeradius-server/archive/release_2_2_5.tar.gz
    tar -xzf release_2_2_5.tar.gz
    cd freeradius-server-release_2_2_5
    VERSION=2.2.5

Apply patches found in this directory for EAP-AKA and SIM modules and for SecurID

    cat /keytalk/Software/Import/freeradius-server-$VERSION/patches/patch-* | patch -p0

Build

     ./configure
    make

Deploy

    OSSPEC=$(lsb_release --id --short | tr "[:upper:]" "[:lower:]")-$(lsb_release --release --short | egrep -o [0-9]+ | sed -n '1p')-$(uname -m | cut -d '-' -f 1)
    BINDIR=/keytalk/Software/Import/freeradius-server-$VERSION/bin/$OSSPEC/
    LIBDIR=/keytalk/Software/Import/freeradius-server-$VERSION/lib/$OSSPEC/
    rm -rf ${BINDIR} ${LIBDIR}
    mkdir -p ${BINDIR} ${LIBDIR}
    cp src/main/.libs/radiusd ${BINDIR}/freeradius
    patchelf --set-rpath '/usr/lib/freeradius' ${BINDIR}/freeradius
    cp src/modules/lib/.libs/*-${VERSION}.so ${LIBDIR}
    for lib in ${LIBDIR}/*-${VERSION}.so ; do patchelf --set-rpath '/usr/lib/freeradius' ${lib}; done
    cp src/lib/.libs/libfreeradius-radius-020205.so ${LIBDIR}
    cp libltdl/.libs/libltdl.so.3.1.4 ${LIBDIR}/libltdl.so.3
