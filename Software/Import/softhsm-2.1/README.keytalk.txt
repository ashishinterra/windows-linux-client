Building SoftHsm-2.1 dynamic library for KeyTalk server and HSM proxy (Linux)
---------------------------------------------------------------------

1. Get the library

Notice that we don't retrieve the library from github version because it doesn't include 'configure' script

    wget https://dist.opendnssec.org/source/softhsm-2.1.0.tar.gz
    tar -xzf softhsm-2.1.0.tar.gz
    cd softhsm-2.1.0/

2. Build the library and helper tool

You might need to run 'autoreconf -i' before 'configure'

    LIBS=-lpthread ./configure --with-crypto-backend=openssl --disable-gost
    make clean && make


3. Install

    OS_SPEC=$(lsb_release --id --short | tr "[:upper:]" "[:lower:]")-$(lsb_release --release --short | egrep -o [0-9]+ | sed -n '1p')-$(uname -m | cut -d '-' -f 1)
    rm -rf /keytalk/Software/Import/softhsm-2.1/include/ /keytalk/Software/Import/softhsm-2.1/lib/${OS_SPEC}/ /keytalk/Software/Import/softhsm-2.1/bin/${OS_SPEC}/
    mkdir -p /keytalk/Software/Import/softhsm-2.1/include/ /keytalk/Software/Import/softhsm-2.1/lib/${OS_SPEC}/ /keytalk/Software/Import/softhsm-2.1/bin/${OS_SPEC}/
    cp -f src/lib/common/softhsm2.conf /keytalk/Software/Import/softhsm-2.1/
    cp -f src/lib/cryptoki_compat/pkcs11.h /keytalk/Software/Import/softhsm-2.1/include/
    cp -f src/lib/.libs/libsofthsm2.so /keytalk/Software/Import/softhsm-2.1/lib/${OS_SPEC}/
    cp -f src/bin/util/softhsm2-util /keytalk/Software/Import/softhsm-2.1/bin/${OS_SPEC}/

    sed -i -E 's/^(SOFT_HSM_LIB_VERSION_DIR)\=.+$/\1=softhsm-2.1/' /keytalk/Software/mk/keytalk.common.mk


4. Rebuild and retest KeyTalk

5. Add new files to the version control and commit your changes


Troubleshooting
---------------------

To build build debug version of the library:

    CFLAGS="-g -DDEBUG" CXXFLAGS="-g -DDEBUG" LIBS=-lpthread ./configure --with-crypto-backend=openssl --disable-gost

Enable logging by enabling DEBUG_LOG_STDERR in src/lib/common/log.h

    make clean && make