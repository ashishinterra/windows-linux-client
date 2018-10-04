include ../mk/keytalk.common.mk

ifneq ($(wildcard /resept_server_dev),)
  # KeyTalk Server
  PRJS+=ulxmlrpcpp sscep libbcrypt-1.3
  INST_PRJS+=softhsm-2.1 sscep
else ifneq ($(wildcard /resept_hsm_proxy_dev),)
  # KeyTalk HSM Proxy
  PRJS+=ulxmlrpcpp
  INST_PRJS+=softhsm-2.1
endif

MAKE_FLAGS=-s BOOST_INCLUDE_DIR=$(BOOST_INCLUDE_DIR) OPENSSL_INCLUDE_DIR=$(OPENSSL_INCLUDE_DIR) OSSPEC=$(OSSPEC) INSTALL_DIR=/usr/local/bin/keytalk

all release debug:
	@set -e;            \
	for dir in $(PRJS); do      \
		echo "--- Building $$dir";  \
		make -C $$dir $(MAKE_FLAGS);     \
	done;

clean:
	@set -e;            \
	for dir in $(PRJS); do      \
		echo "--- Cleaning $$dir";  \
		make -C $$dir $(MAKE_FLAGS) clean;      \
	done;

install:
	@set -e;            \
	for dir in $(INST_PRJS); do     \
		echo "--- Installing $$dir";    \
		make -C $$dir $(MAKE_FLAGS) install;        \
	done;

