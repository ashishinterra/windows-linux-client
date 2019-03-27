include ../mk/keytalk.common.mk

ifneq ($(wildcard /resept_server_dev),)
  # KeyTalk Server
  CMAKE_CONFIG_PROJS=tidy-html5/build/cmake
  PRJS+=ulxmlrpcpp sscep libbcrypt-1.3 libtwiliocpp tidy-html5/build/cmake
  INST_PRJS+=softhsm-2.1 sscep
else ifneq ($(wildcard /resept_hsm_proxy_dev),)
  # KeyTalk HSM Proxy
  CMAKE_CONFIG_PROJS=
  PRJS+=ulxmlrpcpp
  INST_PRJS+=softhsm-2.1
endif

MAKE_FLAGS=-s BOOST_INCLUDE_DIR=$(BOOST_INCLUDE_DIR) OPENSSL_INCLUDE_DIR=$(OPENSSL_INCLUDE_DIR) OSSPEC=$(OSSPEC) INSTALL_DIR=/usr/local/bin/keytalk

all: release

configure_cmake_projects:
	@set -e;            \
	for dir in $(CMAKE_CONFIG_PROJS); do      \
		echo "--- Configuring $$dir";  \
		cd $$dir && cmake ../..;     \
	done;

all release debug: configure_cmake_projects
	@set -e;            \
	for dir in $(PRJS); do      \
		echo "--- Building $$dir";  \
		make -C $$dir $(MAKE_FLAGS);     \
	done;

clean: configure_cmake_projects
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

