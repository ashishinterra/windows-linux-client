PRJS=ReseptConsoleClient ReseptConfigManager ReseptConfigTool ReseptPrGenerator ReseptHwsigDump ReseptPythonClient ReseptInstaller/ConfigUpdater ReseptInstaller/linux/bin ReseptInstaller/linux/apache_remote_deployment
MAKE_FLAGS=-s

# use bash i.o. default sh shell to make use of some nifty features which are not present in sh on some platforms
SHELL=/bin/bash

all: release

check_devenv:
	@set -e; \
	if [ `uname` != "Linux" ]; then \
		echo "Linux platform required to build KeyTalk Linux client" 1>&2 ; \
		exit 1; \
	fi; \
	if [[ ! -f /etc/debian_version && ! -f /etc/centos-release && ! -f /etc/redhat-release ]]; then \
		echo "Linux Debian/RedHat/CentOS platform required to build KeyTalk Linux client" 1>&2 ; \
		exit 1; \
	fi;

release debug: check_devenv
	@set -e;			\
	for dir in $(PRJS); do		\
		echo " --- Building $$dir";	\
		make -C $$dir $(MAKE_FLAGS) $@;		\
	done;

clean: check_devenv
	@set -e;			\
	for dir in $(PRJS); do		\
		echo "--- Cleaning $$dir";	\
		make -C $$dir $(MAKE_FLAGS) clean;		\
	done;
	@rm -rf ./Export/*

install: check_devenv
	@set -e;			\
	for dir in $(PRJS); do \
		echo "--- Installing $$dir";	\
		make -C $$dir $(MAKE_FLAGS) install;		\
	done;
