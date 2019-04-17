SOFTHSM_TOKEN_DIR := $(shell grep ^directories.tokendir softhsm2.conf | cut -d ' ' -f 3)
KEYTALK_BIN_DIR=/usr/local/bin/keytalk
KEYTALK_LIB_DIR=/usr/local/lib/keytalk
ifneq ($(wildcard /resept_server_dev),)
INSTALL_SOFTHSM:=1
else ifneq ($(wildcard /resept_hsm_proxy_dev),)
INSTALL_SOFTHSM:=1
endif

all release debug clean:

install:
ifdef INSTALL_SOFTHSM
		echo "Installing HSM to "$(SOFTHSM_TOKEN_DIR) ; \
		rm -rf $(SOFTHSM_TOKEN_DIR) ; \
		mkdir -p $(SOFTHSM_TOKEN_DIR) ; \
		cp -f softhsm2.conf /etc ; \
		mkdir -p $(KEYTALK_LIB_DIR)/ $(KEYTALK_BIN_DIR)/ ; \
		cp -f lib/$(OSSPEC)/libsofthsm2.so $(KEYTALK_LIB_DIR)/hsm.so ; \
		cp -f bin/$(OSSPEC)/softhsm2-util $(KEYTALK_BIN_DIR)/ ; \
		$(KEYTALK_BIN_DIR)/softhsm2-util --init-token --slot 0 --label "KeyTalk Test HSM" --so-pin 1111 --pin 2222 --module $(KEYTALK_LIB_DIR)/hsm.so
endif
