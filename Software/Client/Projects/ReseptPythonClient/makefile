CLIENT_VERSION:=$(shell cut -d '=' -f 2 ../../version)
PACKAGE=../Export/KeyTalkClient-$(CLIENT_VERSION).python.demo.tgz
DEPENDENCIES=common_config.py pcacert.pem commcacert.pem KeyTalkProtocols.pdf

.PHONY : release debug clean install

all: release

release debug: $(PACKAGE)

$(PACKAGE): $(DEPENDENCIES) keytalk-client.py
	tar -czf $@ $?

common_config.py:
	cp ../../../Common/$@ ./

pcacert.pem commcacert.pem:
	cp ../../../CertKeys/CommunicationAndSigning/$@ ./

KeyTalkProtocols.pdf:
	cp ../../../Documentation/$@ ./

clean:
	rm -f ${DEPENDENCIES} ${PACKAGE}

install:
