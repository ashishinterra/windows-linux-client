CLIENT_VERSION:=$(shell cut -d '=' -f 2 ../../version)
PACKAGE=../Export/KeyTalkClient-$(CLIENT_VERSION).python.demo.tgz
DEPENDENCIES=common_config.py pcacert.pem commcacert.pem KeyTalkApi.pdf

.PHONY : release debug clean install

all: release

release debug: $(PACKAGE)

$(PACKAGE): $(DEPENDENCIES) requirements.txt keytalk-client.py
	tar -czf $@ $?

common_config.py: ../../../Common/common_config.py
	cp $? ./

pcacert.pem commcacert.pem: ../../../CertKeys/CommunicationAndSigning/pcacert.pem ../../../CertKeys/CommunicationAndSigning/commcacert.pem
	cp $? ./

KeyTalkApi.pdf: ../../../Documentation/KeyTalkApi.pdf
	cp $? ./

clean:
	rm -f ${DEPENDENCIES} ${PACKAGE}

install: requirements.txt
	pip3.5 install --upgrade --requirement requirements.txt
