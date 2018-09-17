include ../mk/keytalk.common.mk

all: release

ifdef RESEPT_LINUX_CLIENT

GENERATED_DOCUMENTS=KeyTalk_LinuxClient_for_Apache.pdf KeyTalk_LinuxClient_for_Apache_remote_deployment.pdf KeyTalk_LinuxClient_for_Tomcat.pdf KeyTalk_LinuxClient_for_Tomcat_remote_deployment.pdf

release debug: $(GENERATED_DOCUMENTS)

clean:
	rm -f $(GENERATED_DOCUMENTS)

%.pdf: %.txt
	@echo Generating $@...
	@pandoc --css markdown7.css --from markdown --to html --standalone $< > $<.html
	@xvfb-run --server-args="-screen 0, 1024x768x24" wkhtmltopdf $<.html $@ > /dev/null
	@rm -f ./$<.html

endif

ifdef RESEPT_SERVER

# use bash i.o. default sh shell to make use of some nifty features which are not present in sh on some platforms
SHELL=/bin/bash

VERSION := $(shell cut -d'-' -f 2 ../Server/version)
DOCS_PACKAGE=../Server/Projects/Export/keytalk.svr.doc-$(VERSION).tar

check_generated_pdf: KeyTalkApi.pdf KeyTalkApi.docx KeyTalkServerAdminManualNotes.pdf KeyTalkServerAdminManualNotes.docx
	@if [ KeyTalkApi.pdf -ot KeyTalkApi.docx ]; then\
		echo "KeyTalkApi.pdf is older than KeyTalkApi.docx"; \
		exit 1;\
	fi
	@if [ KeyTalkServerAdminManualNotes.pdf -ot KeyTalkServerAdminManualNotes.docx ]; then\
		echo "KeyTalkServerAdminManualNotes.pdf is older than KeyTalkServerAdminManualNotes.docx"; \
		exit 1;\
	fi

release debug: check_generated_pdf
	@echo Generating server documentation...
	@tar -cf $(DOCS_PACKAGE) KeyTalkServerAdminManualNotes.pdf db_cacert-selfsigned.pem KeyTalkApi.pdf KeyTalkApi.docx
	@tar -uf $(DOCS_PACKAGE) -C ../Server/Projects/config/ create-shared-db-tables.sql create-mod-mysql-db-tables.sql

clean:
	@rm -f $(DOCS_PACKAGE)

endif

install:
