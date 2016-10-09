AUTOMAKE_OPTIONS = no-dependencies
SUBDIRS=src

PACKAGE_NAME		= @PACKAGE_NAME@

etc_prefix		= $(DESTDIR)${exec_prefix}/etc
INSTALL			= ${install_sh_PROGRAM}
CHMOD 		= @CHMOD@
PWD			= @PWD@

my_cflags  =@my_cflags@
my_ldflags  =@my_ldflags@
my_ldadd  =@my_ldadd@

INSTALL_BUILDER = @INSTALL_BUILDER@


AUX_DIST = \
	$(ac_aux_dir)/acinclude.m4	\
	$(ac_aux_dir)/compile		\
	$(ac_aux_dir)/config.guess	\
	$(ac_aux_dir)/config.sub	\
	$(ac_aux_dir)/depcomp		\
	$(ac_aux_dir)/install-sh	\
	$(ac_aux_dir)/missing		
#$(ac_aux_dir)/mkinstalldirs


EXTRA_SCRIPTS = \
	contrib/autogen.sh	\
	contrib/build-rpm.sh	\
	contrib/ocsp-client.spec	\
	contrib/ocsp-client.spec.orig	\
	sh/ocsp-client

EXTRA_XML = \
	config/ocsp-client.xml

EXTRA_CERT = \
	config/cacer/* \
	config/clientcer/*

EXTRA_DIST = $(AUX_DIST) $(EXTRA_XML) $(EXTRA_SCRIPTS) $(EXTRA_CERT)

MAKEFILE=Makefile
TODAY=`date +%Y%m%d`

install-data-local:
	@$(NORMAL_INSTALL)	
	@$(mkinstalldirs) $(DESTDIR)$(exec_prefix)/var	
	@$(mkinstalldirs) $(DESTDIR)$(exec_prefix)/var/run	
	@$(mkinstalldirs) $(etc_prefix)/init.d	
	@$(mkinstalldirs) $(etc_prefix)/ocsp-client	
	@$(mkinstalldirs) $(etc_prefix)/ocsp-client/cacer
	@$(mkinstalldirs) $(etc_prefix)/ocsp-client/clientcer

	@ $(INSTALL_DATA) sh/ocsp-client $(etc_prefix)/init.d/; \
	$(CHMOD) +x $(etc_prefix)/init.d/ocsp-client ;	

	@ $(INSTALL_DATA) config/ocsp-client.xml $(etc_prefix)/ocsp-client/;
	@ $(INSTALL_DATA) config/cacer/* $(etc_prefix)/ocsp-client/cacer/;
	@ $(INSTALL_DATA) config/clientcer/* $(etc_prefix)/ocsp-client/clientcer/;

rpm:
	@echo
	@echo -n "Cleaning up old RPMs ... "
	@for i in $(PACKAGE_NAME)*.rpm ; do \
                rm -f $$i ; \
        done
	@echo "Done."
	@echo -n "Creating spec file ... " ; \
	filename="ocsp-client.spec" ; \
	[ -z "$$minor" ] && minor="1" ; \
	if [ -e "contrib/$$filename.orig" ] ; then \
		echo -n "($$filename.orig) --> "; \
		cat "contrib/$$filename.orig" | \
			sed -e "s/@RPM_VERSION@/$(PKG_VER)/g" | \
			sed -e "s/\@mybits\@/@mybits@/g" | \
			sed -e "s/@PKGNAME@/$(PACKAGE_NAME)/g" | \
			sed -e "s|@BUILDROOT@|/var/tmp/$(PACKAGE_NAME)-%{ver}-root|g" > \
			"contrib/ocsp-client.spec" ; \
		echo "($$filename)"; \
	else \
		echo "contrib/$$filename.orig ... not found" ; \
		exit 1 ; \
	fi ; \
	echo "Building source package... " ; \
	$(MAKE) -f $(MAKEFILE) dist ; \
	echo "Building RPM package(s)... " ; \
	rm -rf /usr/src/redhat/BUILD/$(PACKAGE_NAME)* \
		$(HOME)/rpmbuild/BUILD/$(PACKAGE_NAME)* ; \
	rpmbuild -ta $(PACKAGE_NAME)-$(VERSION).tar.gz ; \
	mv /usr/src/redhat/RPMS/*/$(PACKAGE_NAME)*.rpm . 2>/dev/null || \
	mv $(HOME)/tmp/rpm/RPMS/*/$(PACKAGE_NAME)*.rpm . 2>/dev/null || \
    mv $(HOME)/rpmbuild/RPMS/*/$(PACKAGE_NAME)*.rpm . 2>/dev/null ; \
	mv /usr/src/redhat/SRPMS/$(PACKAGE_NAME)*.src.rpm . 2>/dev/null || \
    mv $(HOME)/tmp/rpm/SRPMS/$(PACKAGE_NAME)*.src.rpm . 2>/dev/null || \
    mv $(HOME)/rpmbuild/SRPMS/$(PACKAGE_NAME)*.src.rpm . 2>/dev/null ; \
	echo "build rpm end"




