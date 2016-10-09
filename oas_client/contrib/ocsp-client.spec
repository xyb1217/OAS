# OpenCA RPM File
# (c) 2006-2009 by Massimiliano Pala and OpenCA Team
# OpenCA Licensed Software

# %define __find_requires %{nil}
#%define debug_package %{nil}
#%define __os_install_post %{nil}

#%define _unpackaged_files_terminate_build 0
#%define _missing_doc_files_terminate_build 0

# Basic Definitions
%define ocsp_client_usr nobody
%define ocsp_client_grp nobody

%define is_mandrake %(test -e /etc/mandrake-release && echo 1 || echo 0)
%define is_suse %(test -e /etc/SuSE-release && echo 1 || echo 0)
%define is_fedora %(test -e /etc/fedora-release && echo 1 || echo 0)

%define dist redhat
%define disttag rh

%if %is_mandrake
%define dist mandrake
%define disttag mdk
%endif
%if %is_suse
%define dist suse
%define disttag suse
%endif
%if %is_fedora
%define dist fedora
%define disttag rhfc
%endif

%define distver %(release="`rpm -q --queryformat='%{VERSION}' %{dist}-release 2> /dev/null | tr . : | sed s/://g`" ; if test $? != 0 ; then release="" ; fi ; echo "$release")
%define packer %(finger -lp `echo "$USER"` | head -n 1 | cut -d ' ' -f 2)

%define ver      	1.0.2
%define RELEASE 	1
%define rel     	%{?CUSTOM_RELEASE} %{!?CUSTOM_RELEASE:%RELEASE}
%define prefix   	/usr/local
%define mand		/usr/man

Summary: OpenCA OCSP Client Daemon
Name: ocsp-client
Version: %ver
Release: %RELEASE
License: OpenCA License (BSD Style)
Group: Network/Daemons
Source: ocsp-client-%{ver}.tar.gz
Packager:  rpmbuild
Vendor: OpenCA Labs
BuildRoot: /var/tmp/ocsp-client-%{ver}-root
URL: http://www.openca.org/projects/ocspd
Prefix: %prefix

%description
The ocsp-client is a ocsp client.


%prep
%setup

%ifarch alpha
  ARCH_FLAGS="--host=alpha-redhat-linux"
%endif

if [ ! -f configure ]; then
  CFLAGS="$RPM_OPT_FLAGS" ./autogen.sh $ARCH_FLAGS --prefix=%{prefix} --mandir={mand} 
else
  CFLAGS="$RPM_OPT_FLAGS" ./configure $ARCH_FLAGS --prefix=%{prefix} --mandir=%{mand}
fi

%build

if [ "$SMP" != "" ]; then
  (make "MAKE=make -k -j $SMP"; exit 0)
  make
else
  make
fi

%install
[ -n "$RPM_BUILD_ROOT" -a "$RPM_BUILD_ROOT" != / ] && rm -rf $RPM_BUILD_ROOT

# make prefix=$RPM_BUILD_ROOT%{prefix} mandir=$RPM_BUILD_ROOT%{mand} install
make DESTDIR="$RPM_BUILD_ROOT" prefix="%{prefix}" mandir="$RPM_BUILD_ROOT%{share}" install

%clean
[ -n "$RPM_BUILD_ROOT" -a "$RPM_BUILD_ROOT" != / ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-, root, root)

%doc AUTHORS COPYING ChangeLog NEWS README

#%{prefix}/bin/*
%{prefix}/sbin/*
#%{prefix}/share/*
%{prefix}/etc/init.d/*
%{prefix}/etc/ocsp-client/*
%{prefix}/var/*
#%{prefix}/lib
# %{mand}/*

%post

%postun


%changelog
* Sat Aug 29 2009 Massimiliano Pala <madwolf@openca.org>
-Added support for LibPKI

* Sun Dec  3 2006 Massimiliano Pala <madwolf@openca.org>
-Added exit message on stderr when server aborts during startup (useful
for interactive startup of the server)
-Added support for HTTP/1.1 "Host: <addr>" header when making HTTP
requests in order to get data via HTTP protocol

* Sun Oct 15 2006 Massimiliano Pala <madwolf@openca.org>
-Fixed HTTP HEADERS parsing problem
-Tested behind an Apache Proxy
-Added '-debug' startup option to output the HTTP head and additional
informations to be pushed to stderr

* Fri Oct 13 2006 Massimiliano Pala <madwolf@openca.org>
-Completely changed the codebase in order to use threads instead
of fork().
-Fixed compilation under OpenSolaris (SunOS 5.11)
-Added chroot() capabilities
-Added options to set the number of threads to be pre-spawned
-Fixed Socket creation under Solaris (Accept)
-Moved from BIO_* interface to pure socket implementation for
better Network options management

* Tue Jul 18 2006 Massimiliano Pala <madwolf@openca.org>
-Removed required index file option in the configuration file (was not
used)

* Mon Apr 24 2006 Massimiliano Pala <madwolf@openca.org>
-Fixed invalidity date problem (no more empty ext added to responses)
-Added log reporting of returned status about a response when the
verbose switch is used (before it was enabled only in DEBUG mode)

* Mon Dec 19 2005 Massimiliano Pala <madwolf@openca.org>
-Added chroot facility to enhance server security

* Thu Nov  3 2005 Massimiliano Pala <madwolf@openca.org>
-Fixed compile against OpenSSL 0.9.8a
-Fixed HTTP downloading routines for CRLs and CA certs
-Fixed Solaris Port for Signal Handling on CRLs check and reloading

* Thu Oct  6 2005 Massimiliano Pala <madwolf@openca.org>
-Fixed variables init (for Solaris) and code cleanup

* Thu Apr 28 2005 Massimiliano Pala <madwolf@openca.org>
-Fixed RPM installation of man pages

* Wed Apr 27 2005 Massimiliano Pala <madwolf@openca.org>
-Fixed RPM creation on Fedora Distros

* Tue Apr 19 2005 Massimiliano Pala <madwolf@openca.org>
-Fixed child re-spawning when HSM is active
-Added support for CA/CRL downloading via HTTP

* Fri Jan 28 2005 Massimiliano Pala <madwolf@openca.org>
-Fixed SIGHUP problem when auto_crl_reload was enabled
-Fixed Solaris include for flock usage instead of semaphores
-Added --enable-flock and --enable-semaphores in configure script

* Tue Jan 18 2005 Massimiliano Pala <madwolf@openca.org>
- Fixed bug for nextUpdate and lastUpdate fields setting when reloading
  CRLs.
- Added CA certificate loading from LDAP.
- Added multiple CA certificate from the same cACertificate entry in LDAP.
- Fixed Solaris putenv issues in configure.c
- Added OS architecture specific targes in makefiles

* Wed May 19 2004 Massimiliano Pala <madwolf@openca.org>
- First support for new data structure for CRL lookup and multi CAs
  support (not working now)
- Fixed configure.in for correct generation of config.h
- Fixed configure.in for openldap ld options (for non-standard directories)

* Mon May 17 2004 Massimiliano Pala <madwolf@openca.org>
- Fixed compilation problems on Solaris
- Added support for exclusion of ldap usage (--disable-openldap)
- Added support for openldap directory specification
- Fixed signal handling and correct children death
- Added pre-spawning of processes()

* Thu May 13 2004 Massimiliano Pala <madwolf@openca.org>
- Fixed miscreation of responses when certificate is revoked
- Fixed crl loading checking (segmentation fault on loading fixed)

* Fri Jan 17 2003 Massimiliano Pala <madwolf@openca.org>
- Correclty lookup using loaded CRL
- Added extensions management from CRL to OCSP response

* Mon Jan 13 2003 Massimiliano Pala <madwolf@openca.org>
- Updated the sample (contrib/) configuration file
- Added CRL retrivial from LDAP server
- Added LDAP support (needs OpenLDAP libraries)
- Added CRL retrivial from file

* Wed Oct 16 2002 Massimiliano Pala <madwolf@openca.org>
- Fixed daemon description
- Fixed requirements (for ENGINE support)
- Added multi child spawning (max_childs_num)
- Fixed zombi child presence

* Mon Feb 25 2002 Massimiliano Pala <madwolf@openca.org>
  - Fixed response generation

* Thu Feb 20 2001 Massimiliano Pala <madwolf@openca.org>
- First RPM spec file
