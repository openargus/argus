%define ver 3.0
%if %{?rel:0}%{!?rel:1}
%define rel 8.3
%endif
%if %{?srcext:0}%{!?srcext:1}
%define srcext .gz
%endif
Summary: ARGUS Software
Name: argus
Version: %ver
Release: %{rel}%{dist}
License: see COPYING file
Group: Applications/Internet
Source: %{name}-%{version}.%{rel}.tar%{srcext}
URL: http://qosient.com/argus
Buildroot: %{_tmppath}/%{name}-%{version}-root
BuildRequires: libpcap-devel
BuildRequires: cyrus-sasl-devel
BuildRequires: zlib-devel
Requires: wget
Requires: cyrus-sasl

%description
The ARGUS (Audit Record Generation And Utilization System) is an data 
network transaction auditing system.  The data generated by argus can be used
for a wide range of tasks such as network operations, security and performance
management.

Copyright: (c) 2000-2015 QoSient, LLC

%define argusdir	/usr
%define argusman	/usr/share/man
%define argusdocs	/usr/share/doc/argus

%define argusbin	%{argusdir}/bin
%define argussbin	%{argusdir}/sbin

%prep
%setup -n %{name}-%{ver}.%{rel}
%build
./configure --prefix=%{argusdir} --with-sasl
make EXTRA_CFLAGS="-ggdb"

%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR="$RPM_BUILD_ROOT" install

install -D -m 0600 pkg/argus.conf $RPM_BUILD_ROOT/etc/argus.conf
install -D -m 0644 pkg/rhel/sysconfig/argus $RPM_BUILD_ROOT/etc/sysconfig/argus
install -D -m 0755 pkg/rhel/init.d/argus $RPM_BUILD_ROOT/etc/rc.d/init.d/argus
install -D -m 0755 support/Archive/argusarchive $RPM_BUILD_ROOT/%{argusbin}/argusarchive
install -d -m 0755 $RPM_BUILD_ROOT/%{argusdocs}/support
cp -av support $RPM_BUILD_ROOT/%{argusdocs}/

%post
/sbin/chkconfig --add argus
service argus start >/dev/null 2>&1

%preun
if [ "$1" = 0 ] ; then
  service argus stop >/dev/null 2>&1
  /sbin/chkconfig --del argus
fi

%postun
if [ "$1" -ge "1" ]; then
  service argus condrestart >/dev/null 2>&1
fi

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{argussbin}/argus
%{argusbin}/argus-extip
%{argusbin}/argus-lsof
%{argusbin}/argus-snmp
%{argusbin}/argus-vmstat
%{argusbin}/argusbug
%{argusbin}/argusarchive

%doc %{argusdocs}
%{argusman}/man5/argus.conf.5.gz
%{argusman}/man8/argus.8.gz

/etc/rc.d/init.d/argus

%config /etc/argus.conf
%config /etc/sysconfig/argus
