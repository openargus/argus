%define ver 5.0
%if %{?rel:0}%{!?rel:1}
%define rel 3.0
%endif
%if %{?srcext:0}%{!?srcext:1}
%define srcext .gz
%endif
Summary: Argus Pro (Gargoyle) Software
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
Gargoyle is codename for the commerical release of Argus (Audit Record Generation And Utilization System),
which is a data network transaction auditing tool.  The data generated by gargoyle can be used
for a wide range of tasks such as network operations, security and performance management.

Copyright: (c) 2000-2020 QoSient, LLC

%define argusdir	/usr
%define argusman	/usr/share/man
%define argusdocs	/usr/share/doc/argus

%define argusbin	%{argusdir}/bin
%define argussbin	%{argusdir}/sbin

%prep
%setup -q -n %{name}-%{ver}.%{rel}
%build
./configure --prefix=%{argusdir} --with-sasl
make EXTRA_CFLAGS="-ggdb"

%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR="$RPM_BUILD_ROOT" install

install -D -m 0600 pkg/argus.conf $RPM_BUILD_ROOT/etc/argus.conf
install -D -m 0644 pkg/rhel/sysconfig/argus $RPM_BUILD_ROOT/etc/sysconfig/argus
install -D -m 0644 pkg/rhel/systemd/argus.server.service $RPM_BUILD_ROOT%{_unitdir}/argus.server.service
install -D -m 0644 pkg/rhel/systemd/argus.workstation.service $RPM_BUILD_ROOT%{_unitdir}/argus.workstation.service
install -D -m 0700 pkg/rhel/systemd/argus-setup $RPM_BUILD_ROOT/%{argussbin}/argus-setup
install -D -m 0644 pkg/rhel/sasl2/argus.conf $RPM_BUILD_ROOT/etc/sasl2/argus.conf
install -D -m 0755 support/Archive/argusarchive $RPM_BUILD_ROOT/%{argusbin}/argusarchive
install -d -m 0755 $RPM_BUILD_ROOT/%{argusdocs}/support
cp -av support $RPM_BUILD_ROOT/%{argusdocs}/
install -d -m 0755 $RPM_BUILD_ROOT/etc/pam.d

%post
ln -sf /etc/pam.d/system-auth /etc/pam.d/argus

%preun
if [ "$1" = 0 ] ; then
  rm -f /etc/pam.d/argus
fi


%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{argussbin}/argus
%{argusbin}/argus-extip
%{argusbin}/argus-lsof
%{argusbin}/argus-netstat
%{argusbin}/argus-snmp
%{argusbin}/argus-stumbler
%{argusbin}/argus-vmstat
%{argusbin}/argusbug
%{argusbin}/argusarchive

%doc %{argusdocs}
%{argusman}/man5/argus.conf.5.gz
%{argusman}/man8/argus.8.gz


%config /etc/argus.conf
%config /etc/sysconfig/argus
%config /etc/sasl2/argus.conf
%ghost %config(noreplace) /etc/pam.d/argus



%package systemd-server
Summary: ArgusPro Server Systemd support files
Group: Applications/Internet
Requires: argus >= %{version}-%{rel}%{dist}.2
Conflicts: argus-systemd-workstation
Conflicts: argus < 5.0-3.0.el7.2
BuildArch: noarch

%description systemd-server
Service description and supporting files for QoSient servers

%files systemd-server
%attr(644,root,root) %{_unitdir}/argus.server.service
%{argussbin}/argus-setup
%ghost %{_unitdir}/argus.service

%post systemd-server
ln -f %{_unitdir}/argus.server.service %{_unitdir}/argus.service

%preun systemd-server
if [ "$1" = 0 ] ; then
  systemctl stop argus
  rm -f %{_unitdir}/argus.service
fi

%postun systemd-server
if [ "$1" -ge "1" ]; then
  service argus condrestart >/dev/null 2>&1
fi


%package systemd-workstation
Summary: ArgusPro Workstation Systemd support files
Group: Applications/Internet
Requires: argus >= %{version}-%{rel}%{dist}.2
Conflicts: argus-systemd-server
Conflicts: argus < 5.0-3.0.el7.2
BuildArch: noarch

%description systemd-workstation
Service description and supporting files for QoSient servers

%files systemd-workstation
%attr(644,root,root) %{_unitdir}/argus.workstation.service
%ghost %{_unitdir}/argus.service

%post systemd-workstation
ln -f %{_unitdir}/argus.workstation.service %{_unitdir}/argus.service

%preun systemd-workstation
if [ "$1" = 0 ] ; then
  systemctl stop argus
  rm -f %{_unitdir}/argus.service
fi

%postun systemd-workstation
if [ "$1" -ge "1" ]; then
  service argus condrestart >/dev/null 2>&1
fi
