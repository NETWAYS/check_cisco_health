# spec file for check_cisco_health

%define lname	check_cisco_health

Summary:        Check various nic port parameters
License:        GPL-2+
Group:          System/Monitoring
Name:           nagios-plugins-cisco_health
Version:        1.0
Url:            https://github.com/NETWAYS/check_cisco_health
Source:         %{lname}-%{version}.tar.gz
BuildRequires:	net-snmp-devel
Requires:	net-snmp

%if 0%{?suse}
Release:	1
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
%endif

%if 0%{?fedora} || 0%{?rhel} || 0%{?centos}
Release:        1%{?dist}
Requires:       nagios-common
%endif

%description
This plugin uses the bulk-get to get the enviroment
state of cisco network equipment. 

%prep
%setup -q -n %{lname}-%{version}

%build
%{__make}

%install
%{__mkdir_p} %{buildroot}%{_libdir}/nagios/plugins
%{__install} -m755 %{lname} %{buildroot}%{_libdir}/nagios/plugins/check_cisco_health

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-,root,root)
%if 0%{?suse}
%dir %{_libdir}/nagios
%dir %{_libdir}/nagios/plugins
%endif
%{_libdir}/nagios/plugins/*

%changelog
* Mon May 17 2013 Lennart Betz <lennart.betz@netways.de> 1.0
- initial setup
