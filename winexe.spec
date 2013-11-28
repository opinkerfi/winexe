# norootforbuild

Summary: winexe
Name: winexe
Version: 1.01
Release: 1
License: GPL3
Group: Administration/Network
Source: %{name}-%{version}.tar.gz
BuildRequires: python-devel autoconf
%if 0%{?suse_version}
BuildRequires: util-linux
%if 0%{?suse_version} == 1110 
BuildRequires: -post-build-checks -rpmlint-Factory
%endif
%else
BuildRequires: which
%endif
BuildRoot: %{_tmppath}/%{name}-%{version}-build

%description
winexe

%prep
%setup -q

%build
cd source4
./autogen.sh
%configure --enable-fhs
%{__make} basics idl bin/winexe

%install
echo %{buildroot}
rm -rf %{buildroot}
%__install -d %{buildroot}/usr/bin
%__install source4/bin/winexe %{buildroot}/usr/bin

%clean
rm -rf %{buildroot}

%files
%defattr(644,root,root,755)
%attr(755,root,root) /usr/bin/winexe

%changelog
* Fri Aug 03 2012 Pall Sigurdsson <palli@opensource.is> 1.00-2.1
- new package built with tito

