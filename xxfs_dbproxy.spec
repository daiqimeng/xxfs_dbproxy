#
# Simple RPM spec file for xxfs_dbproxy
# written by Lenz Grimmer <lenz@mysql.com>
#
%define prefix   /usr

Summary: A partitioning proxy for the MySQL Client/Server protocol
Name: xxfs_dbproxy
Version: 0.8.7
Release: 0
License: GPL
Group: Applications/Networking
Source: %{name}-%{version}.tar.gz
URL: http://sourceforge.net/xxfs_dbproxy
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: mysql-devel glib2-devel libevent
%if 0%{?suse_version} > 1010
%define with_lua 1
%endif
%if 0%{?with_lua}
BuildRequires:  lua-devel >= 5.1
%endif

%description
xxfs_dbproxy is a derivative of the MySql-Proxy project.  However this project
greatly differs in the respect it is designed to act like a database in itself as opposed to just a proxy.  xxfs_dbproxy allows database designers to partition
data across multiple MySQL databases and allow simple (currently) commands to
be sent to one or more databases and those results to be consolidated.  Instead
of using LUA like MySQL-Proxy we have developed most of the code in 'C' and the
spirit of the project is to make a library that will support many of the 
functions MySQL is attempting to support but with performance in mind. 

%prep
%setup

%build
%configure \
%if 0%{?with_lua}
  --with-lua
%else
  --without-lua
%endif
%{__make}

%install
%makeinstall
# we package them later in the documentation. no reason to have them here
%{__rm} -v %{buildroot}%{_datadir}/*.lua
# we dont need to package the Makefile stuff
%{__rm} -v examples/Makefile*

%clean
%{__rm} -rfv %{buildroot}

%files
%defattr(-,root,root)
%doc AUTHORS COPYING INSTALL NEWS README README.TESTS
%doc examples/
%{_sbindir}/%{name}
%{_datadir}/%{name}/
