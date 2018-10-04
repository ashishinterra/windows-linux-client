# KeyTalk clients


## Introduction

Windows and Linux clients for [KeyTalk](https://www.keytalk.com/)

  - KeyTalk Windows client support Windows 7, Windows 8 and Windows 10.
  - KeyTalk Linux client supports RHEL 6/7 x64, CentOS 6/7 x64, Debian 8/9 x64, Ubuntu 16.04/18.04 x64.

## Building KeyTalk Linux Client


### Setup base system
Install Linux distribution (minimal installation) matching the system the KeyTalk Linux client is supposed to run on.
- 15 GB disk space
- 512 MB RAM


### _Setting up development environment for Debian 8/9, Ubuntu 16.04/18.04 Client_

Become root

    $ sudo -i


Set hostname

    # echo ktclient-dev > /etc/hostname
    # hostname -F /etc/hostname
    # grep -q ktclient-dev /etc/hosts || echo "127.0.1.1    ktclient-dev" >> /etc/hosts

Install packages

    Make sure 'universe' repository is listed in /etc/apt/sources.list, add it if not

    # apt-get update
    # apt -y install gdb vim git curl apache2 build-essential expect libexpat1-dev libssl-dev pandoc xvfb xfonts-75dpi wkhtmltopdf tmux zlib1g-dev libxml2-dev libxslt1-dev python-dev python-pip pylint python3 hdparm zip clang lsb-release
    # pip2 install lxml pyopenssl
    # a2enmod ssl
    # curl -s https://bootstrap.pypa.io/get-pip.py | python3


Optional. Ubuntu 16/18 and Debain 9: install ccache to speedup C/C++ builds

    # apt install -y ccache
    # echo 'export PATH=/usr/lib/ccache:$PATH' >> ~/.bashrc
    # export PATH=/usr/lib/ccache:$PATH
    # which clang++


### _Setting up development environment for RHEL 7/CentOS 7 Client_

Become root

    $ sudo -i


Set hostname

    # echo ktclient-dev > /etc/hostname
    # hostname -F /etc/hostname
    # grep -q ktclient-dev /etc/hosts || echo "127.0.1.1    ktclient-dev" >> /etc/hosts


Update the system:

    # yum -y update


Install Development Tools:

    # yum -y groupinstall "Development Tools"


**RHEL 7** only: enable optional and extras repo through subscription manager :

    # subscription-manager repos --enable rhel-7-server-optional-rpms
    # subscription-manager repos --enable rhel-7-server-extras-rpms


Install epel and ius packages:

    # rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
    # yum -y install https://centos7.iuscommunity.org/ius-release.rpm


Install packages:

    # yum -y update
    # yum install -y mesa-libGL-devel gcc gcc-c++ make openssl-devel expat-devel xorg-x11-server-Xvfb xorg-x11-fonts-75dpi libxml2-devel libxslt-devel python-devel python35u python35u-libs python35u-devel python35u-pip redhat-lsb-core gdb vim git ntp ntpdate curl httpd expect automake autoconf libtool pandoc zlib-devel tmux hdparm zip clang mod_ssl python-pip wget wkhtmltopdf pylint bind-utils nc
    # pip install lxml pyopenssl



### _Setting up development environment for RHEL 6 /CentOS 6 Client_

Become root

    $ sudo -i


Set hostname

    # echo ktclient-dev > /etc/hostname
    # hostname -F /etc/hostname
    # grep -q ktclient-dev /etc/hosts || echo "127.0.1.1    ktclient-dev" >> /etc/hosts


Update the system:

    # yum -y update


Install Development Tools:

    # yum -y groupinstall "Development Tools"


**RHEL 6** only: enable optional and extras repo through subscription manager for  :

    # subscription-manager repos --enable rhel-6-server-optional-rpms
    # subscription-manager repos --enable rhel-6-server-extras-rpms



Install epel and ius packages:

    # rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm
    # yum -y install https://centos6.iuscommunity.org/ius-release.rpm


Install packages:

    # yum -y update
    # yum install -y mesa-libGL-devel gcc gcc-c++ make openssl-devel expat-devel xorg-x11-server-Xvfb xorg-x11-fonts-75dpi libxml2-devel libxslt-devel python-devel python35u python35u-libs python35u-devel python35u-pip redhat-lsb-core gdb vim git ntp ntpdate curl httpd expect automake autoconf libtool pandoc zlib-devel tmux hdparm zip clang mod_ssl python-pip wget bind-utils nc
    # pip install lxml pyopenssl

    # wget https://downloads.wkhtmltopdf.org/0.12/0.12.4/wkhtmltox-0.12.4_linux-generic-amd64.tar.xz
    # tar xvf wkhtmltox-0.12.4_linux-generic-amd64.tar.xz
    # mv wkhtmltox/bin/wkhtmlto* /usr/bin
    # pip install pylint


**RHEL 6** only: install devtoolset

    # yum -y install devtoolset-2

**CentsOS 6** only: install devtoolset

    # wget http://people.centos.org/tru/devtools-2/devtools-2.repo -O /etc/yum.repos.d/devtools-2.repo
    # yum -y install devtoolset-2-gcc devtoolset-2-binutils
    # yum -y install devtoolset-2-gcc-c++ devtoolset-2-gcc-gfortran


Enable gcc/g++ version 4.8.x and to update CA Trust

**(Note: gcc/g++ version should always be 4.8.x before installing from keytalk source code)**

    # scl enable devtoolset-2 bash
    # update-ca-trust enable



### Build and install KeyTalk client

Clone

    # git clone https://github.com/KeyTalk/windows-linux-client.git /keytalk
    # touch /resept_linux_client_dev

Install

    # cd /keytalk/Software/Client/Projects/
    # make clean && make && make install



 Quick Test

    # /usr/local/bin/keytalk/ktconfig --rccd-path /keytalk/Software/Client/TestProjects/Common/RCCDs/v2/githubtest.rccd
    # /usr/local/bin/keytalk/ktclient --provider KeyTalk_GitHub_TEST --service test --user test --password test

The certificate will be placed under `~/.keytalk/keystore/`

For more extensive testing make sure the KeyTalk test server demo.keytalkdemo.com is resolvable e.g. (change IP to your network):

     # if grep -q "demo\.keytalkdemo\.com" /etc/hosts ; then sed -i -r 's/^.*\s*demo\.keytalkdemo\.com/192.168.1.123 demo.keytalkdemo.com/' /etc/hosts;  else echo "192.168.1.123 demo.keytalkdemo.com" >> /etc/hosts ; fi

## Building KeyTalk Windows client

### Setup the system

Install Windows 7 x86 SP1 including all the latest updates

Install MSVS 2013 Professional with Update 4

Install Qt-5.5 community edition from the [Qt download page](http://www.qt.io/download-open-source)

 - example [download link](http://ftp1.nluug.nl/languages/qt/archive/qt/5.5/5.5.1/qt-opensource-windows-x86-msvc2013-5.5.1.exe)
 - installing community edition suffices since Qt usage in KeyTalk conforms LGPL terms

Add environment variable QTDIR pointing to the QT installation directory (e.g. `D:\Qt\5.5\msvc2013`).


### Install the client

#### Clone

Clone KeyTalk client from https://github.com/KeyTalk/windows-linux-client.git

#### Install

Open `Software\Client\Resept\Client.sln` in MS Visual Studio and `Rebuild all` for `ReleaseNoSign` target

The executables along with the msi installer will be placed under `Software\Client\Projects\Export`

Install the resulted msi.

#### Test

Start `KeyTalk Configuration Manager` from Start Menu and customize with RCCD from `Software\Client\TestProjects\Common\RCCDs\v2\githubtest.rccd`

Start `KeyTalk 5.2` from Start Menu and login with user `test` and password `test`

### Signing

Building KeyTalk client for `KeyTalkClientNotSigned` produces executables and msi that are not signed. This is ok for local testing, however if you plan to distribute KeyTalk Windows client you should sign your binaries with a trusted codesigning certificate. Follow the steps to sign KeyTalk client:
  1. Acquire code signing certificate e.g. from GlobalSign or other certificate issuer.
  2. Store your code signing pfx under `Software\CertKeys\CodeSigning\CodesigningWindows.pfx` and the pfx password to `Software\CertKeys\CodeSigning\CodesigningWindows.pfx.passwd`
  3. Rebuild the client for `Release` target

## Contributing
  1. Make sure your changes are rebased on origin/master
  2. Make sure your source code is properly formatted by running 'formatcxx.py --fix' and 'formatpython.py --fix'
  3. Commit and create a pull-request
