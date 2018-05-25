# KeyTalk clients


## Introduction

Windows and Linux clients for [KeyTalk](https://www.keytalk.com/)

  - KeyTalk Windows client support Windows 7, Windows 8 and Windows 10.
  - KeyTalk Linux client supports Debian 8 x64, Debian 9 x64 and Ubuntu 16.04 x64.

## Building KeyTalk Linux Client


We will create two development environments:
  - Debian 8-based for building KeyTalk clients for Debian 8 and Ubuntu 16.04
  - Debian 9-based for building KeyTalk clients for Debian 9

The reason for creating two separate development environments is incompatibility of OpenSSL libraries on Debian 8 and Debian 9 (app linked against OpenSSL-1.0.1 on Debian 8 cannot start on Debian 9 having OpenSSL-1.0.2)


### Setup base system
Install Debian 8 x64 to build for Debian 8/Ubuntu 16.04 or Debian 9 x64 to build for Debian 9.
- 10 GB disk space
- 512 MB RAM

Become root

    $ sudo -i


Set hostname

    # echo ktclient-dev > /etc/hostname
    # hostname -F /etc/hostname
    # grep -q ktclient-dev /etc/hosts || echo "127.0.1.1    ktclient-dev" >> /etc/hosts


Install packages

    # apt-get update
    # apt -y install gdb vim git ntp ntpdate curl apache2 build-essential expect libexpat1-dev libssl-dev pandoc xvfb xfonts-75dpi wkhtmltopdf tmux zlib1g-dev libxml2-dev libxslt1-dev python-dev python3 python-pip pylint hdparm zip clang
    # a2enmod ssl
    # pip install lxml pyopenssl
    # curl https://bootstrap.pypa.io/get-pip.py | python3

Debain 9 only. Install ccache to speedup C/C++ builds (it seems ccache can't cache clang on Debian 8)

    # apt install -y ccache
    # echo 'export PATH=/usr/lib/ccache:$PATH' >> ~/.bashrc
    # export PATH=/usr/lib/ccache:$PATH
    # which clang++


### Install KeyTalk

Clone

    # git clone https://github.com/KeyTalk/windows-linux-client.git /keytalk
    # touch /resept_linux_client_dev

Install

    # cd /keytalk/Software/Client/Projects/
    # make clean && make && make install

 Test

    # /usr/local/bin/keytalk/ktconfig --rccd-path /keytalk/Software/Client/TestProjects/Common/RCCDs/v2/githubtest.rccd
    # /usr/local/bin/keytalk/ktclient --provider KeyTalk_GitHub_TEST --service test --user test --password test

The certificate will be placed under `~/.keytalk/keystore/`


## Building KeyTalk Windows client

### Setup the system

Install Windows 7 x86 SP1 including all the latest updates

Install MSVS 2013 Professional with Update 4

Install Qt-5.5 community edition from the [Qt download page](http://www.qt.io/download-open-source)

 - example [download link](http://ftp1.nluug.nl/languages/qt/archive/qt/5.5/5.5.0/qt-opensource-windows-x86-msvc2013-5.5.0.exe)
 - installing community edition suffices since Qt usage in KeyTalk conforms LGPL terms

Add environment variable QTDIR pointing to the QT installation directory (e.g. `D:\Qt\Qt5.5.0\5.5\msvc2013`).


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
  3. Create a pull-request or commit to the agreed branch.
