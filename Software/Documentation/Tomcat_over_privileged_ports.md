# Instructions to give privileged port access to a non-root user for running Tomcat

#### Ignore sudo if root

## Ubuntu/Debian

On Unbuntu/Debian, instead of running tomcat as root you can also use AUTHBIND to allow unprivileged users to bind to 'reserved' ports (below 1023).

      sudo apt-get install authbind
      sudo touch /etc/authbind/byport/443
      sudo chmod 500 /etc/authbind/byport/443
      sudo chown <tomcat-user> /etc/authbind/byport/443

   Edit the file /etc/default/tomcatX or /etc/default/tomcat to change AUTHBIND=no to AUTHBIND=yes.
   Where X is the tomcat version number.

### Reload and Restart the tomcat

      sudo systemctl daemon-reload
      sudo systemctl restart tomcatX or sudo systemctl restart tomcatX



## CentOS-7.x/RHEL-7.x

On CentOS-7.x/RHEL-7.x, instead of running tomcat as root you can also use AUTHBIND to allow unprivileged users to bind to 'reserved' ports (below 1023).

### Install authbind rpm

      sudo rpm -Uvh https://s3.amazonaws.com/aaronsilber/public/authbind-2.1.1-0.1.x86_64.rpm

#### If above rpm fails then you have to build the rpm yourself from the instructions given below

      sudo -i (ignore this if already root)
      svn co https://github.com/tootedom/authbind-centos-rpm.git
      mkdir /root/rpmbuild
      cp -R authbind-centos-rpm.git/trunk/authbind/* /root/rpmbuild/
      cd /root/rpmbuild/SOURCES
      wget http://ftp.debian.org/debian/pool/main/a/authbind/authbind_2.1.1.tar.gz
      mv authbind_2.1.1.tar.gz authbind-2.1.1.tar.gz
      cd ../
      rpmbuild -v -bb --clean SPECS/authbind.spec
      rpm -Uvh /root/rpmbuild/RPMS/x86_64/authbind-2.1.1-0.1.x86_64.rpm

### Configure ports for authbind

      sudo touch /etc/authbind/byport/443
      sudo chmod 500 /etc/authbind/byport/443
      sudo chown <tomcat-user> /etc/authbind/byport/443

Edit the file /etc/systemd/system/multi-user.target.wants/tomcat.service and comment out the original “ExecStart” command, duplicated the line and added authbind as follows:

      #ExecStart=/usr/libexec/tomcat/server start
      ExecStart=/usr/bin/authbind --deep "/usr/libexec/tomcat/server" start

### Reload and Restart the tomcat
      sudo systemctl daemon-reload
      sudo systemctl restart tomcatX or sudo systemctl restart tomcatX

## CentOS-6.x/RHEL-6.x

On CentOS-6.x/RHEL-6.x, instead of running tomcat as root you can also use setcap to allow unprivileged users to bind to 'reserved' ports (below 1023).

### Install libcap library

      yum install libcap

### Apply capablities to java binary in order to use privileged ports on Tomcat

      sudo setcap CAP_NET_BIND_SERVICE=+eip /path_to_java_binary

Now, test to make sure java works:

      java -version

      java: error while loading shared libraries: libjli.so: cannot open shared object file: No such file or directory

The above error means that after setting setcap, it breaks how java looks for its library to run. To fix this, we need to symlink the library it’s looking for into /usr/lib, then run ldconfig

      sudo ln -s <your-java-home>/jre/lib/amd64/jli/libjli.so /usr/lib/ or sudo ln -s <your-java-home>/lib/amd64/jli/libjli.so /usr/lib/
      sudo ldconfig

Now test Java again:

      java -version

### Restart the tomcat server
      sudo service tomcatX restart or sudo service tomcat restart

Enjoy !