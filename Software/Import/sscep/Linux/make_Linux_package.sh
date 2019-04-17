#!/bin/bash

echo "Creating package..."
#arch=$(uname -p)
#ts=$(date +'%Y%m%d%H%M%S')
version=$(head -n 1 VERSION)

sed "s/VERSIONINFO/$version/" < Linux/sscep.spec.in > Linux/sscep.spec
mkdir sscep-$version
cp sscep COPYRIGHT README sscep-$version/
tar -czf $HOME/rpmbuild/SOURCES/sscep-$version.tar.gz sscep-$version
rm -rf sscep-$version
rpmbuild -bb Linux/sscep.spec

