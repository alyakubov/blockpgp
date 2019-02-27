#!/bin/bash -ex


export RELEASE_VERSION=2.0~rc2

export BUILD_PACKAGE=github.com/alyakubov/blockpgp
export HOCKEYBLOCK_PACKAGE_NAME=hockeyblock.v0

### Set up GOPATH

export GOPATH=$(pwd)
for pkg in github.com/rogpeppe/godeps github.com/mitchellh/gox; do
	go get ${pkg}
	go install ${pkg}
done

##go get -d -t ${BUILD_PACKAGE}/${HOCKEYBLOCK_PACKAGE_NAME}/...
##go get -d -t ${BUILD_PACKAGE}/ethpgp/...
go get -d -t ${BUILD_PACKAGE}/...

#cd src/${BUILD_PACKAGE}
#${GOPATH}/bin/godeps -u dependencies.tsv

### Set up webroot

cd ${GOPATH}
mkdir -p instroot/var/lib/hockeypuck
cd instroot/var/lib/hockeypuck
if [ ! -d www ]; then
	git clone https://github.com/hockeypuck/webroot.git www
fi
### TODO: set webroot revision?

## deploy_eth should be modified to reflect the path to blockchain folder
#cd ./src/${BUILD_PACKAGE}/
#./deploy_eth.sh

