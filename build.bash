#!/bin/bash -ex


export RELEASE_VERSION=2.0~rc2

export BUILD_PACKAGE=github.com/alyakubov/blockpgp
export HOCKEYBLOCK_PACKAGE_NAME=hockeyblock.v0

### Set up GOPATH

export GOPATH=$(pwd)

export SHORTHASH=$(git log -1 --pretty=format:%h)
export LONGHASH=$(git log -1 --pretty=format:%H)
export HEXDATE=$(date +%s)

# Get our current and last built revision
export LTS_SERIES="precise trusty"
export PACKAGE_VERSION="${RELEASE_VERSION}~${HEXDATE}+${SHORTHASH}"

cd ${GOPATH}

echo "$LONGHASH" > version-git-commit
echo "$PACKAGE_VERSION" > version-release

## AYAKU

abigen --abi ${GOPATH}/src/${BUILD_PACKAGE}/scontract/binout/LU_PGP_iden.abi --pkg pghkp --type PgpIden --out ${GOPATH}/src/${BUILD_PACKAGE}/bind_iden.go
abigen --abi ${GOPATH}/src/${BUILD_PACKAGE}/scontract/binout/LU_PGP_orchestr.abi --pkg pghkp --type PgpOrchestr --out ${GOPATH}/src/${BUILD_PACKAGE}/bind_orchestr.go


go install ${BUILD_PACKAGE}/${HOCKEYBLOCK_PACKAGE_NAME}/cmd/hockeypuck
go install ${BUILD_PACKAGE}/${HOCKEYBLOCK_PACKAGE_NAME}/cmd/hockeypuck-load
go install ${BUILD_PACKAGE}/${HOCKEYBLOCK_PACKAGE_NAME}/cmd/hockeypuck-pbuild
go install ${BUILD_PACKAGE}/ethpgp
## !AYAKU

