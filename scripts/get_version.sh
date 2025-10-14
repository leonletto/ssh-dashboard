#!/bin/bash
# Generate version string from git, similar to setuptools-scm

set -e

GIT_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
GIT_COMMIT=$(git rev-parse --short=8 HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

if git describe --exact-match --tags HEAD &>/dev/null; then
    VERSION="${GIT_TAG#v}"
else
    COMMITS_SINCE=$(git rev-list ${GIT_TAG}..HEAD --count 2>/dev/null || echo "0")
    
    if [ "$COMMITS_SINCE" -gt 0 ]; then
        # Format: 0.1.0-dev5+gabc1234
        BASE_VERSION="${GIT_TAG#v}"
        VERSION="${BASE_VERSION}-dev${COMMITS_SINCE}+g${GIT_COMMIT}"
    else
        VERSION="0.0.0-dev+g${GIT_COMMIT}"
    fi
fi

if [ "$1" = "--json" ]; then
    cat <<EOF
{
  "version": "${VERSION}",
  "git_tag": "${GIT_TAG}",
  "git_commit": "${GIT_COMMIT}",
  "build_date": "${BUILD_DATE}"
}
EOF
elif [ "$1" = "--ldflags" ]; then
    echo "-X 'github.com/alpindale/ssh-dashboard/internal.Version=${VERSION}' -X 'github.com/alpindale/ssh-dashboard/internal.GitCommit=${GIT_COMMIT}' -X 'github.com/alpindale/ssh-dashboard/internal.BuildDate=${BUILD_DATE}' -X 'github.com/alpindale/ssh-dashboard/internal.GitTag=${GIT_TAG}'"
else
    echo "${VERSION}"
fi

