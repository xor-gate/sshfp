#!/usr/bin/env bash
set -e

GREP_EXCLUDES="vendor\|examples"
LINT_CMD="gometalinter --config .gometalinter.conf"

echo "--- go env"
go env

echo "--- lint (gometalinter)"
go get -v -u github.com/alecthomas/gometalinter
gometalinter --install
${LINT_CMD} ./...

echo "--- create build folder ./build"
mkdir -p build

#echo "--- build and lint examples/*.go"
#for e in $(ls -1 examples/*.go); do
#	filename=$(basename $e)
#	filename="${filename%.*}"
#	echo "* $filename"
#	${LINT_CMD} $e
#	go build -o build/$filename $e
#done

echo "--- go test (with race detector and coverage)"
echo "" > coverage.txt

for d in $(go list ./... | grep -v ${GREP_EXCLUDES}); do
	go test -race -coverprofile=profile.out -covermode=atomic $d
	if [ -f profile.out ]; then
		cat profile.out >> coverage.txt
		rm profile.out
	fi
done
