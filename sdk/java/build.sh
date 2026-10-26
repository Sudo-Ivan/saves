#!/bin/sh
# SPDX-License-Identifier: 0BSD
# Dependency-free build: compiles, runs tests, builds a jar.
set -eu
cd "$(dirname "$0")"
B=build
rm -rf "$B"
mkdir -p "$B/classes" "$B/test-classes"
javac -Xlint:all -Werror -d "$B/classes" $(find src -name '*.java')
javac -Xlint:all -Werror -cp "$B/classes" -d "$B/test-classes" $(find tests -name '*.java')
java -ea -cp "$B/classes:$B/test-classes" TestOffline
java -ea -cp "$B/classes:$B/test-classes" TestIntegration
jar -cf "$B/saves-sdk.jar" -C "$B/classes" .
echo "built $B/saves-sdk.jar"
