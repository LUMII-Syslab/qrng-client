#!/bin/bash

export JC_CLASSIC_HOME="$(dirname "$0")/../"

for l in "$JC_CLASSIC_HOME/lib"/*.jar ; do
    JC_CLASSPATH="$l:$JC_CLASSPATH"
done

MAIN="$1"
shift 1
java "-Djc.home=$JC_CLASSIC_HOME" -classpath "$JC_CLASSPATH" "$MAIN" "$@"

