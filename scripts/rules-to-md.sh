#!/bin/bash

cd ..

tree=$(tree -tf --noreport -I '*~' --charset ascii $1 |
       sed -e 's/| \+/  /g' -e 's/[|`]-\+/ */g' -e 's:\(* \)\(\(.*/\)\([^/]\+\)\):\1[\4](\2):g' | grep -v README | grep -v scripts | grep -v LICENSE)

printf "# YARA rules\n\n${tree}"
