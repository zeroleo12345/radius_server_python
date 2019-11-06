#!/usr/bin/env sh
ls *.log | xargs -I{} -p -t sh -c "echo '' > {}"
