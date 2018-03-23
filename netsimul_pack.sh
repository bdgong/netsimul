#!/bin/bash
#
# tar netsimul project
cd /home/bdg/share/public/project
tar -cvf netsimul-0.3.tar netsimul/ --exclude=netsimul/.git
cd -
