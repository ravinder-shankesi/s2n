#!/bin/bash

#download saw binaries
curl http://saw.galois.com/builds/nightly/saw-0.2-2016-11-02-Ubuntu14.04-64.tar.gz > \
     saw.tar.gz; tar -xzvf saw.tar.gz

#download z3
mkdir z3; curl http://saw.galois.com/builds/z3/z3 > z3/z3
sudo chmod +x z3/z3
