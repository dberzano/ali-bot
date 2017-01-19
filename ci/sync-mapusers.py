#!/usr/bin/env python
from __future__ import print_function
from requests import get
from random import choice
#from urlparse import urlparse,urlunparse
from urlparse import urlsplit,urlunsplit
import yaml,sys

url = sys.argv[1]
mesos_dns = "leader.mesos:8123"

parts = list(urlsplit(url))
host = parts[1].split(":", 1)[0]
host = "_"+host.replace(".", "._tcp.", 1)

try:
  parts[1] = str(choice([ x["ip"]+":"+x["port"]
                         for x in get("http://%s/v1/services/%s" % (mesos_dns,host)).json()
                         if x.get("ip", None) ]))
  url = urlunsplit(parts)
except Exception:
  sys.stderr.write("Error resolving service for %s\n" % url)

# Update current mapping with new
umap = yaml.safe_load(open("mapusers.yml"))
umap.update( get(url).json()["login_mapping"] )
for k in sorted(umap.keys()):
  print("%s: %s" % (k, umap[k]))
