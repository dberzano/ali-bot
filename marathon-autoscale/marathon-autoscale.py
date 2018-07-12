#!/usr/bin/env python

from __future__ import print_function
from requests import get, put
from time import sleep
import yaml
import os

def sync():
  conf = {}
  try:
    conf = yaml.safe_load(get(os.environ["MARATHON_AUTOSCALE_CONF_URL"], headers={"Cache-Control": "no-cache"}).text)
    marathon_url = conf["marathon_url"]
  except Exception as e:
    print("Error fetching configuration: %s" % e)

  for app,spec in conf.get("apps", {}).items():
    try:
      # Get number of instances
      d = get("{url}/v2/apps/{app}".format(url=marathon_url, app=app)).json()
      print("[%s] Before: %d" % (app, d["app"]["instances"]))

      # Scale if necessary
      if d["app"]["instances"] != spec["instances"]:
        print("[%s] Scaling to %d" % (app, spec["instances"]))
        put("{url}/v2/apps/{app}?force=true".format(url=marathon_url, app=app), json={"instances": spec["instances"]})
        d = get("{url}/v2/apps/{app}".format(url=marathon_url, app=app)).json()
        print("[%s] After: %d" % (app, d["app"]["instances"]))
      else:
        print("[%s] No need to scale" % app)
    except Exception as e:
      print("[%s] Error: %s" % (app, e))

while True:
  sync()
  print("Sleeping 10 seconds")
  sleep(10)
