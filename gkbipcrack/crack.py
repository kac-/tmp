# -*- coding: utf-8 -*-
import json
import bip
import sys
import httplib, urllib

user = "kactech"

conn = httplib.HTTPConnection("btc.7u.pl")
test = True

while True:
 if test:
  str = '{"concat":["HsE","aąc","HsF","HsG","HsH","HsI","HsJ","HsK","HsL","HsM","aąc"],"work":{"left":164633,"max":238328}}'
 else:
  conn.request("POST", "/post.php") 
  resp = conn.getresponse()
  str = resp.read()
 
 obj = json.loads(str)['concat']
 for pwd in obj:
  print pwd
  pwd = pwd.encode('utf-8');
  p = bip.test(pwd)
  params = urllib.urlencode({'queue': 10, 'result[author]': user, 'result[pass]': pwd, 'result[res]': p, 'result[priv]':''})
  if test:
    print params
  else:
    conn.request("POST", "/post.php", params)
  if p == 1:
   sys.exit(1)
 #end for
 if test:
  sys.exit(0)
 
