#!/usr/bin/env python3
import passlib.hash
import base64
def f(p,s,r):
  h = passlib.hash.sha512_crypt.encrypt(p,salt=s,rounds=r)
  print('  {"%s", "%s", %s, "%s"},' % (p,s,r,h))

f('','',5000)
f('','a',5000)
f('','ab',5000)
f('','abc',5000)
f('','abcd',5000)
f('','abcde',5000)
f('','abcdef',5000)
f('','abcdefg',5000)
f('','abcdefgh',5000)
f('','abcdefghi',5000)
f('','abcdefghij',5000)
f('','abcdefghijk',5000)
f('','abcdefghijkl',5000)
f('','abcdefghijklm',5000)
f('','abcdefghijklmn',5000)
f('','abcdefghijklmno',5000)
f('','abcdefghijklmnop',5000)
f('','qrstuvwxyz012345',5000)
f('','67890./',5000)
f('','ABCDEFGHIJKLMNOP',5000)
f('','QRSTUVWXYZ012345',5000)
f('','a',1000)
f('','a',1001)
f('','a',1002)
for i in range(70):
    f(('password'*10)[0:i],'a',5000)
