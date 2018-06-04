#!/usr/bin/python
import os

names = ['omar', 'solis', 'scott', 'buttinger']


for filename in os.listdir(os.curdir):
	if not filename.endswith(".trace"):
		continue
	with open(filename, "r", errors='ignore') as f:
		f1 = f.readlines()

	app_name = filename.split('.')[0]
	inRequest = False
	inResponse = False
	message_body = ""
	method = ""
	protocol = ""
	host = ""
	for line in f1:
		#gets these for each post.. Each new post starts with these..
		if line.startswith("Method: "):
			method = line.split(': ')[1]

		if line.startswith("Protocol: "):
			protocol = line.split(': ')[1]

		if line.startswith("Host: "):
			host = line.split(": ")[1]


		
		
		#have request/response fully built
		if (inResponse and line.startswith("--EOF")) or (inRequest and line.startswith("--EOF")):

			## do text analysis here since we have the request/response fully built
			if any(name in message_body.lower() for name in names):
				if inRequest:
					message = "name sent from " + app_name +  ' to ' + host
				if inResponse:
					message = "name sent to " + app_name +  ' from ' + host

				if protocol.startswith('https'):
					#message += " securely"
					pass
				else:

					message += " insecurely"
					print(message)

				#print(message)

			
			##restart response/request body
			message_body = ""
			inResponse = False
			inRequest = False

			
		#build request/response body
		if inRequest or inResponse:
			line = line.replace('\n', ' ')
			message_body += line
			



		if line.startswith('Request-Body:<<'):
			inRequest = True

		if line.startswith('Response-Body:<<'):
			inResponse = True
	

