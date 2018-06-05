#!/usr/bin/python
import os
import re


import networkx as nx
from networkx.algorithms import bipartite
import matplotlib.pyplot as plt

names = ['omar', 'solis', 'scott', 'buttinger']
emails = ['omarsolis4@gmail.com', 'sbuttinger19@gmail.com']

pii_types = ['omar', 'solis', 'scott', 'buttinger','936-404-8305','male','650-656-0106',
			'latitude','longitude','omarsolis4@gmail.com','sbuttinger19@gmail.com',
			'1996-04-06','04061996','1994-12-25','12251994','9364048305','6506560106']

pii_apps = set([])
pii_hosts = set([])
pii_edges = set([])


B = nx.Graph()
B_sensitive = nx.Graph()
apps = []
hosts = []
edges = []
for filename in os.listdir(os.curdir):
	if not filename.endswith(".trace"):
		continue
	with open(filename, "r", errors='ignore') as f:
		f1 = f.readlines()

	app_name = filename.split('.')[0]
	apps.append(app_name)
	inRequest = False
	inResponse = False
	message_body = ""
	method = ""
	protocol = ""
	host = ""
	inSocket = False
	for line in f1:
		
		#gets these for each post.. Each new post starts with these..
		if line.startswith("Method: "):
			method = line.split(': ')[1][:-1] #I remove the /n at the end

		if line.startswith("Protocol: "):
			protocol = line.split(': ')[1][:-1]

		if line.startswith("Host: "):
			host = line.split(": ")[1][:-1]
			ip = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host) ##checks to see if its a socket
			top_level = re.match(r"[^.]*\.[^.]{2,3}(?:\.[^.]{2,3})?$", host)
			top_level_pattern = re.compile("[^.]*\.[^.]{2,3}(?:\.[^.]{2,3})?$")

			if ip:
				inSocket = True
			else:

				matches = top_level_pattern.findall(host)
				if len(matches) != 0:
					host = matches[0]
				if host not in hosts:
					hosts.append(host)
					#print(host)
				edge = (app_name, host)
				if edge not in edges:
					edges.append(edge)

				inSocket = False


		#dont do data parsing if the message was sent to a socket and not a server
		#I dont really understand when the host is just an IP so for now I'm not analyzing that
		if inSocket:
			continue

		#have request/response fully built
		if (inResponse and line.startswith("--EOF")) or (inRequest and line.startswith("--EOF")):

			## do text analysis here since we have the request/response fully built
			if any(pii_type in message_body.lower() for pii_type in pii_types):

				pii_apps.add(app_name)
				pii_hosts.add(host)
				pii_edges.add((app_name,host))

				if inRequest:
					message = "PII sent in request from " + app_name +  ' to ' + host
				if inResponse:
					message = "PII sent in response to " + app_name +  ' from ' + host

				if protocol.startswith('https'):
					message += " securely"
					# pass
				else:

					message += " insecurely"
					# print(message_body.lower())
					# print(message)

				print(message)

			
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

	
"""B.add_nodes_from(apps, bipartite=0)
B.add_nodes_from(hosts, bipartite=1)

B.add_edges_from(edges)

print(nx.is_connected(B))

l, r = nx.bipartite.sets(B)
pos = {}

#pos.update((node, (1, index)) for index, node in enumerate(l))
pos.update((node, [1, i*(i/2)]) for i,node in enumerate(l))
pos.update((node, (2, index*(index/90))) for index, node in enumerate(r))
print(len(apps))
print(len(hosts))
print(len(edges))
nx.draw(B, pos=pos, with_labels=True, node_size=10, linewidths=.2, width=.2, font_size=3)
#nx.draw(B)
#nx.draw_networkx(B, pos=pos, node_size=100)
plt.savefig("graph.pdf")
plt.show()"""



pii_apps = list(pii_apps)
pii_hosts = list(pii_hosts)
pii_edges = list(pii_edges)

B_sensitive.add_nodes_from(pii_apps, bipartite=0)
B_sensitive.add_nodes_from(pii_hosts, bipartite=1)

B_sensitive.add_edges_from(pii_edges)

l = {n for n, d in B_sensitive.nodes(data=True) if d['bipartite']==0}
r = set(B_sensitive) - l



pos = {}

#pos.update((node, (1, index)) for index, node in enumerate(l))
pos.update((node, [1, i*(2.5)]) for i,node in enumerate(l))
pos.update((node, (2, index)) for index, node in enumerate(r))

nx.draw(B_sensitive, pos=pos, with_labels=True, node_size=10, linewidths=.2, width=.2, font_size=6)
#nx.draw(B)
#nx.draw_networkx(B, pos=pos, node_size=100)
plt.savefig("graph_pii.pdf")
plt.show()



	
print('Results:')
print(len(pii_apps))
print(len(pii_hosts))
print(len(pii_edges))

