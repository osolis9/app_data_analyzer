#!/usr/bin/python
import os
import re
from collections import OrderedDict
from collections import defaultdict

import networkx as nx
from networkx.algorithms import bipartite
import matplotlib.pyplot as plt

names = ['omar', 'solis', 'scott', 'buttinger']
emails = ['omarsolis4@gmail.com', 'sbuttinger19@gmail.com']

pii_types = ['omar', 'solis', 'scott', 'buttinger','936-404-8305','male','650-656-0106',
			'latitude','longitude','omarsolis4@gmail.com','sbuttinger19@gmail.com',
			'1996-04-06','04061996','1994-12-25','12251994','9364048305','6506560106', 
			'phone', 'email', 'zipcode', 'birthday']


third_party = ['smaato.net', 'tlnk.io', 'amazonaws.com', 'serving-sys.com', 'appbaqend.com',
 				'os-data.com', 'freshchat.com', 'akamaized.net', 'freshchat.com', 'appspot.com', 'googleapis.com',
  				'ssacdn.com', 'kiip.me', 'facebook.com', 'apple.com', 'localytics.com', 'gameanalytics.com', 'tapjoyads.com', 
  				'manage.com', 'pubnub.com', 'netmng.com', 'zendrive.com', 'atom-data.io', 'swrve.com', 'rec-engine.com', 'amazon-adsystem.com', 
  				'google-analytics.com', 'amplitude.com', 'appsee.com', 'qbk1.com', 'appcloudbox.net', 'supersonic.com', 'uxcam.com', 'cloudfront.net']

pii_apps = set([])
pii_hosts = set([])
pii_edges = set([])

http_count = 0
https_count = 0
B = nx.Graph()
B_sensitive = nx.OrderedGraph()
apps = []
hosts = []
edges = []
third_party_connections = 0
app_to_third_parties_pii = defaultdict(list)
app_to_third_party = defaultdict(set)


app_to_servers = defaultdict(set)
app_to_servers_pii = defaultdict(set)
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
			if host in third_party:
				app_to_third_party[app_name].add(host)

			app_to_servers[app_name].add(host)
			if protocol.startswith('https'):
				https_count += 1
			else:
				http_count += 1
			## do text analysis here since we have the request/response fully built
			if any(pii_type in message_body.lower() for pii_type in pii_types):

				pii_apps.add(app_name)
				pii_hosts.add(host)
				pii_edges.add((app_name,host))

				if host in third_party:
					if host not in app_to_third_parties_pii[app_name]:
						app_to_third_parties_pii[app_name].append(host)
				app_to_servers_pii[app_name].add(host)

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


pos = OrderedDict({})

#pos.update((node, (1, index)) for index, node in enumerate(l))
pos.update((node, [1, i*(2.5)]) for i,node in enumerate(l))
pos.update((node, (2, index)) for index, node in enumerate(r))

d = nx.degree(B_sensitive)
d = [(d[node]+1) * 30 for node in B_sensitive.nodes()]
# print(d)

nx.draw(B_sensitive, pos=pos, with_labels=False, node_size=d, linewidths=.2, width=.2, font_size=6)

for node in list(pos.items()):
	if node[0] in pii_apps:
		plt.text(node[1][0]-0.05,node[1][1],s=node[0],horizontalalignment='right',fontsize=10,verticalalignment='center')
	else:
		plt.text(node[1][0]+0.05,node[1][1],s=node[0],fontsize=7,verticalalignment='center')
plt.xlim((0.5,2.5))
plt.savefig("graph_pii.png",dpi=300)
plt.show()

	
print('Results:')
print(len(pii_apps))
print(len(pii_hosts))
print(len(pii_edges))

third_party_count_pii = 0
for app, third_parties in app_to_third_parties_pii.items():
	third_party_count_pii += len(third_parties)

third_party_count = 0
for app, third_parties in app_to_third_party.items():
	third_party_count += len(third_parties)

servers_count = 0
for app, servers in app_to_servers.items():
	servers_count += len(servers)

servers_count_pii = 0
for app, servers in app_to_servers_pii.items():
	servers_count_pii += len(servers)

print('http count:'+ str(http_count))
print('https count: ' + str(https_count))
print('third party connections with pii: ' + str(third_party_count_pii))
print('third party connections: ' + str(third_party_count))
print('server connections: ' + str(servers_count))
print('server connections with pii ' + str(servers_count_pii))
print('app count: ' + str(len(apps)))
#print(pii_hosts)
