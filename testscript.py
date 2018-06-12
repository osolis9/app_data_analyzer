#!/usr/bin/python
import os
import re
from collections import OrderedDict
from collections import defaultdict
import numpy as np

import networkx as nx
from networkx.algorithms import bipartite
import matplotlib.pyplot as plt
plt.style.use('ggplot')

names = ['omar', 'solis', 'scott', 'buttinger']
emails = ['omarsolis4@gmail.com', 'sbuttinger19@gmail.com']

pii_types = ['omar', 'solis', 'scott', 'buttinger','936-404-8305','male','650-656-0106',
			'latitude','longitude','omarsolis4@gmail.com','sbuttinger19@gmail.com',
			'1996-04-06','04061996','1994-12-25','12251994','9364048305','6506560106', 
			'phone-num','phonenum', 'email', 'zipcode', 'birthday','phone_num',
			'username']

# pii categories
email_pii = ['email','omarsolis4@gmail.com','sbuttinger19@gmail.com','gmail']
birthday_pii = ['1996-04-06','04061996','1994-12-25','12251994','birthday']
phone_pii = ['9364048305','6506560106','936-404-8305','650-656-0106','phone-num','phonenum',
			 'phone_num']
location_pii = ['latitude','longitude']
gender_pii = ['male']
name_pii = ['omar', 'solis', 'scott', 'buttinger','username']
zip_pii = ['zipcode','94305','94306','94309','zip-code','zip_code']


email_cnt = 0
birthday_cnt = 0
phone_cnt = 0
location_cnt = 0
gender_cnt = 0
name_cnt = 0
zip_cnt = 0


# app categories

business = ['adobe','adp','indeed']
entertainment = ['sling drift','unicorn','colorfy']
health_fitness = ['myfitnesspal','fitbit','sweatcoin']
lifestyle = ['zillow','horoscope+ 2018','ebay']
medical = ['leafly','ovia pregnancy','mychart']
social = ['pinterest','groupme','findmyfamilyfriendsphone']
navigation = ['geocaching','moovit','transit']
photo_video = ['snapchat','musically','youtube']

app_categories = ['business','entertainment','health & fitness','lifestyle','medical','social','navigation','photo & video']

business_cnt = 0
entertainment_cnt = 0
health_fitness_cnt = 0
lifestyle_cnt = 0
medical_cnt = 0
social_cnt = 0
navigation_cnt = 0
photo_video_cnt = 0



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

		# outlook.com requests are caused by background email refreshes so we ignore them
		if host == 'outlook.com':
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

				# count PII by category
				if any(pii in message_body.lower() for pii in email_pii):
					email_cnt += 1
				elif any(pii in message_body.lower() for pii in birthday_pii):
					birthday_cnt += 1
				elif any(pii in message_body.lower() for pii in location_pii):
					location_cnt += 1
				elif any(pii in message_body.lower() for pii in gender_pii):
					gender_cnt += 1
				elif any(pii in message_body.lower() for pii in name_pii):
					name_cnt += 1
				elif any(pii in message_body.lower() for pii in zip_pii):
					zip_cnt += 1
				elif any(pii in message_body.lower() for pii in phone_pii):
					phone_cnt += 1

				# count apps by category
				if any(name in app_name for name in entertainment):
					entertainment_cnt += 1
				elif any(name in app_name for name in business):
					business_cnt += 1
				elif any(name in app_name for name in health_fitness):
					health_fitness_cnt += 1
				elif any(name in app_name for name in lifestyle):
					lifestyle_cnt += 1
				elif any(name in app_name for name in medical):
					medical_cnt += 1
				elif any(name in app_name for name in social):
					social_cnt += 1
				elif any(name in app_name for name in navigation):
					navigation_cnt += 1
				elif any(name in app_name for name in photo_video):
					photo_video_cnt += 1


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

pos.update((node, [1, i*(2.6)]) for i,node in enumerate(l))
pos.update((node, (2, index)) for index, node in enumerate(r))

d = nx.degree(B_sensitive)
d = [(d[node]+1) * 30 for node in B_sensitive.nodes()]

nx.draw(B_sensitive, pos=pos, with_labels=False, node_size=d, linewidths=.2, width=.4, font_size=6)

for node in list(pos.items()):
	if node[0] in pii_apps:
		plt.text(node[1][0]-0.05,node[1][1],s=node[0],horizontalalignment='right',fontsize=10,verticalalignment='center')
	else:
		plt.text(node[1][0]+0.05,node[1][1],s=node[0],fontsize=7,verticalalignment='center')
plt.xlim((0.5,2.5))
plt.show()

	
print('Results:')
print(str(len(pii_apps)) + ' apps')
print(str(len(pii_hosts)) + ' hosts')
print(str(len(pii_edges)) + ' edges')

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


print('\n\nMETRICS')
print('http count: '+ str(http_count))
print('https count: ' + str(https_count))
print('third party connections with pii: ' + str(third_party_count_pii))
print('third party connections: ' + str(third_party_count))
print('server connections: ' + str(servers_count))
print('server connections with pii ' + str(servers_count_pii))
print('app count: ' + str(len(apps)))
#print(pii_hosts)

# plot pii categorical breakdown
pii_counts = np.array([email_cnt,birthday_cnt,phone_cnt,location_cnt,gender_cnt,name_cnt,zip_cnt])
total_pii = np.sum(pii_counts)
pii_names = ['email','birthday','phone number','location','gender','name','zip code']
indices = np.argsort(np.array(pii_counts))
plt.barh(y=range(len(pii_counts)),width=np.array(pii_counts)[indices],tick_label=np.array(pii_names)[indices],color='red')
plt.ylabel('PII Category')
plt.xlabel('Number of Times Shared')
plt.title('PII Transmissions by Category')
plt.show()

print('\n\nPII CATEGORY COUNTS')
print('email count: ' + str(email_cnt))
print('birthday count: ' + str(birthday_cnt))
print('phone count: ' + str(phone_cnt))
print('location count: ' + str(location_cnt))
print('gender count: ' + str(gender_cnt))
print('name count: ' + str(name_cnt))
print('zip count: ' + str(zip_cnt))
print('total pii: ' + str(total_pii))

# plot app categorical breakdown
app_pii_counts = np.array([business_cnt,entertainment_cnt,health_fitness_cnt,lifestyle_cnt,medical_cnt,
						social_cnt,navigation_cnt,photo_video_cnt])
total_app_pii = np.sum(app_pii_counts)
indices = np.argsort(np.array(app_pii_counts))
plt.barh(y=range(len(app_pii_counts)),width=np.array(app_pii_counts)[indices],tick_label=np.array(app_categories)[indices],color='red')
plt.ylabel('App Category')
plt.xlabel('Number of PII Transmissions')
plt.title('PII Transmissions by App Category')
plt.show()

print('\n\nAPP PII CATEGORY COUNTS')
print('business count: ' + str(business_cnt))
print('entertainment count: ' + str(entertainment_cnt))
print('health_fitness count: ' + str(health_fitness_cnt))
print('lifestyle count: ' + str(lifestyle_cnt))
print('medical count: ' + str(medical_cnt))
print('social count: ' + str(social_cnt))
print('navigation count: ' + str(navigation_cnt))
print('photo_video count: ' + str(photo_video_cnt))
print('total app pii: ' + str(total_app_pii))
