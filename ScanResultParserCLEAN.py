from datetime import datetime, timedelta
from time import strftime

from postmarker.core import PostmarkClient
postmark = PostmarkClient(server_token='your token here')

todaysOutputFile = open("NewPortsAndHosts", 'r+')

yesterday = datetime.now() - timedelta(days=1)
yesterday = yesterday.strftime("%Y_%m_%d")

priorScanFile = open(yesterday, 'r')	#when the script finishes, this file should be renamed to (today's date - 1)
newScanFile = open(strftime("%Y_%m_%d"), 'r')	#this is the filename the nmap scan should output. When the script finishes, rename this file to "scan-prior-results

priorScanContent = priorScanFile.readlines()
newScanContent = newScanFile.readlines()

oldOpenPorts = []
newOpenPorts = []


for line in priorScanContent:
	if "Ports" in line:			#any line that contains open ports will have the word "port" in it
		splitIP = line.split()	#Split the line up into substrings at every whitespace. Good since there's both tabs and spaces in the output
		newPortElement = []
		newPortElement.append(splitIP[1])   #grab the host's IP
		portString = line.split("\t")
		
		splitPortList = portString[1][5:].split(", ")
		splitPortList[0] = splitPortList[0]

		for subString in splitPortList:
			
			
			if("open" in subString or "filtered" in subString or "closed" in subString):         #Also look for `filtered` entries
				newPortElement.append(subString)
		oldOpenPorts.append(newPortElement)

		#print(oldOpenPorts)


for line in newScanContent:
	if "Ports" in line:			#any line that contains open ports will have the word "port" in it
		splitIP = line.split()	#Split the line up into substrings at every whitespace. Good since there's both tabs and spaces in the output
		newPortElement = []
		newPortElement.append(splitIP[1])   #grab the host's IP
		portString = line.split("\t")
		
		splitPortList = portString[1][5:].split(", ")
		splitPortList[0] = splitPortList[0]

		for subString in splitPortList:
			if("open" in subString or "filtered" in subString or "closed" in subString):
				newPortElement.append(subString)                
		newOpenPorts.append(newPortElement)

		#print(newOpenPorts)


differences = []
#Now for the diff function. Used to find new ports & machines
for newHostPortArray in newOpenPorts:   #iterate through every host-port array from the "new" list
	foundPortMatch = False
	foundIPmatch = False    #since we haven't started on this IP yet, this has to be false
	for oldHostPortArray in oldOpenPorts:   #grab the next old host-port array
		if newHostPortArray[0] == oldHostPortArray[0]:  #Do the IPs of each array match?
                        
			foundIPmatch = True     #store this for later, so we can identify new hosts
			for newPort in newHostPortArray:       #Now we look at each element in the current item from the "new" array. So we're now looking at the hostIP, and any open ports
				foundPortMatch = False
				
				for oldPort in oldHostPortArray:       #same deal as above, but now on the old array
					
					if newPort == oldPort:
						
						foundPortMatch = True
						break
				if(not foundPortMatch):
					#print("NewPort: " + newPort + "\nOldPort: " + oldPort)
					print("New port opened on host " + newHostPortArray[0] + " ! " + newPort)
					differences.append(newPort)
					todaysOutputFile.write("New port opened on host " + newHostPortArray[0] + " ! " + newPort)
				
	if(not foundIPmatch):
		print("!! New host scanned !! " + newHostPortArray[0])
		todaysOutputFile.write("<p>!! New host scanned !! " + newHostPortArray[0] + "</p>")


if len(differences) == 0:
	print("No changes found")
	todaysOutputFile.write("No changes found")

todaysOutputFile.close()
todaysOutputFile = open("NewPortsAndHosts", 'r')
results = todaysOutputFile.read()
print(results)

postmark.emails.send(
From='from address',
To='recipient address',
Subject='Daily Portscan Report',
HtmlBody='<html><body><strong>' + results + '</body></html>')




todaysOutputFile.close()
