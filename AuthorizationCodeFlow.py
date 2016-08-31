import requests
import json
import re
import sys
import os
import subprocess
import urllib
import getpass
import base64

# Please replace everything in <> with your information
argumentsCount = len(sys.argv)

if argumentsCount == 7:

	orgUrl = str(sys.argv[1])
	userName = str(sys.argv[2])
	clientId = str(sys.argv[3])
	clientSecret = str(sys.argv[4])
	redirectUri = str(sys.argv[5])
	tokenType = str(sys.argv[6])

	print "Please Enter Password for User Name: " + str(userName)
	password = getpass.getpass()


	url = "https://" + orgUrl + "/api/v1/authn"

	redirectUri = urllib.quote_plus(redirectUri)

	# redirectUri = "http://localhost:8888/okta-simplesamlphp-example/"

	credentials  = {}

	credentials["username"] = userName
	credentials["password"] = password

	credentialsJSON = json.dumps(credentials)

	headers = {'Accept':'application/json','Content-Type':'application/json'}

	response = requests.post(url, data = credentialsJSON, headers=headers)

	sessionToken = response.json()[u"sessionToken"]

	# Making GET /authorize call

	openIdUrl ="https://" + orgUrl + "/oauth2/v1/authorize?sessionToken="+sessionToken+"&client_id="+clientId+"&scope=openid+email+profile+groups&response_type=" + tokenType + "&response_mode=fragment&nonce=staticNonce&redirect_uri="+redirectUri+"&state=staticState"

	# print openIdUrl
	proc = subprocess.Popen(["curl","-v", "-D", "--silent",openIdUrl],  stderr=subprocess.PIPE, stdout=subprocess.PIPE)

	response = str(proc.communicate()[1])

	# print response


	startIndex = response.find("code=") + len("code=")

	endIndex = response.find("&state=staticState",startIndex);

	code = response[startIndex:endIndex]

	print "\n\n****************** Code*********************"
	print "\n \n"
	print code
	print "\n \n"
	print "****************** Code *********************\n\n"


	print "Using code to Generate Access and Id Token\n \n"
	# Making POST /token call

	base64ClientIdSecret = base64.b64encode(clientId + ":" + clientSecret)

	headers = {'Authorization':'Basic ' + base64ClientIdSecret,'Content-Type':'application/x-www-form-urlencoded;'}

	openIdUrl = "https://" + orgUrl + "/oauth2/v1/token?grant_type=authorization_code&code=" + code + "&redirect_uri=" + redirectUri

	response = requests.post(openIdUrl, headers=headers)

	accessToken = response.json()["access_token"]
	idToken = response.json()["id_token"]

	print "\n\n****************** Access Token *********************"
	print "\n \n"
	print accessToken
	print "\n \n"
	print "****************** Access Token *********************\n\n"

	print "\n\n****************** Id Token *********************"
	print "\n \n"
	print idToken
	print "\n \n"
	print "****************** Id Token *********************\n\n"

	


else:

	print "*Error* Please include exact 6 arguments in order --> Org Url, UserName, ClientId, Client Secret, RedirectUri and TokenType"
