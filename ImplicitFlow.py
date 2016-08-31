import requests
import json
import re
import sys
import os
import subprocess
import urllib
import getpass

# Please replace everything in <> with your information
argumentsCount = len(sys.argv)

if argumentsCount == 6:

	orgUrl = str(sys.argv[1])
	userName = str(sys.argv[2])
	clientId = str(sys.argv[3])
	redirectUri = str(sys.argv[4])
	tokenType = str(sys.argv[5])


	print "\nPlease Enter Password for User Name: " + str(userName)
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

	openIdUrl ="https://" + orgUrl + "/oauth2/v1/authorize?sessionToken="+sessionToken+"&client_id="+clientId+"&scope=openid+phone+email+profile+groups&response_type=" + tokenType + "&response_mode=fragment&nonce=staticNonce&redirect_uri="+redirectUri+"&state=staticState"

	print openIdUrl
	proc = subprocess.Popen(["curl","-v", "-D", "--silent",openIdUrl],  stderr=subprocess.PIPE, stdout=subprocess.PIPE)

	response = str(proc.communicate()[1])

	if tokenType == "id_token":

		startIndex = response.find("id_token=") + len("id_token=")

		endIndex = response.find("&state=staticState",startIndex);

		id_token = response[startIndex:endIndex]

		print "\n\n****************** ID Token *********************"
		print "\n \n"
		print id_token
		print "\n \n"
		print "****************** ID Token *********************\n\n"

	elif tokenType == "token":

		startIndex = response.find("access_token=") + len("access_token=")

		endIndex = response.find("&token_type=Beare",startIndex);

		access_token = response[startIndex:endIndex]

		print "\n\n****************** Access Token *********************"
		print "\n \n"
		print access_token
		print "\n \n"
		print "****************** Access Token *********************\n\n"


else:

	print "*Error* Please include exact 5 arguments in order -> Org Url, UserName, ClientId, RedirectUri and TokenType"
