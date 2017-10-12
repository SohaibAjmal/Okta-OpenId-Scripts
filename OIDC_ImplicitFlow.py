import requests
import json
import re
import sys
import os
import subprocess
import urllib
import getpass
import base64
import jwt
import urllib2
import argparse


def post_request(url, headers, data):

	response = ""

	try:

	    if data != None:

	        response = requests.post(url, data= data, headers=headers)

	    else:
	    	
	        response = requests.post(url, headers=headers)

	    response =  response.json()

	except Exception as e:

		response = str(e)

	return response
    

def curl_get_request(url):
	
	response = ""

	try:
		
		req = urllib2.Request(url)

		redirect = urllib2.urlopen(req)

		response = str(redirect.geturl())
		
		if response.find("error") > -1:

			errorDescIndex = response.find("error_description=")

			response = response[errorDescIndex:]

			endIndex = response.find(".")

			response = response[:endIndex]

			response = urllib.unquote_plus(response)

		
	except Exception as e:

		exceptionMessage = str(e)

		if exceptionMessage.find("400: Bad Request") > -1:

			response  = "error: Illegal Redirect Uri value error likely\n"

		else:

			response = "error: " + exceptionMessage


	return response

def decode_token(token):

	decodedToken = jwt.decode(token,verify=False)

	tokenJSON = json.dumps(decodedToken, indent = 4)

	return tokenJSON



def request_tokens(**kwargs):

	orgUrl = kwargs['orgUrl']
	userName = kwargs['userName']
	clientId = kwargs['clientId']
	redirectUri = kwargs['redirectUri']
	scopes = kwargs['scopes']
	tokenType = kwargs['tokenType']

	print "Please Enter Password for User Name: " + str(userName)
	password = getpass.getpass()
	

	url = "https://" + orgUrl + "/api/v1/authn"
	redirectUri = urllib.quote_plus(redirectUri)

	credentials  = {
	"username":userName,
	"password":password
	}

	headers = {'Accept':'application/json','Content-Type':'application/json'}
	credentialsJSON = json.dumps(credentials)


	response = post_request(url, headers, credentialsJSON)

	if "sessionToken" in response:
		sessionToken = str(response["sessionToken"])

		authorizeUrl ="https://" + orgUrl + "/oauth2/v1/authorize?sessionToken="+sessionToken+"&client_id="+clientId+"&scope=" + scopes + "&response_type=" + tokenType + "&response_mode=fragment&nonce=staticNonce&redirect_uri="+redirectUri+"&state=staticState"

		response = curl_get_request(authorizeUrl)

		if response.find("error") > -1:

			print "\nGET /authorize call encountered error:\n"

			print response

		else:

			if tokenType == "id_token":

				startIndex = response.find("id_token=") + len("id_token=")

				endIndex = response.find("&state=staticState",startIndex);

				idToken = response[startIndex:endIndex]

				print "\n\n*** Encoded (JWT) Id Token *** \n\n" + str(idToken)

				decodedIdToken = decode_token(idToken)

				print "\n\n*** Decoded Id Token *** \n\n" + str(decodedIdToken)


			elif tokenType == "token":

				startIndex = response.find("access_token=") + len("access_token=")

				endIndex = response.find("&token_type=Bearer",startIndex);

				accessToken = response[startIndex:endIndex]

				print "\n\n*** Encoded (JWT) Access Token *** \n\n" + str(accessToken)

				decodedAccessToken = decode_token(accessToken)

				print "\n\n*** Decoded Access Token *** \n\n" + str(decodedAccessToken)


	elif "stateToken" in response:

		print "\nMFA Enabled for your org: Please disable MFA and try again\n"

	else:

		print "\nError occured during primary authentication\n"
		
		print response
	


if __name__ == "__main__":	

	parser = argparse.ArgumentParser()

	parser.add_argument("-orgUrl",
					help="Example - https://your-domain.okta.com or https://your-domain.oktapreview.com",
					required="True",
					default="https://example.okta.com")

	parser.add_argument("-user",
					help="Okta UserName: user@example.com",
					required="True",
					default="user@example.com")

	parser.add_argument("-clientId",
					help="Okta Open ID Connect Client Id",
					required="True",
					default=":clientId")


	parser.add_argument("-scopes",
					help="Scopes separated with + e.g. openid+profile+email",
					required="True",
					default="openid+profile+email")


	parser.add_argument("-redirectUri",
					help="Redirect Uri registered in OIDC client in Okta",
					required="True",
					default="https://www.google.com/")

	parser.add_argument("-token",
					help="id_token or token for access token)",
					required="True",
					default="id_token")


	arguments = parser.parse_args()


	request_tokens(
			orgUrl=arguments.orgUrl,
			userName = arguments.user,
			clientId = arguments.clientId,
			scopes = arguments.scopes,
			redirectUri = arguments.redirectUri,
			tokenType = arguments.token,
			)


