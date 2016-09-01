# Okta-OpenId-Scripts

Two scripts demonstrate using OAuth Implicit and Authorization Code flow. You can run these two scripts to see how calls are 
made to retrieve the id token and/or access token.

# Pre-requisites

In order to run the scripts you would need following

1) cURL 


2) Python 2.7 


3) Python's "requests" library  

# Note

The scripts need to obtain sessionToken via primary authentication for your Okta org. These scripts do not take care of Multifactor
authentication. Therefore, please turn Off MFA polciies on your org before running the scripts. Otherwise, scripts will fail. 

# Usage and Examples.

1) Implicit Flow (ImplicitFlow.py)

This script generates Id Token or Access Token based on the response_type (does not support hybrid at the moment). You would need to 
provide all of following input to the script in the same order 

i) Org url (for example org-name.okta.com or org-name.oktapreview.com)

ii) Username (Okta user for whom you would want to generate the id or access token e.g. username@example.com)

iii) Client ID (Client Id from Open ID app in Okta)

iv) Redirect URI (Redirect URI same as set in Open ID app whose client id you will use as input)

v) Token Type (It can be either id_token or token (for access token))

Examples:

python ImplicitFlow.py orgname.okta.com username@examplee.com <clientId> <redirectUri> id_token -> For Id Token
python ImplicitFlow.py orgname.okta.com username@examplee.com <clientId> <redirectUri> token -> For Access Token
python ImplicitFlow.py orgname.oktapreview.com.com username@examplee.com <clientId> <redirectUri> token -> Access token for preview org





1) Authorization Code Flow (AuthorizationCodeFlow.py)

This script generates Id Token and Access Token via authorization code flow where code is first generated via 
GET  /authorize call that is exchanged for id and access token via POST /token

Please make sure to use Web App for this (not Single Page App) as you would need client secret for this

i) Org url (for example org-name.okta.com or org-name.oktapreview.com)

ii) Username (Okta user for whom you would want to generate the id or access token e.g. username@example.com)

iii) Client ID (Client Id from Open ID app in Okta)

iv) Client Secret (Client Secret from Open ID app in Okta)

v) Redirect URI (Redirect URI same as set in Open ID app whose client id you will use as input)

vi) Token Type (It will always be code)

Examples:

python AuthorizationCodeFlow.py orgname.okta.com username@examplee.com <clientId> <clientSecret> <redirectUri> id_token -> For Id Token

python AuthorizationCodeFlow.py orgname.okta.com username@examplee.com <clientId> <clientSecret>  <redirectUri> token -> For Access Token

python AuthorizationCodeFlow.py orgname.oktapreview.com.com username@examplee.com <clientId> <clientSecret> <redirectUri> token -> Access token for preview org

