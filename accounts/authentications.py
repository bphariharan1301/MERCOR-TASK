from rest_framework.authentication import BaseAuthentication
from accounts.exceptions import *
from django.contrib.auth.models import User
import firebase_admin
from firebase_admin import credentials, auth, exceptions
from django.conf import settings




# Firebase Creds

cred = credentials.Certificate({
        "type" : settings.FIREBASE_ACCOUNT_TYPE,
        "project_id" : settings.FIREBASE_PROJECT_ID,
        "private_key_id" : settings.FIREBASE_PRIVATE_KEY_ID,
        "private_key" : settings.FIREBASE_PRIVATE_KEY.replace('\\n', '\n'),
        "client_email" : settings.FIREBASE_CLIENT_EMAIL,
        "client_id" : settings.FIREBASE_CLIENT_ID,
        "auth_uri" : settings.FIREBASE_AUTH_URI,
        "token_uri" : settings.FIREBASE_TOKEN_URI,
        "auth_provider_x509_cert_url" : settings.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
        "client_x509_cert_url" : settings.FIREBASE_CLIENT_X509_CERT_URL
})

default_app = firebase_admin.initialize_app(cred)

# Firebase auth
def Firebase_validation(id_token):
   """
   This function receives id token sent by Firebase and
   validate the id token then check if the user exist on
   Firebase or not if exist it returns True else False
   """
   try:
       decoded_token = auth.verify_id_token(id_token)
       uid = decoded_token['uid']
       provider = decoded_token['firebase']['sign_in_provider']
       image = None
       name = None
       if "name" in decoded_token:
           name = decoded_token['name']
       if "picture" in decoded_token:
           image = decoded_token['picture']
       try:
           user = auth.get_user(uid)
           email = user.email
           if user:
               return {
                   "status": True,
                   "uid": uid,
                   "email": email,
                   "name": name,
                   "provider": provider,
                   "image": image
               }
           else:
               return False
       except UserNotFoundError:
           print("user not exist")
   except InvalidAuthToken:
       print("invalid token")