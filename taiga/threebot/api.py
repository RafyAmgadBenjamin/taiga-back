from uuid import uuid4
import urllib
import json
import nacl.encoding
import nacl.signing
import requests
import base64
from django.conf import settings
from django.shortcuts import redirect
from nacl.public import Box

from taiga.base.status import HTTP_400_BAD_REQUEST
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from django.utils.translation import ugettext as _
from django.contrib.auth import login
from django.http import JsonResponse, HttpResponse

from taiga.projects.models import Membership
from taiga.users.serializers import UserAdminSerializer, UserSerializer

# from taiga.auth.tokens import get_token_for_user
from taiga.external_apps.models import ApplicationToken
from taiga.base import response
from django.db.models import Q

from taiga.external_apps.auth_backends import Token
from taiga.base.exceptions import NotAuthenticated
from django.contrib.auth import login
from taiga.base import exceptions as exc
from taiga.base.exceptions import ValidationError

from django.contrib.sessions.backends.db import SessionStore
from taiga.auth.api import AuthViewSet


def check_registered(username, email):
    user_model = get_user_model()
    res = user_model.objects.filter(username=username)
    if res:
        return res[0]

    res = user_model.objects.filter(email=email)
    if res:
        return res[0]


def get_threebot_url(req):
    # req.session.set_test_cookie()

    private_key = nacl.signing.SigningKey(settings.PRIVATE_KEY, encoder=nacl.encoding.Base64Encoder)
    public_key = private_key.verify_key

    state = str(uuid4()).replace("-", "")
    req.session["threebot_state"] = state

    # print(f'###the state {req.session.get("threebot_state")}')
    req.session.modified = True
    req.session.save()

    # params = {
    #     "state": state,
    #     "appid": settings.SITES["api"]["domain"],
    #     "scope": '{"user": true, "email": true}',
    #     "redirecturl": "/api/v1/auth/callback",
    #     "publickey": public_key.to_curve25519_public_key().encode(encoder=nacl.encoding.Base64Encoder),
    # }
    params = {
        "state": state,
        "appid": settings.SITES["front"]["domain"],
        "scope": '{"user": true, "email": true}',
        "redirecturl": "/threebot",
        "publickey": public_key.to_curve25519_public_key().encode(encoder=nacl.encoding.Base64Encoder),
    }
    # params = {
    #     "state": state,
    #     "appid": settings.SITES["front"]["domain"],
    #     "scope": '{"user": true, "email": true}',
    #     "redirecturl": "/auth/callback",
    #     "publickey": public_key.to_curve25519_public_key().encode(encoder=nacl.encoding.Base64Encoder),
    # }

    return JsonResponse({"url": "{0}?{1}".format(settings.THREEBOT_URL, urllib.parse.urlencode(params))})


# TODO: I need remove this after testing
def test_session(req):
    # print(f'###### session test {req.session.get("threebot_state")}')
    return HttpResponse(status=200)


def callback(req):
    # import ipdb

    # ipdb.set_trace()
    if req.method == "OPTIONS":
        return HttpResponse(status=200)

    # try:
    #     t = Token()

    #     user, _ = t.authenticate(req)
    #     print(f"########## the user object after authentication trial {user}")

    #     if user:
    #         login(req, user)
    # # except NotAuthenticated:
    # except:
    #     pass

    data = req.GET.get("signedAttempt")
    if not data:
        return JsonResponse(
            {"_error_message": "one or more parameter values were missing (signedAttempt)", "_error_type": ""},
            status=400,
        )

    data = json.loads(data)
    username = data["doubleName"]
    if not username:
        return JsonResponse({"_error_message": "Bad request, some params are missing", "_error_type": ""}, status=400)

    res = requests.get(settings.THREEBOT_URL + "/api/users/{0}".format(username), {"Content-Type": "application/json"})

    if res.status_code != 200:
        return JsonResponse({"_error_message": "Error getting user pub key", "_error_type": ""}, status=400)

    user_pub_key = nacl.signing.VerifyKey(res.json()["publicKey"], encoder=nacl.encoding.Base64Encoder)
    pk = res.json()["publicKey"]

    # verify data
    signedData = data["signedAttempt"]
    if not signedData:
        return JsonResponse({"_error_message": "Bad request, some params are missing", "_error_type": ""}, status=400)

    verifiedData = user_pub_key.verify(base64.b64decode(signedData)).decode()

    data = json.loads(verifiedData)

    if not data:
        return JsonResponse({"_error_message": "Bad request, some params are missing", "_error_type": ""}, status=400)

    if data["doubleName"] != username:
        return JsonResponse({"_error_message": "Bad request, some params are missing", "_error_type": ""}, status=400)

    # verify state
    state = data["signedState"]
    # print(f'###### after call back session{req.session.get("threebot_state")}')

    # TODO: State verification for now is disabled
    # if not state or state != req.session.get("threebot_state"):
    #     return JsonResponse({"_error_message": "Invalid state", "_error_type": ""}, status=400)

    nonce = base64.b64decode(data["data"]["nonce"])
    ciphertext = base64.b64decode(data["data"]["ciphertext"])

    private_key = nacl.signing.SigningKey(settings.PRIVATE_KEY, encoder=nacl.encoding.Base64Encoder)

    box = Box(private_key.to_curve25519_private_key(), user_pub_key.to_curve25519_public_key())
    try:
        decrypted = box.decrypt(ciphertext, nonce)
        result = json.loads(decrypted)
        email = result["email"]["email"]

        sei = result["email"]["sei"]
        res = requests.post(
            settings.OPEN_KYC_URL, headers={"Content-Type": "application/json"}, json={"signedEmailIdentifier": sei}
        )
        if res.status_code != 200:
            return JsonResponse({"_error_message": "Email not verified", "_error_type": ""}, status=400)

        # user_model = get_user_model()

        # users_with_email = user_model.objects.filter(email=email)
        # if users_with_email:
        #     user_with_email = users_with_email[0]
        # else:
        #     user_with_email = None

        # Link user to 3bot login account
    #     print(f"############### check if the user is_authenticated {req.user.is_authenticated}")
    #     if req.user.is_authenticated:
    #         user = user_model.objects.filter(id=req.user.id)[0]
    #         if user_with_email and user_with_email.id != req.user.id:
    #             return JsonResponse(
    #                 {"_error_message": "Email address is linked with another active account", "_error_type": ""},
    #                 status=400,
    #             )
    #         # user already linked with 3 bot login
    #         if user.public_key:
    #             # user linking another account
    #             if user.public_key != pk:
    #                 user.email = email
    #                 user.public_key = pk
    #                 user.threebot_name = username.replace(".3bot", "")
    #                 user.save()
    #         else:
    #             # user linking their account for first time
    #             user.email = email
    #             user.public_key = pk
    #             user.threebot_name = username.replace(".3bot", "")
    #             user.save()
    #     else:
    #         users = user_model.objects.filter(Q(email=email) | Q(public_key=pk))
    #         # users = user_model.objects.filter(Q(email=email))
    #         if len(users) == 0:
    #             # new user
    #             username = username.replace(".3bot", "")
    #             user = user_model(username=username, email=email, full_name=username, public_key=pk)
    #             # user = user_model(username=username, email=email, full_name=username)
    #             user.is_active = True
    #             user.public_key = pk
    #             user.threebot_name = username
    #             user.save()
    #         else:
    #             # email or public key exists
    #             user = users[0]
    #             if user.public_key != pk:
    #                 user.public_key = pk
    #                 user.threebot_name = username.replace(".3bot", "")
    #                 user.save()
    #             elif user.email != email:
    #                 user.email = email
    #                 user.threebot_name = username.replace(".3bot", "")
    #                 user.save()
    #     login(req, user)
    except:
        raise
    # serializer = UserAdminSerializer(user)
    # applicationToken = ApplicationToken()
    # import ipdb

    # ipdb.set_trace()
    auth_apis = AuthViewSet()
    req.DATA = {}

    req.DATA["username"] = "test"
    req.DATA["password"] = "test1234"
    req.DATA["type"] = "normal"
    # req.DATA["username"] = username.replace(".3bot", "")
    # req.DATA["password"] = email
    # req.DATA["type"] = "normal"
    auth_apis.create(req)
    data = []
    # data = dict(serializer.data)
    # data["auth_token"] = applicationToken.generate_token()
    # data["public_key"] = pk
    # data["email"] = email
    # data["threebot_name"] = username.replace(".3bot", "")
    # data["roles"] = [role for role in data["roles"]]
    return JsonResponse(data)


# def callback(req):
#     import ipdb

#     ipdb.set_trace()
#     if req.method == "OPTIONS":
#         return HttpResponse(status=200)

#     try:
#         t = Token()

#         user, _ = t.authenticate(req)
#         print(f"########## the user object after authentication trial {user}")

#         if user:
#             login(req, user)
#     # except NotAuthenticated:
#     except:
#         pass

#     data = req.GET.get("signedAttempt")
#     if not data:
#         return JsonResponse(
#             {"_error_message": "one or more parameter values were missing (signedAttempt)", "_error_type": ""},
#             status=400,
#         )

#     data = json.loads(data)
#     username = data["doubleName"]
#     if not username:
#         return JsonResponse({"_error_message": "Bad request, some params are missing", "_error_type": ""}, status=400)

#     res = requests.get(settings.THREEBOT_URL + "/api/users/{0}".format(username), {"Content-Type": "application/json"})

#     if res.status_code != 200:
#         return JsonResponse({"_error_message": "Error getting user pub key", "_error_type": ""}, status=400)

#     user_pub_key = nacl.signing.VerifyKey(res.json()["publicKey"], encoder=nacl.encoding.Base64Encoder)
#     pk = res.json()["publicKey"]

#     # verify data
#     signedData = data["signedAttempt"]
#     if not signedData:
#         return JsonResponse({"_error_message": "Bad request, some params are missing", "_error_type": ""}, status=400)

#     verifiedData = user_pub_key.verify(base64.b64decode(signedData)).decode()

#     data = json.loads(verifiedData)

#     if not data:
#         return JsonResponse({"_error_message": "Bad request, some params are missing", "_error_type": ""}, status=400)

#     if data["doubleName"] != username:
#         return JsonResponse({"_error_message": "Bad request, some params are missing", "_error_type": ""}, status=400)

#     # verify state
#     state = data["signedState"]
#     # print(f'###### after call back session{req.session.get("threebot_state")}')

#     # TODO: State verification for now is disabled
#     # if not state or state != req.session.get("threebot_state"):
#     #     return JsonResponse({"_error_message": "Invalid state", "_error_type": ""}, status=400)

#     nonce = base64.b64decode(data["data"]["nonce"])
#     ciphertext = base64.b64decode(data["data"]["ciphertext"])

#     private_key = nacl.signing.SigningKey(settings.PRIVATE_KEY, encoder=nacl.encoding.Base64Encoder)

#     box = Box(private_key.to_curve25519_private_key(), user_pub_key.to_curve25519_public_key())
#     try:
#         decrypted = box.decrypt(ciphertext, nonce)
#         result = json.loads(decrypted)
#         email = result["email"]["email"]

#         sei = result["email"]["sei"]
#         res = requests.post(
#             settings.OPEN_KYC_URL, headers={"Content-Type": "application/json"}, json={"signedEmailIdentifier": sei}
#         )
#         if res.status_code != 200:
#             return JsonResponse({"_error_message": "Email not verified", "_error_type": ""}, status=400)

#         user_model = get_user_model()

#         users_with_email = user_model.objects.filter(email=email)
#         if users_with_email:
#             user_with_email = users_with_email[0]
#         else:
#             user_with_email = None

#         # Link user to 3bot login account
#         print(f"############### check if the user is_authenticated {req.user.is_authenticated}")
#         if req.user.is_authenticated:
#             user = user_model.objects.filter(id=req.user.id)[0]
#             if user_with_email and user_with_email.id != req.user.id:
#                 return JsonResponse(
#                     {"_error_message": "Email address is linked with another active account", "_error_type": ""},
#                     status=400,
#                 )
#             # user already linked with 3 bot login
#             if user.public_key:
#                 # user linking another account
#                 if user.public_key != pk:
#                     user.email = email
#                     user.public_key = pk
#                     user.threebot_name = username.replace(".3bot", "")
#                     user.save()
#             else:
#                 # user linking their account for first time
#                 user.email = email
#                 user.public_key = pk
#                 user.threebot_name = username.replace(".3bot", "")
#                 user.save()
#         else:
#             users = user_model.objects.filter(Q(email=email) | Q(public_key=pk))
#             # users = user_model.objects.filter(Q(email=email))
#             if len(users) == 0:
#                 # new user
#                 username = username.replace(".3bot", "")
#                 user = user_model(username=username, email=email, full_name=username, public_key=pk)
#                 # user = user_model(username=username, email=email, full_name=username)
#                 user.is_active = True
#                 user.public_key = pk
#                 user.threebot_name = username
#                 user.save()
#             else:
#                 # email or public key exists
#                 user = users[0]
#                 if user.public_key != pk:
#                     user.public_key = pk
#                     user.threebot_name = username.replace(".3bot", "")
#                     user.save()
#                 elif user.email != email:
#                     user.email = email
#                     user.threebot_name = username.replace(".3bot", "")
#                     user.save()
#         login(req, user)
#     except:
#         raise
#     serializer = UserAdminSerializer(user)
#     data = dict(serializer.data)
#     applicationToken = ApplicationToken()
#     data["auth_token"] = applicationToken.generate_token()
#     data["public_key"] = pk
#     data["email"] = email
#     data["threebot_name"] = username.replace(".3bot", "")
#     data["roles"] = [role for role in data["roles"]]
#     return JsonResponse(data)
