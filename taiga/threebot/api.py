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

    private_key = nacl.signing.SigningKey(settings.PRIVATE_KEY, encoder=nacl.encoding.Base64Encoder)
    public_key = private_key.verify_key

    state = str(uuid4()).replace("-", "")
    req.session["threebot_state"] = state

    req.session.modified = True
    req.session.save()

    params = {
        "state": state,
        "appid": settings.SITES["front"]["domain"],
        "scope": '{"user": true, "email": true}',
        "redirecturl": "/threebot",
        "publickey": public_key.to_curve25519_public_key().encode(encoder=nacl.encoding.Base64Encoder),
    }

    return JsonResponse({"url": "{0}?{1}".format(settings.THREEBOT_URL, urllib.parse.urlencode(params))})

