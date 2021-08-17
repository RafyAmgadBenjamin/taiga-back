# -*- coding: utf-8 -*-
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2021-present Kaleidos Ventures SL

from functools import partial

from django.utils.translation import ugettext as _
from django.conf import settings
from django.contrib.auth import get_user_model


from taiga.base import exceptions as exc
from taiga.base import response
from taiga.base.api import viewsets
from taiga.base.decorators import list_route
from taiga.projects.services.invitations import accept_invitation_by_existing_user
from taiga.users.serializers import UserAdminSerializer, UserSerializer

from . import serializers
from .authentication import AUTH_HEADER_TYPES
from .permissions import AuthPermission
from .services import private_register_for_new_user
from .services import public_register
from .services import make_auth_response_data
from .services import get_auth_plugins
from .throttling import LoginFailRateThrottle, RegisterSuccessRateThrottle
from django.http import JsonResponse, HttpResponse
import requests
import nacl.encoding
import nacl.signing
from nacl.public import Box
import json
import base64


# from rest_framework.decorators import authentication_classes, permission_classes
# from rest_framework.decorators import api_view
# from taiga.base.api.permissions import AllowAny


def _validate_data(data: dict, *, cls):
    """
    Generic function for parse and validate user
    data using specified validator on `cls`
    keyword parameter.

    Raises: RequestValidationError exception if
    some errors found when data is validated.
    """

    validator = cls(data=data)
    if not validator.is_valid():
        raise exc.RequestValidationError(validator.errors)
    return validator.object


get_token = partial(_validate_data, cls=serializers.TokenObtainPairSerializer)
refresh_token = partial(_validate_data, cls=serializers.TokenRefreshSerializer)
verify_token = partial(_validate_data, cls=serializers.TokenVerifySerializer)
parse_public_register_data = partial(_validate_data, cls=serializers.PublicRegisterSerializer)
parse_private_register_data = partial(_validate_data, cls=serializers.PrivateRegisterSerializer)


class AuthViewSet(viewsets.ViewSet):
    permission_classes = (AuthPermission,)
    throttle_classes = (LoginFailRateThrottle, RegisterSuccessRateThrottle)

    serializer_class = None

    www_authenticate_realm = "api"

    def get_authenticate_header(self, request):
        return '{0} realm="{1}"'.format(AUTH_HEADER_TYPES[0], self.www_authenticate_realm)

    # Login view: /api/v1/auth
    def create(self, request, **kwargs):

        self.check_permissions(request, "get_token", None)
        auth_plugins = get_auth_plugins()

        login_type = request.DATA.get("type", "").lower()

        if login_type == "normal":
            # Default login process
            data = get_token(request.DATA)
        elif login_type in auth_plugins:
            data = auth_plugins[login_type]["login_func"](request)
        else:
            raise exc.BadRequest(_("invalid login type"))
        if data:
            self.auth_token = data.get("auth_token", None)
        # Processing invitation token
        invitation_token = request.DATA.get("invitation_token", None)
        if invitation_token:
            accept_invitation_by_existing_user(invitation_token, data["id"])

        return response.Ok(data)

    # Refresh token view: /api/v1/auth/refresh
    @list_route(methods=["POST"])
    def refresh(self, request, **kwargs):

        self.check_permissions(request, "refresh_token", None)
        data = refresh_token(request.DATA)
        return response.Ok(data)

    # Validate token view: /api/v1/auth/verify
    @list_route(methods=["POST"])
    def verify(self, request, **kwargs):
        if not settings.DEBUG:
            return response.Forbidden()

        self.check_permissions(request, "verify_token", None)
        data = verify_token(request.DATA)
        return response.Ok(data)

    def _public_register(self, request):
        if not settings.PUBLIC_REGISTER_ENABLED:
            raise exc.BadRequest(_("Public registration is disabled."))

        try:
            data = parse_public_register_data(request.DATA)
            user = public_register(**data)
        except exc.IntegrityError as e:
            raise exc.BadRequest(e.detail)

        data = make_auth_response_data(user)
        return response.Created(data)

    def _private_register(self, request):
        data = parse_private_register_data(request.DATA)
        user = private_register_for_new_user(**data)

        data = make_auth_response_data(user)
        return response.Created(data)

    # Register user: /api/v1/auth/register
    @list_route(methods=["POST"])
    def register(self, request, **kwargs):
        accepted_terms = request.DATA.get("accepted_terms", None)
        if accepted_terms in (None, False):
            raise exc.BadRequest(_("You must accept our terms of service and privacy policy"))

        self.check_permissions(request, "register", None)

        type = request.DATA.get("type", None)
        # self.auth_token = data.get("auth_token", None)
        if type == "public":
            return self._public_register(request)
        elif type == "private":
            return self._private_register(request)
        raise exc.BadRequest(_("invalid registration type"))

    # /api/v1/auth/callback

    # @action(methods=["GET"], detail=False, permission_classes=[])
    @list_route(methods=["GET"])
    def callback(self, request, **kwargs):
        # import ipdb

        # ipdb.set_trace()
        # username = request.QUERY_PARAMS.get("username", None)

        # if request.method == "OPTIONS":
        #     return HttpResponse(status=200)
        username, email, pk = self._verify_callback_data(request)
        try:
            # Authenticate User
            # create_resp = self._threebot_auth(request, username, email)
            # Authenticate User
            print("User is being authenticated")
            # import ipdb

            # ipdb.set_trace()
            self._threebot_auth(request, username, email)
            user = self._get_user_default_data(username, email)
            user = self._update_user_default_data(user, pk)
            return self._get_response(user)
        except Exception as e:
            print(f"The User can't be authenticated  {e}")
            try:
                # Register User
                print("User is being registered")
                return self._threebot_register(request, username, email)
                # return self._get_response(username, email)
            except Exception as e:
                print(f"The User can't be authenticated or registered  {e}")
                # raise e

        return

        # data = {}
        # return response.Ok(data)

    def _threebot_auth(self, request, username, email):
        _mutable = request.DATA._mutable
        request.DATA._mutable = True
        request.DATA["username"] = username
        request.DATA["password"] = email
        request.DATA["type"] = "normal"
        request.DATA._mutable = _mutable
        return self.create(request)

    def _threebot_register(self, request, username, email):
        _mutable = request.DATA._mutable
        request.DATA._mutable = True
        request.DATA["type"] = "public"
        request.DATA["username"] = username
        request.DATA["password"] = email
        request.DATA["accepted_terms"] = True
        request.DATA["full_name"] = username
        request.DATA["email"] = email
        request.DATA._mutable = _mutable
        return self.register(request)

    def _get_user_default_data(self, username, email):
        user_model = get_user_model()
        res = user_model.objects.filter(username=username)
        if res:
            return res[0]

        res = user_model.objects.filter(email=email)
        if res:
            return res[0]

    def _update_user_default_data(self, user, pk):
        user.is_active = True
        user.public_key = pk
        user.threebot_name = user.username
        user.save()
        return user

    def _get_response(self, user):
        serializer = UserAdminSerializer(user)
        data = dict(serializer.data)
        data["auth_token"] = self.auth_token
        data["email"] = user.email
        data["threebot_name"] = user.username
        data["public_key"] = user.public_key
        data["threebot_name"] = user.username
        # data["roles"] = [role for role in data["roles"]]
        return response.Ok(data)

    def _verify_callback_data(self, req):
        username = ""
        email = ""
        data = req.GET.get("signedAttempt")
        if not data:
            return JsonResponse(
                {"_error_message": "one or more parameter values were missing (signedAttempt)", "_error_type": ""},
                status=400,
            )

        data = json.loads(data)
        username = data["doubleName"]
        if not username:
            return JsonResponse(
                {"_error_message": "Bad request, some params are missing", "_error_type": ""}, status=400
            )

        res = requests.get(
            settings.THREEBOT_URL + "/api/users/{0}".format(username), {"Content-Type": "application/json"}
        )

        if res.status_code != 200:
            return JsonResponse({"_error_message": "Error getting user pub key", "_error_type": ""}, status=400)

        user_pub_key = nacl.signing.VerifyKey(res.json()["publicKey"], encoder=nacl.encoding.Base64Encoder)
        pk = res.json()["publicKey"]

        # verify data
        signedData = data["signedAttempt"]
        if not signedData:
            return JsonResponse(
                {"_error_message": "Bad request, some params are missing", "_error_type": ""}, status=400
            )

        verifiedData = user_pub_key.verify(base64.b64decode(signedData)).decode()

        data = json.loads(verifiedData)

        if not data:
            return JsonResponse(
                {"_error_message": "Bad request, some params are missing", "_error_type": ""}, status=400
            )

        if data["doubleName"] != username:
            return JsonResponse(
                {"_error_message": "Bad request, some params are missing", "_error_type": ""}, status=400
            )

        # verify state
        state = data["signedState"]
        nonce = base64.b64decode(data["data"]["nonce"])
        ciphertext = base64.b64decode(data["data"]["ciphertext"])

        private_key = nacl.signing.SigningKey(settings.PRIVATE_KEY, encoder=nacl.encoding.Base64Encoder)

        box = Box(private_key.to_curve25519_private_key(), user_pub_key.to_curve25519_public_key())
        try:
            decrypted = box.decrypt(ciphertext, nonce)
            result = json.loads(decrypted)
            # nonlocal email

            email = result["email"]["email"]

            sei = result["email"]["sei"]
            res = requests.post(
                settings.OPEN_KYC_URL, headers={"Content-Type": "application/json"}, json={"signedEmailIdentifier": sei}
            )
            if res.status_code != 200:
                return JsonResponse({"_error_message": "Email not verified", "_error_type": ""}, status=400)

        except:
            raise

        return username.replace(".3bot", ""), email, pk

