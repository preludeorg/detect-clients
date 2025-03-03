import configparser
import json
import os
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from prelude_sdk.controllers.http_controller import HttpController


class Keychain:

    def __init__(
        self, keychain_location=os.path.join(Path.home(), ".prelude", "keychain.ini")
    ):
        self.keychain_location = keychain_location
        if not os.path.exists(self.keychain_location):
            head, _ = os.path.split(Path(self.keychain_location))
            Path(head).mkdir(parents=True, exist_ok=True)
            open(self.keychain_location, "x").close()
            self.configure_keychain("", "")

    def read_keychain(self):
        cfg = configparser.ConfigParser()
        cfg.read(self.keychain_location)
        return cfg

    def configure_keychain(
        self,
        account,
        handle,
        hq="https://api.us1.preludesecurity.com",
        profile="default",
    ):
        cfg = self.read_keychain()
        cfg[profile] = {"account": account, "handle": handle, "hq": hq}
        with open(self.keychain_location, "w") as f:
            cfg.write(f)

    def get_profile(self, profile="default"):
        try:
            cfg = self.read_keychain()
            profile = next(s for s in cfg.sections() if s == profile)
            return cfg[profile]
        except StopIteration:
            raise Exception(
                "Could not find profile %s for account in %s"
                % (profile, self.keychain_location)
            )


class Account(HttpController):

    def __init__(
        self,
        account: str,
        handle: str,
        hq: str,
        profile: str | None = None,
        token: str | None = None,
        token_location: str | None = os.path.join(
            Path.home(), ".prelude", "tokens.json"
        ),
    ):
        if not any([token, token_location]):
            raise ValueError("Please provide either an ID token or a token location")

        super().__init__()
        self.account = account
        self.handle = handle
        self.headers = dict(account=account, _product="py-sdk")
        self.hq = hq
        self.keychain = Keychain()
        self.profile = profile
        self.token = token
        self.token_location = token_location
        if self.token_location and not os.path.exists(self.token_location):
            head, _ = os.path.split(Path(self.token_location))
            Path(head).mkdir(parents=True, exist_ok=True)
            with open(self.token_location, "x") as f:
                json.dump({}, f)

    @staticmethod
    def from_keychain(profile: str = "default"):
        profile_items = dict(Keychain().get_profile(profile).items())
        if "token" in profile_items or "handle" not in profile_items:
            raise ValueError("Please make sure you are using an up-to-date profile")
        return Account(**profile_items, profile=profile)

    @staticmethod
    def from_params(
        account: str, handle: str, hq: str = "https://api.us1.preludesecurity.com"
    ):
        return Account(account, handle, hq)

    @staticmethod
    def from_token(
        account: str,
        handle: str,
        token: str,
        hq: str = "https://api.us1.preludesecurity.com",
    ):
        return Account(account, handle, hq, token=token, token_location=None)

    def _read_tokens(self):
        with open(self.token_location, "r") as f:
            return json.load(f)

    def _save_new_token(self, new_tokens):
        existing_tokens = self._read_tokens()
        if self.handle not in existing_tokens:
            existing_tokens[self.handle] = dict()
        existing_tokens[self.handle][self.hq] = new_tokens
        with open(self.token_location, "w") as f:
            json.dump(existing_tokens, f)

    def _verify(self):
        if not self.token_location:
            raise ValueError("Please provide a token location to continue")
        if self.profile and not any([self.handle, self.account]):
            raise ValueError(
                "Please configure your %s profile to continue" % self.profile
            )

    def password_login(self, password):
        self._verify()
        res = self._session.post(
            f"{self.hq}/iam/token",
            headers=self.headers,
            json=dict(
                auth_flow="password",
                handle=self.handle,
                password=password,
            ),
            timeout=10,
        )
        if not res.ok:
            raise Exception("Error logging in using password: %s" % res.text)
        self._save_new_token(res.json())

    def refresh_tokens(self):
        self._verify()
        existing_tokens = self._read_tokens().get(self.handle, {}).get(self.hq, {})
        if not (refresh_token := existing_tokens.get("refresh_token")):
            raise Exception("No refresh token found, please login first to continue")
        res = self._session.post(
            f"{self.hq}/iam/token",
            headers=self.headers,
            json=dict(
                auth_flow="refresh",
                handle=self.handle,
                refresh_token=refresh_token,
            ),
            timeout=10,
        )
        if not res.ok:
            raise Exception(
                "Error refreshing token: %s. Please reauthenticate to obtain a new refresh token."
                % res.text
            )
        self._save_new_token(existing_tokens | res.json())

    def get_token(self):
        if self.token:
            return self.token

        tokens = self._read_tokens().get(self.handle, {}).get(self.hq, {})
        if "token" not in tokens:
            raise Exception("Please login to continue")
        if float(tokens["expires"]) < datetime.now(timezone.utc).timestamp():
            self.refresh_tokens()
            return self.get_token()
        return tokens["token"]


def verify_credentials(func):
    @wraps(verify_credentials)
    def handler(*args, **kwargs):
        args[0].account.headers = args[0].account.headers | dict(
            authorization=f"Bearer {args[0].account.get_token()}"
        )
        return func(*args, **kwargs)

    handler.__wrapped__ = func
    return handler
