import datetime
import logging

from prelude_sdk.controllers.http_controller import HttpController

from prelude_sdk.models.account import verify_credentials
from prelude_sdk.models.codes import AuditEvent, Mode, Permission


class IAMController(HttpController):

    def __init__(self, account):
        super().__init__()
        self.account = account

    def migrate(self):
        cfg = self.account.read_keychain_config()
        for section in cfg.sections():
            res = self._session.get(
                f"{cfg.get(section, 'hq')}/iam/account",
                headers=dict(
                    account=cfg.get(section, "account"),
                    token=cfg.get(section, "token"),
                    _product="py-sdk",
                ),
                timeout=10,
            )
            if res.status_code == 200:
                cfg[section]["handle"] = res.json()["whoami"]
            else:
                logging.warning(f"Failed to migrate {section}: {res.text}")
        self.account.write_keychain_config(cfg)
        return [], "Succesfully migrated keychain"

    @verify_credentials
    def new_account(
        self, user_email: str, company: str, user_name: str = None, slug: str = None
    ):
        body = dict(handle=user_email, company=company)
        if user_name:
            body["user_name"] = user_name
        if slug:
            body["slug"] = slug

        res = self._session.post(
            url=f"{self.account.hq}/iam/account",
            json=body,
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code != 200:
            raise Exception(res.text)

        cfg = self.account.read_keychain_config()
        res_json = res.json()
        cfg[self.account.profile]["account"] = res_json["account_id"]
        cfg[self.account.profile]["token"] = res_json["token"]
        self.account.write_keychain_config(cfg)
        return res_json

    @verify_credentials
    def purge_account(self):
        """Delete an account and all things in it"""
        res = self._session.delete(
            f"{self.account.hq}/iam/account", headers=self.account.headers, timeout=10
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def update_account(self, mode: Mode = None, company: str = None, slug: str = None):
        """Update properties on an account"""
        body = dict()
        if mode is not None:
            body["mode"] = mode.name
        if company is not None:
            body["company"] = company
        if slug is not None:
            body["slug"] = slug

        res = self._session.put(
            f"{self.account.hq}/iam/account",
            headers=self.account.headers,
            json=body,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def attach_oidc(
        self, issuer: str, client_id: str, client_secret: str, oidc_config_url: str
    ):
        """Attach OIDC to an account"""
        body = dict(
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            oidc_config_url=oidc_config_url,
        )

        res = self._session.post(
            f"{self.account.hq}/iam/account/oidc",
            headers=self.account.headers,
            json=body,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def detach_oidc(self):
        """Detach OIDC to an account"""
        res = self._session.delete(
            f"{self.account.hq}/iam/account/oidc",
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def get_account(self):
        """Get account properties"""
        res = self._session.get(
            f"{self.account.hq}/iam/account", headers=self.account.headers, timeout=10
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def create_user(
        self,
        permission: Permission,
        email: str,
        expires: datetime = None,
        name: str = None,
        oidc: bool = False,
    ):
        """Create a new user inside an account"""
        body = dict(permission=permission.name, handle=email, oidc=oidc)
        if name:
            body["name"] = name
        if expires:
            body["expires"] = expires.isoformat()

        res = self._session.post(
            url=f"{self.account.hq}/iam/user",
            json=body,
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def update_user(
        self,
        email: str,
        permission: Permission = None,
        expires: datetime = None,
        name: str = None,
        oidc: bool = False,
    ):
        """Update properties on a user"""
        body = dict(handle=email)
        if permission is not None:
            body["permission"] = permission.name
        if expires:
            body["expires"] = expires.isoformat()
        if name is not None:
            body["name"] = name
        if oidc is not None:
            body["oidc"] = oidc

        res = self._session.put(
            f"{self.account.hq}/iam/user",
            json=body,
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def delete_user(self, handle):
        """Delete a user from an account"""
        res = self._session.delete(
            f"{self.account.hq}/iam/user",
            json=dict(handle=handle),
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def reset_password(self, email: str, account_id: str = None):
        """Reset a user's password"""
        data = dict(
            account_id=account_id or self.account.headers["account"], handle=email
        )
        res = self._session.post(
            f"{self.account.hq}/iam/user/reset", json=data, timeout=10
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def verify_user(self, token: str):
        """Verify a user"""
        params = dict(token=token, request_credentials="true")
        res = self._session.get(
            f"{self.account.hq}/iam/user", params=params, timeout=10
        )
        if res.status_code == 200:
            cfg = self.account.read_keychain_config()
            res_json = res.json()
            cfg[self.account.profile]["account"] = res_json["account"]
            cfg[self.account.profile]["token"] = res_json["token"]
            self.account.write_keychain_config(cfg)
            return res_json
        raise Exception(res.text)

    @verify_credentials
    def audit_logs(self, days: int = 7, limit: int = 1000):
        """Get audit logs from the last X days"""
        params = dict(days=days, limit=limit)
        res = self._session.get(
            f"{self.account.hq}/iam/audit",
            headers=self.account.headers,
            params=params,
            timeout=30,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def subscribe(self, event: AuditEvent):
        """Subscribe to email notifications for an event"""
        res = self._session.post(
            f"{self.account.hq}/iam/subscribe/{event.name}",
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def unsubscribe(self, event: AuditEvent):
        """Unsubscribe to email notifications for an event"""
        res = self._session.delete(
            f"{self.account.hq}/iam/subscribe/{event.name}",
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def accept_terms(self, name, version):
        """Accept terms and conditions"""
        res = self._session.post(
            f"{self.account.hq}/iam/terms",
            headers=self.account.headers,
            json=dict(name=name, version=version),
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)
