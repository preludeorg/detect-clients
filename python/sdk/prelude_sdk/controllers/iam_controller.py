from prelude_sdk.controllers.http_controller import HttpController
from prelude_sdk.models.account import Account, verify_credentials
from prelude_sdk.models.codes import Mode, Permission


class IAMController(HttpController):

    def __init__(self, account: Account):
        super().__init__()
        self.account = account

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
    def reset_password(self, email: str):
        """Reset a user's password"""
        body = dict(handle=email)

        res = self._session.post(
            f"{self.account.hq}/iam/user/admin_reset",
            headers=self.account.headers,
            json=body,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

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
        self,
        client_id: str,
        client_secret: str,
        issuer: str,
        oidc_url: str,
        email_attr: str = "email",
    ):
        """Attach OIDC to an account"""
        body = dict(
            client_id=client_id,
            client_secret=client_secret,
            email_attr=email_attr,
            issuer=issuer,
            oidc_url=oidc_url,
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
    def invite_user(
        self,
        email: str,
        oidc: str | None,
        permission: Permission,
        name: str | None = None,
    ):
        """Invite a new user to the account"""
        body = dict(permission=permission.name, handle=email, oidc=oidc)
        if name:
            body["name"] = name

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
    def create_service_user(self, email: str):
        """Create a service user"""
        body = dict(handle=email)

        res = self._session.post(
            f"{self.account.hq}/iam/account/service_user",
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
        name: str = None,
    ):
        """Update properties on a user"""
        body = dict()
        if name is not None:
            body["name"] = name

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
    def update_account_user(
        self,
        email: str,
        oidc: str | None,
        permission: Permission = None,
    ):
        """Update properties on an account user"""
        body = dict(handle=email, oidc=oidc)
        if permission is not None:
            body["permission"] = permission.name

        res = self._session.put(
            f"{self.account.hq}/iam/account/user",
            json=body,
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def remove_user(self, email: str, oidc: str | None):
        """Remove user from the account"""
        params = dict(handle=email, oidc=oidc)

        res = self._session.delete(
            f"{self.account.hq}/iam/account/user",
            params=params,
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def purge_user(self):
        """Delete your user"""
        res = self._session.delete(
            f"{self.account.hq}/iam/user", headers=self.account.headers, timeout=10
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def list_accounts(self):
        """List all accounts for your user"""
        res = self._session.get(
            f"{self.account.hq}/iam/user/account",
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
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
    def get_oidc_name(self, slug: str):
        """Get OIDC provider name from organization slug"""
        params = dict(slug=slug)

        res = self._session.get(
            f"{self.account.hq}/iam/account/oidc",
            headers=self.account.headers,
            params=params,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def new_user_and_account(self, company, email, name):
        """Create a new user and account"""
        body = dict(company=company, email=email, name=name)

        res = self._session.post(
            f"{self.account.hq}/iam/new_user_and_account",
            headers=self.account.headers,
            json=body,
            timeout=10,
        )
        if res.ok:
            return res.json()
        raise Exception(res.text)
