from datetime import datetime, timezone

from prelude_sdk.controllers.http_controller import HttpController
from prelude_sdk.models.account import Account, verify_credentials
from prelude_sdk.models.codes import Control


class PartnerController(HttpController):

    def __init__(self, account: Account):
        super().__init__()
        self.account = account

    @verify_credentials
    def attach(
        self,
        partner: Control,
        api: str,
        user: str,
        secret: str,
        name: str | None = None,
        instance_id: str | None = None,
    ):
        """Attach a partner to your account"""
        params = dict()
        if name:
            params["name"] = name
        if api:
            params["api"] = api
        if user:
            params["user"] = user
        if secret:
            params["secret"] = secret
        extra = f"/{instance_id}" if instance_id else ""
        res = self._session.post(
            f"{self.account.hq}/partner/{partner.name}{extra}",
            headers=self.account.headers,
            json=params,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def detach(self, partner: Control, instance_id: str):
        """Detach a partner from your Detect account"""
        res = self._session.delete(
            f"{self.account.hq}/partner/{partner.name}/{instance_id}",
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def block(self, partner: Control, test_id: str):
        """Report to a partner to block a test"""
        params = dict(test_id=test_id)
        res = self._session.post(
            f"{self.account.hq}/partner/block/{partner.name}",
            headers=self.account.headers,
            json=params,
            timeout=30,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def endpoints(
        self,
        partner: Control,
        platform: str,
        hostname: str = "",
        offset: int = 0,
        count: int = 100,
    ):
        """Get a list of endpoints from a partner"""
        params = dict(platform=platform, hostname=hostname, offset=offset, count=count)
        res = self._session.get(
            f"{self.account.hq}/partner/endpoints/{partner.name}",
            headers=self.account.headers,
            params=params,
            timeout=30,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def deploy(self, partner: Control, host_ids: list):
        """Deploy probes on all specified partner endpoints"""
        params = dict(host_ids=host_ids)
        res = self._session.post(
            f"{self.account.hq}/partner/deploy/{partner.name}",
            headers=self.account.headers,
            json=params,
            timeout=30,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def list_reports(self, partner: Control, test_id: str | None):
        """Get reports to a partner for a test"""
        params = dict(test_id=test_id) if test_id else dict()
        res = self._session.get(
            f"{self.account.hq}/partner/reports/{partner.name}",
            headers=self.account.headers,
            json=params,
            timeout=30,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def ioa_stats(self, test_id: str | None = None):
        """Get IOA stats"""
        params = dict(test_id=test_id) if test_id else dict()
        res = self._session.get(
            f"{self.account.hq}/partner/ioa_stats",
            headers=self.account.headers,
            json=params,
            timeout=30,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def observed_detected(self, test_id: str | None = None, hours: int | None = None):
        """Get observed_detected stats"""
        params = dict()
        if test_id:
            params["test_id"] = test_id
        if hours:
            params["start_epoch_ms"] = (
                datetime.now(timezone.utc).timestamp() - hours * 60 * 60
            ) * 1000

        res = self._session.get(
            f"{self.account.hq}/partner/observed_detected",
            headers=self.account.headers,
            json=params,
            timeout=30,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def list_advisories(
        self, partner: Control, start: str = None, limit: int = None, offset: int = None
    ):
        """Get advisory reports provided by a partner"""
        params = dict()
        if start:
            params["start"] = start
        if limit:
            params["limit"] = limit
        if offset:
            params["offset"] = offset
        res = self._session.get(
            f"{self.account.hq}/partner/advisories/{partner.name}",
            headers=self.account.headers,
            params=params,
            timeout=30,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)
