from prelude_sdk.controllers.http_controller import HttpController
from prelude_sdk.models.account import Account


class ProbeController(HttpController):

    def __init__(self, account: Account):
        super().__init__()
        self.account = account

    def download(self, name: str, dos: str):
        """Download a probe executable"""
        res = self._session.get(
            f"{self.account.hq}/download/{name}", headers=dict(dos=dos), timeout=10
        )
        if not res.status_code == 200:
            raise Exception(res.text)
        return res.text
