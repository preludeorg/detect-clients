from prelude_sdk.controllers.http_controller import HttpController
from prelude_sdk.models.account import Account, verify_credentials
from prelude_sdk.models.codes import SCMCategory


class ExportController(HttpController):

    def __init__(self, account: Account):
        super().__init__()
        self.account = account

    @verify_credentials
    def export_scm(
        self,
        export_type: SCMCategory,
        filter: str = None,
        orderby: str = None,
        top: int = None,
    ):
        """Download partner data as a CSV"""
        params = {
            "$filter": filter,
            "$orderby": orderby,
            "$top": top,
        }
        res = self._session.post(
            f"{self.account.hq}/export/scm/{export_type.name}",
            params=params,
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)
