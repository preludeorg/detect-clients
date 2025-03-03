from prelude_sdk.controllers.http_controller import HttpController
from prelude_sdk.models.account import Account, verify_credentials


class JobsController(HttpController):

    def __init__(self, account: Account):
        super().__init__()
        self.account = account

    @verify_credentials
    def job_statuses(self):
        """Get job statuses"""
        res = self._session.get(
            f"{self.account.hq}/jobs/statuses", headers=self.account.headers, timeout=30
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def job_status(self, job_id: str):
        """Get job status given job ID"""
        res = self._session.get(
            f"{self.account.hq}/jobs/statuses/{job_id}",
            headers=self.account.headers,
            timeout=30,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)
