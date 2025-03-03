import urllib

from prelude_sdk.controllers.http_controller import HttpController
from prelude_sdk.models.account import Account, verify_credentials
from prelude_sdk.models.codes import Control, EDRResponse


class BuildController(HttpController):

    def __init__(self, account: Account):
        super().__init__()
        self.account = account

    @verify_credentials
    def clone_test(self, source_test_id):
        """Clone a test"""
        res = self._session.post(
            f"{self.account.hq}/build/tests",
            json=dict(source_test_id=source_test_id),
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def create_test(self, name, unit, technique=None, test_id=None):
        """Create or update a test"""
        body = dict(name=name, unit=unit)
        if technique:
            body["technique"] = technique
        if test_id:
            body["id"] = test_id

        res = self._session.post(
            f"{self.account.hq}/build/tests",
            json=body,
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def update_test(
        self,
        test_id,
        name=None,
        unit=None,
        technique=None,
        crowdstrike_expected_outcome: EDRResponse = None,
    ):
        """Update a test"""
        body = dict()
        if crowdstrike_expected_outcome:
            body["expected"] = dict(crowdstrike=crowdstrike_expected_outcome.value)
        if name:
            body["name"] = name
        if unit:
            body["unit"] = unit
        if technique is not None:
            body["technique"] = technique

        res = self._session.post(
            f"{self.account.hq}/build/tests/{test_id}",
            json=body,
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def delete_test(self, test_id, purge):
        """Delete an existing test"""
        res = self._session.delete(
            f"{self.account.hq}/build/tests/{test_id}",
            json=dict(purge=purge),
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def undelete_test(self, test_id):
        """Undelete a tombstoned test"""
        res = self._session.post(
            f"{self.account.hq}/build/tests/{test_id}/undelete",
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def upload(self, test_id, filename, data, skip_compile=False):
        """Upload a test or attachment"""
        if len(data) > 1000000:
            raise ValueError(f"File size must be under 1MB ({filename})")

        h = self.account.headers | {"Content-Type": "application/octet-stream"}
        query_params = ""
        if skip_compile:
            query_params = "?" + urllib.parse.urlencode(dict(skip_compile=True))
        res = self._session.post(
            f"{self.account.hq}/build/tests/{test_id}/{filename}{query_params}",
            data=data,
            headers=h,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def compile_code_string(self, code: str, source_test_id: str = None):
        """Compile a code string"""
        res = self._session.post(
            f"{self.account.hq}/build/compile",
            json=dict(code=code, source_test_id=source_test_id),
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def get_compile_status(self, job_id):
        res = self._session.get(
            f"{self.account.hq}/build/compile/{job_id}",
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def create_threat(
        self, name, published, threat_id=None, source_id=None, source=None, tests=None
    ):
        """Create a threat"""
        body = dict(name=name, published=published)
        if threat_id:
            body["id"] = threat_id
        if source_id:
            body["source_id"] = source_id
        if source:
            body["source"] = source
        if tests:
            body["tests"] = tests

        res = self._session.post(
            f"{self.account.hq}/build/threats",
            json=body,
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def update_threat(
        self,
        threat_id,
        name=None,
        source_id=None,
        source=None,
        published=None,
        tests=None,
    ):
        """Update a threat"""
        body = dict()
        if name:
            body["name"] = name
        if source_id is not None:
            body["source_id"] = source_id
        if source is not None:
            body["source"] = source
        if published is not None:
            body["published"] = published
        if tests is not None:
            body["tests"] = tests

        res = self._session.post(
            f"{self.account.hq}/build/threats/{threat_id}",
            json=body,
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def delete_threat(self, threat_id, purge):
        """Delete an existing threat"""
        res = self._session.delete(
            f"{self.account.hq}/build/threats/{threat_id}",
            json=dict(purge=purge),
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def undelete_threat(self, threat_id):
        """Undelete a tombstoned threat"""
        res = self._session.post(
            f"{self.account.hq}/build/threats/{threat_id}/undelete",
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def create_detection(
        self, rule: str, test_id: str, detection_id=None, rule_id=None
    ):
        """Create a detection"""
        body = dict(rule=rule, test_id=test_id)
        if detection_id:
            body["detection_id"] = detection_id
        if rule_id:
            body["rule_id"] = rule_id

        res = self._session.post(
            f"{self.account.hq}/build/detections",
            json=body,
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def update_detection(self, detection_id: str, rule=None, test_id=None):
        """Update a detection"""
        body = dict()
        if rule:
            body["rule"] = rule
        if test_id:
            body["test_id"] = test_id

        res = self._session.post(
            f"{self.account.hq}/build/detections/{detection_id}",
            json=body,
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def delete_detection(self, detection_id: str):
        """Delete an existing detection"""
        res = self._session.delete(
            f"{self.account.hq}/build/detections/{detection_id}",
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def create_threat_hunt(
        self,
        control: Control,
        test_id: str,
        name: str,
        query: str,
        threat_hunt_id: str = None,
    ):
        """Create a threat hunt"""
        body = dict(
            control=control.name,
            name=name,
            query=query,
            test_id=test_id,
        )
        if threat_hunt_id:
            body["id"] = threat_hunt_id

        res = self._session.post(
            f"{self.account.hq}/build/threat_hunts",
            json=body,
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def update_threat_hunt(
        self,
        threat_hunt_id: str,
        name: str = None,
        query: str = None,
        test_id: str = None,
    ):
        """Update a threat hunt"""
        body = dict()
        if name:
            body["name"] = name
        if query:
            body["query"] = query
        if test_id:
            body["test_id"] = test_id

        res = self._session.post(
            f"{self.account.hq}/build/threat_hunts/{threat_hunt_id}",
            json=body,
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)

    @verify_credentials
    def delete_threat_hunt(self, threat_hunt_id: str):
        """Delete an existing threat hunt"""
        res = self._session.delete(
            f"{self.account.hq}/build/threat_hunts/{threat_hunt_id}",
            headers=self.account.headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
        raise Exception(res.text)
