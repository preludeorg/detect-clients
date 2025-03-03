import json
import pytest

from datetime import datetime, timedelta, timezone
from dateutil.parser import parse
from prelude_sdk.controllers.iam_controller import IAMController
from prelude_sdk.models.codes import AuditEvent, Mode, Permission, RunCode

from testutils import *


@pytest.mark.order(1)
@pytest.mark.usefixtures("setup_account")
class TestIAM:

    def setup_class(self):
        self.iam = IAMController(pytest.account)
        self.company = "prelude"
        self.second_user = "registration"

    def test_get_account(self, unwrap):
        res = unwrap(self.iam.get_account)(self.iam)
        diffs = check_dict_items(pytest.expected_account, res)
        assert not diffs, json.dumps(diffs, indent=2)

    def test_create_user(self, unwrap):
        ex = datetime.now(timezone.utc) + timedelta(days=1)
        res = unwrap(self.iam.create_user)(
            self.iam,
            email=self.second_user,
            permission=Permission.SERVICE,
            name="Rob",
        )
        assert self.second_user == res["handle"]
        assert check_if_string_is_uuid(res["token"])

        res = unwrap(self.iam.get_account)(self.iam)

        pytest.expected_account["users"].append(
            dict(
                handle=self.second_user,
                permission=Permission.SERVICE.value,
                name="Rob",
                subscriptions=[],
                oidc=False,
                terms={},
            )
        )

        diffs = check_dict_items(pytest.expected_account, res)
        assert not diffs, json.dumps(diffs, indent=2)

    def test_update_user(self, unwrap):
        unwrap(self.iam.update_user)(self.iam, email=self.second_user, name="Robb")

        for user in pytest.expected_account["users"]:
            if user["handle"] == self.second_user:
                user["name"] = "Robb"
                break

        res = unwrap(self.iam.get_account)(self.iam)
        diffs = check_dict_items(pytest.expected_account, res)
        assert not diffs, json.dumps(diffs, indent=2)

    def test_remove_user(self, unwrap):
        unwrap(self.iam.remove_user)(self.iam, handle=self.second_user)

        for i, user in enumerate(pytest.expected_account["users"]):
            if user["handle"] == self.second_user:
                break
        del pytest.expected_account["users"][i]

        res = unwrap(self.iam.get_account)(self.iam)
        diffs = check_dict_items(pytest.expected_account, res)
        assert not diffs, json.dumps(diffs, indent=2)

    def test_update_account(self, unwrap):
        unwrap(self.iam.update_account)(
            self.iam, mode=Mode.MANUAL, company=self.company
        )
        pytest.expected_account["mode"] = Mode.MANUAL.value
        pytest.expected_account["company"] = self.company
        autopilot = [
            i
            for i, item in enumerate(pytest.expected_account["queue"])
            if item["tag"] == "autopilot"
        ]
        for i in sorted(autopilot, reverse=True):
            del pytest.expected_account["queue"][i]

        res = unwrap(self.iam.get_account)(self.iam)
        diffs = check_dict_items(pytest.expected_account, res)
        assert not diffs, json.dumps(diffs, indent=2)

    def test_audit_logs(self, unwrap):
        res = unwrap(self.iam.audit_logs)(self.iam, limit=1)[0]
        expected = dict(
            event="update_account",
            user_id=pytest.expected_account["whoami"],
            status="200",
            values=dict(mode=Mode.MANUAL.name, company=self.company),
            account_id=pytest.expected_account["account_id"],
        )
        diffs = check_dict_items(expected, res)
        assert not diffs, json.dumps(diffs, indent=2)

    def test_reset_account(self, unwrap, manual, pause_for_manual_action, email):
        if not manual:
            pytest.skip("Not manual mode")

        unwrap(self.iam.reset_password)(
            self.iam, email=email, account_id=pytest.expected_account["account_id"]
        )
        with pause_for_manual_action:
            token = input("Enter your verification token:\n")
        res = unwrap(self.iam.verify_user)(self.iam, token=token)
        assert pytest.expected_account["account_id"] == res["account"]
        assert check_if_string_is_uuid(res["token"])

        pytest.account.headers["token"] = res["token"]

    @pytest.mark.order(-1)
    def test_purge_account(self, unwrap, existing_account):
        if existing_account:
            pytest.skip("Pre-existing account")

        iam = IAMController(pytest.account)
        unwrap(iam.purge_account)(iam)
