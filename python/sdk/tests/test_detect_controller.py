import os
import pytest
import subprocess

from prelude_sdk.models.codes import Decision, RunCode
from prelude_sdk.controllers.detect_controller import DetectController


@pytest.mark.order(after='test_probe_controller.py::TestProbeController::test_download')
class TestDetectController:

    def setup_class(self):
        """Setup the test class"""
        self.host = 'test_host'
        self.serial = 'test_serial'
        self.edr_id = 'test_edr_id'
        self.tags = 'test_tag'
        self.health_check = '39de298a-911d-4a3b-aed4-1e8281010a9a'
        self.recommendation = 'Test'
        self.detect = DetectController(pytest.account)

    def test_register_endpoint(self, unwrap):
        """Test register_endpoint method"""
        res = unwrap(self.detect.register_endpoint)(self.detect, host=self.host, serial_num=self.serial, edr_id=self.edr_id, tags=self.tags)
        assert len(res) == 32
        pytest.endpoint_token = res

    def test_list_endpoints(self, unwrap):
        """Test list_endpoints method"""
        res = unwrap(self.detect.list_endpoints)(self.detect)
        assert len(res) > 0
        assert self.host == res[0]['host']
        assert self.serial == res[0]['serial_num']
        assert self.edr_id == res[0]['edr_id']
        assert self.tags in res[0]['tags']
        pytest.endpoint_id = res[0]['endpoint_id']

    def test_list_tests(self, unwrap):
        """Test list_tests method"""
        res = unwrap(self.detect.list_tests)(self.detect)
        assert len(res) > 0
        tests = [test for test in res if test['id'] != self.health_check]
        pytest.test_id = tests[0]['id']

    def test_list_queue(self, unwrap):
        """Test list_queue method"""
        res = unwrap(self.detect.list_queue)(self.detect)
        assert len(res) > 0
        assert self.health_check == res[0]['test']
        assert RunCode.DAILY.value == res[0]['run_code']

    def test_enable_test(self, unwrap):
        """Test enable_test method"""
        unwrap(self.detect.enable_test)(self.detect, ident=pytest.test_id, run_code=RunCode.DEBUG.value, tags=self.tags)
        res = unwrap(self.detect.list_queue)(self.detect)
        assert len([test for test in res if test['test'] == pytest.test_id]) == 1

    def test_describe_activity(self, unwrap):
        """Test describe_activity method"""
        try:
            subprocess.run([pytest.probe], capture_output=True, env={'PRELUDE_TOKEN': pytest.endpoint_token}, timeout=20)
        except subprocess.TimeoutExpired:
            describe_activity = unwrap(self.detect.describe_activity)(self.detect, filters={'endpoint_id': pytest.endpoint_id})
            assert len(describe_activity) == 2
        finally:
            os.remove(pytest.probe)

    def test_disable_test(self, unwrap):
        """Test disable_test method"""
        unwrap(self.detect.disable_test)(self.detect, ident=pytest.test_id, tags=self.tags)
        res = unwrap(self.detect.list_queue)(self.detect)
        assert len([test for test in res if test['test'] == pytest.test_id]) == 0

    def test_social_stats(self, unwrap):
        """Test social_stats method"""
        res = unwrap(self.detect.social_stats)(self.detect, ident=pytest.test_id)
        assert len(res.values()) >= 1

    def test_delete_endpoint(self, unwrap):
        """Test delete_endpoint method"""
        unwrap(self.detect.delete_endpoint)(self.detect, ident=pytest.endpoint_id)
        res = unwrap(self.detect.list_endpoints)(self.detect)
        assert len(res) == 0

    def test_create_recommendation(self, unwrap):
        """Test create_recommendation method"""
        unwrap(self.detect.create_recommendation)(self.detect, title=self.recommendation, description=self.recommendation)
        assert True

    def test_recommendations(self, unwrap):
        """Test recommendations method"""
        res = unwrap(self.detect.recommendations)(self.detect)
        assert self.recommendation == res[0]['title']
        assert self.recommendation == res[0]['description']
        pytest.recommendation_id = res[0]['id']

    def test_make_decision(self, unwrap):
        """Test make_decision method"""
        unwrap(self.detect.make_decision)(self.detect, id=pytest.recommendation_id, decision=Decision.APPROVE.value)
        res = unwrap(self.detect.recommendations)(self.detect)
        assert Decision.APPROVE.value == res[0]['events'][0]['decision']
