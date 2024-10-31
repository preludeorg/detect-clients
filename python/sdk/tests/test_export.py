import pytest

from prelude_sdk.controllers.export_controller import ExportController


@pytest.mark.order(13)
@pytest.mark.usefixtures('setup_account')
class TestExport:

    def setup_class(self):
        self.export = ExportController(pytest.account)

    def test_export_missing_edr_endpoints_csv(self, unwrap):
        export_url = unwrap(self.export.partner)(self.export, 'endpoints?$filter=not known_by_edrs/any()')
        assert 'url' in export_url