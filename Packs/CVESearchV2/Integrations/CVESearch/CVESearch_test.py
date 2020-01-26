from CVESearch import cve_command, cve_latest_commnad, Client
import demistomock as demisto
from CommonServerPython import DemistoException

BASE_URL = 'http://cve.circl.lu/api/'


def test_wrong_path():
    bad_url = 'http://cve.bad_url'
    client = Client(base_url=bad_url)
    try:
        cve_command(client, {})
        assert False, 'Bad url- Exception should by raised'
    except DemistoException as err:
        expected_exception_message = 'Verify that the server URL parameter is correct'
        assert expected_exception_message in str(err), 'Bad error response when bad url is given'


def test_module():
    client = Client(base_url=BASE_URL)
    raw_results = cve_latest_commnad(client, {})
    results = _get_results(raw_results)
    assert len(results) == 30, 'cve-latest command should return latest 30 cves'


def test_bad_cve_id(mocker):
    bad_cve_id = 'CVE-bad-cve'
    client = Client(base_url=BASE_URL)
    mocker.patch.object(demisto, 'results')
    try:
        cve_command(client, {'cve_id': bad_cve_id})
        assert False, 'Bad url- Exception should by raised'
    except SystemExit:
        results = _get_results()
        assert results == f'Could not find cve results for ID {bad_cve_id}'


def _get_results(raw_results=None):
    if raw_results:
        return raw_results[1]['CVE(val.ID === obj.ID)']
    return demisto.results.call_args[0][0]['Contents']
