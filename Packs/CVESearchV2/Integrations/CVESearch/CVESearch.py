import urllib3
from typing import Dict, Any, Tuple, List

from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url: str):
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        super().__init__(base_url=base_url, headers=headers)

    def http_request(self, suffix: str):
        """Connects to api and Returns response.
           Args:
               suffix :The API endpoint.
           Returns:
               response from the api.
           """
        return self._http_request(method='GET', url_suffix=suffix)

    def cve_latest(self) -> List[Dict[str, Any]]:
        res: List[Dict[str, Any]] = self.http_request(suffix='/last')  # type: ignore
        return res

    def cve(self, cve_id) -> Dict[str, Any]:
        res: Dict[str, Any] = self.http_request(f'cve/{cve_id}')
        if not res:
            return_error(f'Could not find cve results for ID {cve_id}')
        return res


def cve_to_context(cve) -> Dict[str, str]:
    """Returning a cve structure with the following fields:
    * ID: The cve ID.
    * CVSS: The cve score scale/
    * Published: The date the cve was published.
    * Modified: The date the cve was modified.
    * Description: the cve's description

        Args:
            cve: The cve response from CVE-Search web site
    @return:
        The cve structure.
    """
    return {
        'ID': cve.get('id', ''),
        'CVSS': cve.get('cvss', '0'),
        'Published': cve.get('Published', '').rstrip('Z'),
        'Modified': cve.get('Modified', '').rstrip('Z'),
        'Description': cve.get('summary', '')
    }


def test_module(client: Client, *_):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    client.http_request(suffix='/last')
    return 'ok', None, None


def cve_latest_commnad(client: Client, *_) -> Tuple[
        Any, Dict[str, List[Any]], List[Dict[str, Any]]]:
    """Returns the 30 latest updated CVEs.
    @return:
        Latest 30 CVE details containing ID, CVSS, modified date, published date and description.
    """
    res = client.cve_latest()
    data = [cve_to_context(cve_details) for cve_details in res]
    ec = {'CVE(val.ID === obj.ID)': data}
    human_readable = tableToMarkdown('Latest CVEs', data)
    return human_readable, ec, res


def cve_command(client: Client, args: dict) -> Tuple[str, Dict[str, Dict[str, str]], Dict[str, Any]]:
    """Search for cve with the given ID and returns the cve data if found.
    Args:
           args :The demisto args containing the cve_id
    @return:
        CVE details containing ID, CVSS, modified date, published date and description.
    """
    cve_id = args.get('cve_id')
    res = client.cve(cve_id)
    data = cve_to_context(res)
    human_readable = tableToMarkdown('CVE Search results', data)
    context = {'CVE(val.ID === obj.ID)': data}
    return human_readable, context, res


def main():
    params = demisto.params()
    # Service base URL
    base_url = params.get('url', 'http://cve.circl.lu/api/')
    client = Client(base_url=base_url)
    command = demisto.command()
    LOG(f'Command being called is {command}')
    try:
        if demisto.command() == 'test-module':
            return_outputs(*test_module(client, demisto.args()))

        elif demisto.command() == 'cve-latest':
            return_outputs(*cve_latest_commnad(client, demisto.args()))

        elif demisto.command() == 'cve':
            return_outputs(*cve_command(client, demisto.args()))

        else:
            raise NotImplementedError(f'{command} is not an existing CVE Search command')

    except Exception as err:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(err)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
