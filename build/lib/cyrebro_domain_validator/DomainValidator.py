import re
import requests
import socket

from dns import resolver
from tld import get_tld, is_tld

from requests.exceptions import ConnectionError
from socket import gaierror


class DomainValidator:
    def __init__(self, domain_name: str, dkim_selector: str = None, raw_data=False):
        self.raw_data = raw_data
        self._domain_name = domain_name
        self._domain_tld = self._get_domain_tld()
        self._dkim_selector = dkim_selector
        self._regex_result = False
        self._http_result = False
        self._https_result = False
        self._dkim_results = False
        self._spf_results = False
        self._nslookup_results = False
        self._whois_results = False

        self._validate_domain()

    def __dict__(self):
        return {
            "regex": self._regex_result,
            "http": self._http_result,
            "https": self._https_result,
            "nslookup": self._nslookup_results,
            "whois": self._whois_results,
            "dkim": self._dkim_results,
            "spf": self._spf_results,
        }

    @property
    def _domain_reg(self):
        return re.compile(
            r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9.]$")

    @property
    def results(self):
        if self.raw_data:
            return self.__dict__()

        elif any([
            self._regex_result,
            self._http_result,
            self._https_result,
            self._dkim_results,
            self._spf_results,
            self._nslookup_results,
            self._whois_results
        ]):
            return True

        return False

    def _get_domain_tld(self):
        return get_tld(f"https://{self._domain_name}", fail_silently=True)

    def _regex_validator(self):
        if self._domain_tld:
            if self._domain_reg.fullmatch(self._domain_name) and is_tld(self._domain_tld):
                self._regex_result = True
        return

    def _web_validator(self):
        try:
            requests.get(f"http://{self._domain_name}")
            self._http_result = True
        except ConnectionError:
            pass
        try:
            requests.get(f"https://{self._domain_name}")
            self._https_result = True
        except ConnectionError:
            pass

        return

    def _nslookup_validator(self):
        try:
            socket.gethostbyname(self._domain_name)
            self._nslookup_results = True
        except gaierror:
            pass

        return

    def _whois_validator(self):
        unavailable_domain_str = f"You queried for {self._domain_name} but this server does not have\n% any data for " \
                                 f"{self._domain_name}."
        response = requests.get(f"https://www.iana.org/whois?q={self._domain_name}").text
        if unavailable_domain_str not in response:
            self._whois_results = True

        return

    def _dkim_validator(self):
        if self._dkim_selector:
            try:
                results = resolver.resolve(f"{self._dkim_selector}._domainkey.{self._domain_name}",
                                           "TXT").response.answer
                for response in results:
                    if "v=DKIM1" in str(response):
                        self._dkim_results = True
            except (resolver.NXDOMAIN, resolver.NoAnswer):
                self._query_common_dkim_selectors()

        return

    def _query_common_dkim_selectors(self):
        default_dkim_selectors = [
            "google", "dkim", "mail", "default", "selector1",
            "selector2", "everlytickey1", "everlytickey2", "k1",
            "mxvault"
        ]
        for selector in default_dkim_selectors:
            try:
                results = resolver.resolve(f"{selector}._domainkey.{self._domain_name}", "TXT").response.answer
                for response in results:
                    if "v=DKIM1" in str(response):
                        self._dkim_results = True
            except (resolver.NXDOMAIN, resolver.NoAnswer):
                continue

    def _spf_validator(self):
        try:
            resolver_response = str(resolver.resolve(self._domain_name, 'TXT').response)
            if "v=spf1" in resolver_response:
                self._spf_results = True
        except (resolver.NXDOMAIN, resolver.NoAnswer):
            pass

        return

    def _validate_domain(self):
        self._regex_validator()
        self._web_validator()
        self._nslookup_validator()
        self._whois_validator()
        self._dkim_validator()
