import re
import requests
import socket

from dns import resolver
from tld import get_tld, is_tld
from json import dumps
from typing import Tuple

from requests.exceptions import ConnectionError
from socket import gaierror


class DomainValidator:
    def __init__(self, domain_name: str, dkim_selector: str = None):
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

    def __bool__(self) -> bool:
        """
        :return: True if ONE of the validity checks were successful.
        """
        if any([
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

    def __dict__(self) -> dict:
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
    def json(self):
        return dumps(self.__dict__())

    @property
    def _domain_reg(self):
        return re.compile(
            r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9.]$")

    def _get_domain_tld(self):
        return get_tld(f"https://{self._domain_name}", fail_silently=True)

    def _regex_validator(self):
        """
        Validates domain by regex and checks that the domain's TLD is one of the known and valid ones.
        The "is_tld" function from the tld package uses a list of known TLDs which can be found here:
        https://github.com/barseghyanartur/tld/blob/b4a741f9abbd0aca472ac33badb0b08752e48b67/src/tld/res/effective_tld_names.dat.txt
        """
        if self._domain_tld:
            if self._domain_reg.fullmatch(self._domain_name) and is_tld(self._domain_tld):
                self._regex_result = True
        return

    def _web_validator(self):
        """Simple HTTP and HTTPs connectivity checks."""
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
        """Simple nslookup check, this is used to determine if the domain name translates to an IP address."""
        try:
            socket.gethostbyname(self._domain_name)
            self._nslookup_results = True
        except gaierror:
            pass

        return

    def _whois_validator(self):
        """
        To easily validate if the domain has a valid WHOIS data, we use query IANA's WHOIS service to look for
        the domain's WHOIS record.

        The Internet Assigned Numbers Authority (IANA) is responsible for maintaining a collection of registries that
        are critical in ensuring global coordination of the DNS root zone, IP addressing, and other Internet protocol
        resources.
        """
        unavailable_domain_str = f"You queried for {self._domain_name} but this server does not have\n% any data for " \
                                 f"{self._domain_name}."
        response = requests.get(
            f"https://www.iana.org/whois?q={self._domain_name}").text
        if unavailable_domain_str not in response:
            self._whois_results = True

        return

    def _dkim_validator(self):
        """
         DKIM are one of the most crucial information while investigating an email sent by an external source.
         It allows for validating that integrity and validity of the domain the email had been sent from.
         For extra information about DKIM: https://www.dmarcanalyzer.com/dkim/.

         In order to receive the DKIM information of a domain, a specific DNS query should be sent with a known
         DKIM-selector.
         If the DKIM selector is known in advance, it can be passed over and it will be used firstly.
         If no DKIM selector is specified (or the known DKIM selector query failed) the package will query the DNS with
         a common list of DKIM-selectors.
        """
        if self._dkim_selector:
            try:
                results = resolver.resolve(f"{self._dkim_selector}._domainkey.{self._domain_name}",
                                           "TXT").response.answer
                for response in results:
                    if "v=DKIM1" in str(response):
                        self._dkim_results = True
                        return
            except (resolver.NXDOMAIN, resolver.NoAnswer, resolver.NoNameservers, resolver.LifetimeTimeout):
                self._query_common_dkim_selectors()
                return
        self._query_common_dkim_selectors()
        return

    def _query_common_dkim_selectors(self):
        """Queries well known and common list of DKIM-selectors."""
        default_dkim_selectors = [
            "google", "dkim", "mail", "default", "selector1",
            "selector2", "everlytickey1", "everlytickey2", "k1",
            "mxvault"
        ]
        for selector in default_dkim_selectors:
            try:
                results = resolver.resolve(
                    f"{selector}._domainkey.{self._domain_name}", "TXT").response.answer
                for response in results:
                    if "v=DKIM1" in str(response):
                        self._dkim_results = True
            except (resolver.NXDOMAIN, resolver.NoAnswer, resolver.NoNameservers, resolver.LifetimeTimeout):
                continue

    def _spf_validator(self):
        """
        Same as DKIM, spf selectors are used to verify the email domain's integrity and validity.
        Unlike DKIM, no selectors are needed and we can query the DNS server regularly.
        """
        try:
            resolver_response = str(resolver.resolve(
                self._domain_name, 'TXT').response)
            if "v=spf1" in resolver_response:
                self._spf_results = True
        except (resolver.NXDOMAIN, resolver.NoAnswer, resolver.NoNameservers, resolver.LifetimeTimeout):
            pass

        return

    def validate_domain(self):
        """Main class execution function."""
        self._regex_validator()
        self._web_validator()
        self._nslookup_validator()
        self._whois_validator()
        self._dkim_validator()
        self._spf_validator()


def validate_domain(domain_name: str, dkim_selector: str = None, raw_data=False) -> Tuple[bool, dict]:
    """
    This function is used to allow the users to get the results without handling with the object itself.
    :param domain_name: The name of the domain - mandatory.
    :param dkim_selector: A known-in-advance DKIM-selector - optional.
    :param raw_data: Determines the return type.
    :return: Returns the validity check results in both bool and dictionary formats.
        If raw_data marked as False, returns a boolean expression as the result.
        Else, returns a dictionary representation of the validity checks' results.
    :rtype: bool, dict
    """
    dv = DomainValidator(domain_name=domain_name, dkim_selector=dkim_selector)
    dv.validate_domain()
    if not raw_data:
        return True if dv else False
    else:
        return dv.__dict__()
