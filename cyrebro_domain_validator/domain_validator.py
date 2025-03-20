import re
import requests
import socket

from typing import Tuple

from dns import resolver
from tld import get_tld, is_tld

from requests.exceptions import ConnectionError
from socket import gaierror
from tenacity import retry, stop_after_attempt, wait_fixed


class DomainValidator:
    _domain_regex = re.compile(
        r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9.]$"
    )

    default_dkim_selectors = [
        "google",
        "dkim",
        "mail",
        "default",
        "selector1",
        "selector2",
        "everlytickey1",
        "everlytickey2",
        "k1",
        "mxvault",
    ]

    def __init__(self, domain_name: str, dkim_selector: str = None):
        self._domain_name = domain_name
        self._domain_tld = self.get_domain_tld(self._domain_name)
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
        return any(
            [
                self._regex_result,
                self._http_result,
                self._https_result,
                self._dkim_results,
                self._spf_results,
                self._nslookup_results,
                self._whois_results,
            ]
        )

    @staticmethod
    def get_domain_tld(domain_name: str):
        return get_tld(f"https://{domain_name}", fail_silently=True)

    @staticmethod
    def _http_validator(domain_name) -> bool:
        try:
            requests.get(f"http://{domain_name}")
            return True
        except ConnectionError:
            return False

    @staticmethod
    def _https_validator(domain_name) -> bool:
        try:
            requests.get(f"https://{domain_name}")
            return True
        except ConnectionError:
            return False

    def _regex_validator(self) -> None:
        """
        Validates domain by regex and checks that the domain's TLD is one of the known and valid ones.
        The "is_tld" function from the tld package uses a list of known TLDs which can be found here:
        https://github.com/barseghyanartur/tld/blob/b4a741f9abbd0aca472ac33badb0b08752e48b67/src/tld/res/effective_tld_names.dat.txt
        """
        if not self._domain_tld:
            return

        if self._domain_regex.fullmatch(self._domain_name) and is_tld(self._domain_tld):
            self._regex_result = True

    def _web_validator(self) -> None:
        """Simple HTTP and HTTPs connectivity checks."""
        if self._http_validator(self._domain_name):
            self._http_result = True

        if self._https_validator(self._domain_name):
            self._https_result = True

    def _nslookup_validator(self) -> None:
        """Simple nslookup check, this is used to determine if the domain name translates to an IP address."""
        try:
            socket.gethostbyname(self._domain_name)
            self._nslookup_results = True
        except gaierror:
            pass

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(20))
    def _whois_validator(self) -> None:
        """
        To easily validate if the domain has a valid WHOIS data, we use query IANA's WHOIS service to look for
        the domain's WHOIS record.

        The Internet Assigned Numbers Authority (IANA) is responsible for maintaining a collection of registries that
        are critical in ensuring global coordination of the DNS root zone, IP addressing, and other Internet protocol
        resources.
        """
        unavailable_domain_str = (
            f"You queried for {self._domain_name} but this server does not have\n% any data for "
            f"{self._domain_name}."
        )
        response = requests.get(
            f"https://www.iana.org/whois?q={self._domain_name}"
        ).text
        if unavailable_domain_str not in response:
            self._whois_results = True

    def _dkim_validator(self) -> None:
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
        if not self._dkim_selector:
            self._query_common_dkim_selectors()
            return

        try:
            results = resolver.resolve(
                f"{self._dkim_selector}._domainkey.{self._domain_name}", "TXT"
            ).response.answer
            for response in results:
                if "v=DKIM1" in str(response):
                    self._dkim_results = True
                    return
        except (
            resolver.NXDOMAIN,
            resolver.NoAnswer,
            resolver.NoNameservers,
            resolver.LifetimeTimeout,
        ):
            self._query_common_dkim_selectors()

    def _query_common_dkim_selectors(self) -> None:
        """Queries well known and common list of DKIM-selectors."""
        for selector in self.default_dkim_selectors:
            try:
                results = resolver.resolve(
                    f"{selector}._domainkey.{self._domain_name}", "TXT"
                ).response.answer
                for response in results:
                    if "v=DKIM1" in str(response):
                        self._dkim_results = True
            except (
                resolver.NXDOMAIN,
                resolver.NoAnswer,
                resolver.NoNameservers,
                resolver.LifetimeTimeout,
            ):
                continue

    def _spf_validator(self) -> None:
        """
        Same as DKIM, spf selectors are used to verify the email domain's integrity and validity.
        Unlike DKIM, no selectors are needed and we can query the DNS server regularly.
        """
        try:
            resolver_response = str(resolver.resolve(self._domain_name, "TXT").response)
            if "v=spf1" in resolver_response:
                self._spf_results = True
        except (
            resolver.NXDOMAIN,
            resolver.NoAnswer,
            resolver.NoNameservers,
            resolver.LifetimeTimeout,
        ):
            pass

    def to_dict(self) -> dict:
        return {
            "regex": self._regex_result,
            "http": self._http_result,
            "https": self._https_result,
            "nslookup": self._nslookup_results,
            "whois": self._whois_results,
            "dkim": self._dkim_results,
            "spf": self._spf_results,
        }

    def validate_domain(self):
        """Main class execution function."""
        self._regex_validator()
        self._web_validator()
        self._nslookup_validator()
        self._whois_validator()
        self._dkim_validator()
        self._spf_validator()


def validate_domain(
    domain_name: str, dkim_selector: str = None, raw_data=False
) -> Tuple[bool, dict]:
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
    return dv.to_dict()
