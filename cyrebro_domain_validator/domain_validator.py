"""DomainValidator class for validating domain names and their associated records."""

from __future__ import annotations

import re
import socket
from socket import gaierror
from typing import TYPE_CHECKING, ClassVar

import requests
from dns import resolver
from requests.exceptions import ConnectionError as RequestsConnectionError
from tenacity import retry, stop_after_attempt, wait_fixed
from tld import Result, get_tld, is_tld

if TYPE_CHECKING:
    from dns.rrset import RRset


class DomainValidator:
    """DomainValidator class for validating domain names and their associated records."""

    _domain_regex: re.Pattern[str] = re.compile(
        pattern=r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9.]$",
    )

    default_dkim_selectors: ClassVar[list[str]] = [ # https://docs.astral.sh/ruff/rules/mutable-class-default/
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

    def __init__(self, domain_name: str, dkim_selector: str | None = None) -> None:
        """Initialize the DomainValidator class."""
        self._domain_name: str = domain_name
        self._domain_tld: str | Result | None = self.get_domain_tld(domain_name=self._domain_name)
        self._dkim_selector: str | None = dkim_selector
        self._regex_result = False
        self._http_result = False
        self._https_result = False
        self._dkim_results = False
        self._spf_results = False
        self._nslookup_results = False
        self._whois_results = False

    def __bool__(self) -> bool:
        """:return: True if ONE of the validity checks were successful."""
        return any(
            [
                self._regex_result,
                self._http_result,
                self._https_result,
                self._dkim_results,
                self._spf_results,
                self._nslookup_results,
                self._whois_results,
            ],
        )

    @staticmethod
    def get_domain_tld(domain_name: str) -> str | Result | None:
        """Get the TLD of a domain name."""
        return get_tld(url=f"https://{domain_name}", fail_silently=True)

    @staticmethod
    def _http_validator(domain_name: str) -> bool: # https://docs.astral.sh/ruff/rules/try-consider-else/
        try:
            requests.get(url=f"http://{domain_name}", timeout=5)
        except RequestsConnectionError:
            return False
        else:
            return True

    @staticmethod
    def _https_validator(domain_name: str) -> bool:
        try:
            requests.get(url=f"https://{domain_name}", timeout=5)
        except RequestsConnectionError:
            return False
        else:
            return True

    def _regex_validator(self) -> None:
        """Validate domain by regex and check that the domain's TLD is one of the known and valid ones.

        The "is_tld" function from the tld package uses a list of known TLDs which can be found here:
        https://github.com/barseghyanartur/tld/blob/b4a741f9abbd0aca472ac33badb0b08752e48b67/src/tld/res/effective_tld_names.dat.txt.
        """
        if not self._domain_tld:
            return

        if self._domain_regex.fullmatch(string=self._domain_name) and is_tld(value=self._domain_tld):
            self._regex_result = True

    def _web_validator(self) -> None:
        """Perform simple HTTP and HTTPs connectivity checks."""
        if self._http_validator(domain_name=self._domain_name):
            self._http_result = True

        if self._https_validator(domain_name=self._domain_name):
            self._https_result = True

    def _nslookup_validator(self) -> None:
        """Perform a simple nslookup check to determine if the domain name translates to an IP address."""
        try:
            socket.gethostbyname(self._domain_name)
            self._nslookup_results = True
        except gaierror:
            pass

    @retry(stop=stop_after_attempt(max_attempt_number=3), wait=wait_fixed(wait=20))
    def _whois_validator(self) -> None:
        """To easily validate if the domain has a valid WHOIS data, we use IANA's WHOIS service.

        The Internet Assigned Numbers Authority (IANA) is responsible for maintaining a collection of registries that
        are critical in ensuring global coordination of the DNS root zone, IP addressing, and other Internet protocol
        resources.
        """
        unavailable_domain_str: str = (
            f"You queried for {self._domain_name} but this server does not have\n% any data for {self._domain_name}."
        )
        response: str = requests.get(url=f"https://www.iana.org/whois?q={self._domain_name}", timeout=5).text
        if unavailable_domain_str not in response:
            self._whois_results = True

    def _dkim_validator(self) -> None:
        """DKIM are one of the most crucial information while investigating an email sent by an external source.

        It allows for validating that integrity and validity of the domain the email had been sent from.
        For extra information about DKIM: https://www.dmarcanalyzer.com/dkim/.

        In order to receive the DKIM information of a domain, a specific DNS query should be sent with a known
        DKIM-selector.
        If the DKIM selector is known in advance, it can be passed over and it will be used firstly.
        If no DKIM selector is specified (or the known DKIM selector query failed) the package will query the DNS with
        a common list of DKIM-selectors.
        """
        # Try with the provided selector first if available
        if self._dkim_selector and self._check_dkim_selector(selector=self._dkim_selector):
            return

        # Fall back to common selectors
        self._query_common_dkim_selectors()

    def _check_dkim_selector(self, selector: str) -> bool:
        """Check if a specific DKIM selector exists and contains valid DKIM record."""
        dkim_domain: str = f"{selector}._domainkey.{self._domain_name}"
        try:
            results: list[RRset] = resolver.resolve(qname=dkim_domain, rdtype="TXT").response.answer
            for response in results:
                if "v=DKIM1" in str(response):
                    self._dkim_results = True
                    return True
        except (
            resolver.NXDOMAIN,
            resolver.NoAnswer,
            resolver.NoNameservers,
            resolver.LifetimeTimeout,
        ):
            pass
        return False

    def _query_common_dkim_selectors(self) -> None:
        """Query well known and common list of DKIM-selectors."""
        for selector in self.default_dkim_selectors:
            if self._check_dkim_selector(selector):
                return

    def _spf_validator(self) -> None:
        """Verify the email domain's integrity and validity using SPF selectors.

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
        """Convert the results to a dictionary format."""
        return {
            "regex": self._regex_result,
            "http": self._http_result,
            "https": self._https_result,
            "nslookup": self._nslookup_results,
            "whois": self._whois_results,
            "dkim": self._dkim_results,
            "spf": self._spf_results,
        }

    def validate_domain(self) -> None:
        """Execute the main class validation functions."""
        self._regex_validator()
        self._web_validator()
        self._nslookup_validator()
        self._whois_validator()
        self._dkim_validator()
        self._spf_validator()


def validate_domain(domain_name: str, dkim_selector: str | None = None, *, raw_data: bool = False) -> bool | dict:
    """Allow users to get the results without handling the object itself.

    :param domain_name: The name of the domain - mandatory.
    :param dkim_selector: A known-in-advance DKIM-selector - optional.
    :param raw_data: Determines the return type.
    :return: If raw_data is False, returns a boolean expression as the result.
             If raw_data is True, returns a dictionary representation of the validity checks' results.
    :rtype: bool | dict
    """
    dv = DomainValidator(domain_name=domain_name, dkim_selector=dkim_selector)
    dv.validate_domain()
    if not raw_data:
        return bool(dv)
    return dv.to_dict()
