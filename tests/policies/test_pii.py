"""Tests for PII detection policy."""

import pytest

from overrule.models.violation import ViolationSeverity
from overrule.policies.pii import PIIPolicy


@pytest.fixture
def policy() -> PIIPolicy:
    return PIIPolicy()


class TestCreditCardDetection:
    def test_detects_visa(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("My card is 4111111111111111")
        assert not result.passed
        assert result.violations[0].severity == ViolationSeverity.CRITICAL
        assert "credit_card" in result.violations[0].metadata["pattern"]

    def test_detects_mastercard(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("Pay with 5500000000000004")
        assert not result.passed

    def test_detects_amex(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("Amex: 378282246310005")
        assert not result.passed

    def test_ignores_random_numbers(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("Order #123456789 was placed")
        assert result.passed


class TestSSNDetection:
    def test_detects_valid_ssn(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("SSN: 123-45-6789")
        assert not result.passed
        assert result.violations[0].severity == ViolationSeverity.CRITICAL

    def test_ignores_invalid_ssn_000(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("Not a SSN: 000-12-3456")
        assert result.passed

    def test_ignores_invalid_ssn_666(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("Not a SSN: 666-12-3456")
        assert result.passed


class TestEmailDetection:
    def test_detects_email(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("Contact me at john@example.com please")
        assert not result.passed
        assert result.violations[0].severity == ViolationSeverity.MEDIUM

    def test_ignores_non_email(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("This is not@an email at all")
        assert result.passed


class TestPhoneDetection:
    def test_detects_us_phone(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("Call me at (415) 555-4567")
        assert not result.passed

    def test_detects_international_phone(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("Reach me at +44 20 7946 0958")
        assert not result.passed


class TestIPAddressDetection:
    def test_detects_ipv4(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("Server at 192.168.1.100")
        assert not result.passed
        assert result.violations[0].severity == ViolationSeverity.LOW

    def test_ignores_invalid_ip(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("Version 999.999.999.999 released")
        assert result.passed


class TestRedaction:
    def test_redacts_matched_content(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("SSN: 123-45-6789")
        assert "****" in (result.violations[0].matched_content or "")
        assert "123-45-6789" not in (result.violations[0].matched_content or "")


class TestConfiguration:
    def test_disable_specific_pattern(self) -> None:
        policy = PIIPolicy(parameters={"disabled_patterns": ["email"]})
        result = policy.evaluate("Contact john@example.com")
        assert result.passed

    def test_multiple_violations(self, policy: PIIPolicy) -> None:
        content = "SSN: 123-45-6789, card: 4111111111111111, email: test@foo.com"
        result = policy.evaluate(content)
        assert not result.passed
        assert len(result.violations) >= 3


def patterns_for(policy: PIIPolicy, content: str) -> set[str]:
    """Return the set of PII pattern names that fired on ``content``."""
    result = policy.evaluate(content)
    return {v.metadata["pattern"] for v in result.violations}


class TestCreditCardFormats:
    """P7 — the fixed 4-4-4-4 grouping missed many real card formats."""

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param("4111.1111.1111.1111", id="dot-separators"),
            pytest.param("4111-1111-1111-1111", id="dash-separators"),
            pytest.param("4111 1111 1111 1111", id="space-separators"),
            pytest.param("Amex 3782 822463 10005", id="amex-4-6-5-print-format"),
            pytest.param("card 4222222222222", id="visa-13-digit"),
            pytest.param("4111111111111111119", id="19-digit-run"),
            pytest.param("Diners 30569309025904", id="diners-club"),
            pytest.param("JCB 3530111333300000", id="jcb"),
            pytest.param("UnionPay 6200000000000005", id="unionpay"),
            pytest.param("Discover 6011111111111117", id="discover"),
            pytest.param("x4111111111111111", id="leading-word-char"),
            pytest.param("41111111111111119", id="trailing-digit"),
        ],
    )
    def test_detects_card(self, policy: PIIPolicy, content: str) -> None:
        assert "credit_card" in patterns_for(policy, content), content

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param("Order 4111-2024-0001-5678 shipped", id="four-group-order-id"),
            pytest.param("card 4111111111111112", id="bad-luhn-check-digit"),
            pytest.param("Order #123456789 was placed", id="short-number"),
            pytest.param("prices: 500 200 300 4000", id="price-list"),
            pytest.param("1000 2000 3000 4000", id="round-numbers"),
            pytest.param("2024 2025 2026 2027", id="year-list"),
            pytest.param("ref 9876543210123456", id="unknown-issuer-prefix"),
        ],
    )
    def test_not_a_card(self, policy: PIIPolicy, content: str) -> None:
        assert "credit_card" not in patterns_for(policy, content), content

    def test_raw_match_is_the_card_not_the_whole_run(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("41111111111111119")
        card = next(v for v in result.violations if v.metadata["pattern"] == "credit_card")
        assert card.metadata["raw_match"] == "4111111111111111"


class TestSSNContext:
    """P6/P7 — NNN-NN-NNNN alone is indistinguishable from an invoice number."""

    @pytest.mark.parametrize(
        "content",
        [
            "SSN: 123-45-6789",
            "my SSN is 123-45-6789",
            "Employee SSN 123 45 6789",
            "social security number 123456789",
            "123-45-6789 is the SSN on file",
            "taxpayer id 123-45-6789",
            "social-security 123-45-6789",
        ],
    )
    def test_detects_ssn_with_context(self, policy: PIIPolicy, content: str) -> None:
        assert "ssn" in patterns_for(policy, content), content

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param("Invoice 555-12-3456 due", id="invoice-number"),
            pytest.param("Part 111-22-3333 in stock", id="part-number"),
            pytest.param("Order #123456789 was placed", id="order-number"),
            pytest.param("123 45 6789", id="bare-digits-no-context"),
        ],
    )
    def test_no_context_no_ssn(self, policy: PIIPolicy, content: str) -> None:
        assert "ssn" not in patterns_for(policy, content), content

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param("SSN: 000-12-3456", id="area-000"),
            pytest.param("SSN: 666-12-3456", id="area-666"),
            pytest.param("SSN 900-12-3456", id="area-900"),
            pytest.param("SSN 999-12-3456", id="area-999"),
            pytest.param("SSN 123-00-6789", id="group-00"),
            pytest.param("SSN 123-45-0000", id="serial-0000"),
        ],
    )
    def test_officially_invalid_ranges_excluded(self, policy: PIIPolicy, content: str) -> None:
        assert "ssn" not in patterns_for(policy, content), content

    def test_inconsistent_separators_rejected(self, policy: PIIPolicy) -> None:
        assert "ssn" not in patterns_for(policy, "SSN 123-45 6789")


class TestIBANValidation:
    """P6/P7 — no country-code or checksum validation, and no space tolerance."""

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param("IBAN DE89370400440532013000", id="compact"),
            pytest.param("DE89 3704 0044 0532 0130 00", id="spaced"),
            pytest.param("GB82 WEST 1234 5698 7654 32", id="gb-spaced"),
            pytest.param("NL91ABNA0417164300 is the account", id="trailing-words"),
            pytest.param("IBAN: FR1420041010050500013M02606", id="alphanumeric-bban"),
        ],
    )
    def test_detects_iban(self, policy: PIIPolicy, content: str) -> None:
        assert "iban" in patterns_for(policy, content), content

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param("ORDER DE12ABCD1234567 ref", id="wrong-length-for-country"),
            pytest.param("ZZ12ABCD1234567890", id="unknown-country-code"),
            pytest.param("DE89370400440532013001", id="bad-mod97-checksum"),
            pytest.param("SKU AB12CD3456789012345678", id="not-an-iban"),
        ],
    )
    def test_not_an_iban(self, policy: PIIPolicy, content: str) -> None:
        assert "iban" not in patterns_for(policy, content), content

    def test_raw_match_excludes_trailing_words(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("NL91ABNA0417164300 is the account")
        iban = next(v for v in result.violations if v.metadata["pattern"] == "iban")
        assert iban.metadata["raw_match"] == "NL91ABNA0417164300"


class TestPassportContext:
    """P6 — letter + 8 digits matched every SKU and ticket ID at HIGH severity."""

    @pytest.mark.parametrize(
        "content",
        [
            "Passport A12345678 issued 2020",
            "Travel document B12345678",
            "passport number: C87654321",
        ],
    )
    def test_detects_with_context(self, policy: PIIPolicy, content: str) -> None:
        assert "passport_us" in patterns_for(policy, content), content

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param("B12345678", id="bare-token"),
            pytest.param("Ticket A98765432 resolved", id="ticket-id"),
            pytest.param("SKU X11223344 in stock", id="sku"),
        ],
    )
    def test_no_context_no_passport(self, policy: PIIPolicy, content: str) -> None:
        assert "passport_us" not in patterns_for(policy, content), content


class TestPhoneTightening:
    """P6 — the old pattern matched inside a price list."""

    @pytest.mark.parametrize(
        "content",
        [
            "Call me at (415) 555-4567",
            "415-555-4567",
            "415.555.4567",
            "+1 415 555 4567",
            "phone: 415 555 4567",
            "4155554567",
        ],
    )
    def test_detects_phone(self, policy: PIIPolicy, content: str) -> None:
        assert "phone_us" in patterns_for(policy, content), content

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param("prices: 500 200 300 4000", id="price-list"),
            pytest.param("quantities 200 300 4000 units", id="quantity-list"),
            pytest.param("scores 415 555 4567 in the table", id="space-run-no-context"),
        ],
    )
    def test_space_separated_needs_phone_context(self, policy: PIIPolicy, content: str) -> None:
        assert "phone_us" not in patterns_for(policy, content), content


class TestIPVersionContext:
    """P6 — only 20 chars of prefix were inspected, so 'upgrade to' slipped through."""

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param("Server at 192.168.1.100", id="server-at"),
            pytest.param("connect to 10.20.30.40", id="connect-to"),
            pytest.param(
                "The server was updated; connect to 10.0.0.5",
                id="version-word-far-from-number",
            ),
        ],
    )
    def test_detects_ip(self, policy: PIIPolicy, content: str) -> None:
        assert "ip_address" in patterns_for(policy, content), content

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param("upgrade to 10.20.30.40", id="upgrade-to"),
            pytest.param("please update to 10.20.30.40", id="update-to"),
            pytest.param("v1.2.3.4", id="v-prefix"),
            pytest.param("build 172.16.0.1", id="build-prefix"),
            pytest.param("version 10.20.30.40", id="version-prefix"),
            pytest.param("release 8.8.8.8", id="release-prefix"),
            pytest.param("Version 999.999.999.999 released", id="invalid-octets"),
        ],
    )
    def test_version_like_is_not_an_ip(self, policy: PIIPolicy, content: str) -> None:
        assert "ip_address" not in patterns_for(policy, content), content


class TestIPv6Detection:
    """P7 — IPv6 was absent entirely."""

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param("2001:0db8:85a3:0000:0000:8a2e:0370:7334", id="full-form"),
            pytest.param("addr fe80::1ff:fe23:4567:890a", id="compressed"),
            pytest.param("2001:db8::8a2e:370:7334", id="compressed-middle"),
            pytest.param("2001:db8:: is the prefix", id="trailing-double-colon"),
        ],
    )
    def test_detects_ipv6(self, policy: PIIPolicy, content: str) -> None:
        assert "ipv6_address" in patterns_for(policy, content), content

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param("meeting at 12:30:45", id="timestamp"),
            pytest.param("MAC 00:1A:2B:3C:4D:5E", id="mac-address"),
            pytest.param("values = x[::1] reversed", id="python-slice"),
            pytest.param("std::vector<int> v;", id="cpp-namespace"),
            pytest.param("abc::def is a C++ member", id="all-hex-letters"),
            pytest.param("https://example.com:8080/path", id="url-with-port"),
            pytest.param("2001:db8:85a3:0000:0000:8a2e:0370", id="too-few-groups"),
        ],
    )
    def test_not_ipv6(self, policy: PIIPolicy, content: str) -> None:
        assert "ipv6_address" not in patterns_for(policy, content), content

    def test_can_be_disabled(self) -> None:
        policy = PIIPolicy(parameters={"disabled_patterns": ["ipv6_address"]})
        assert policy.evaluate("2001:0db8:85a3:0000:0000:8a2e:0370:7334").passed


class TestRawMatchContract:
    def test_every_violation_carries_full_raw_match(self, policy: PIIPolicy) -> None:
        content = (
            "SSN: 123-45-6789, card: 4111 1111 1111 1111, "
            "email: test@foo.com, IBAN DE89370400440532013000"
        )
        result = policy.evaluate(content)
        assert result.violations
        for violation in result.violations:
            raw = violation.metadata["raw_match"]
            assert raw in content
            assert violation.metadata["char_count"] == len(raw)
            assert raw not in (violation.matched_content or "")


class TestPerformance:
    def test_evaluation_under_5ms(self, policy: PIIPolicy) -> None:
        content = "A" * 10_000
        result = policy.evaluate(content)
        assert result.execution_time_ms < 5.0

    def test_handles_empty_string(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("")
        assert result.passed
        assert len(result.violations) == 0

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param(
                ("The quick brown fox jumps over the lazy dog. " * 2300)[:100_000],
                id="prose",
            ),
            pytest.param(
                ("4111 1111 1111 1111 3782 822463 10005 " * 2700)[:100_000],
                id="card-heavy",
            ),
            pytest.param(
                ("DE89 3704 0044 0532 0130 00 GB82WEST12345698765432 " * 2000)[:100_000],
                id="iban-heavy",
            ),
            pytest.param("DE00" + "A0" * 49_998, id="adversarial-iban"),
            pytest.param("a" * 50_000 + "@" + "b." * 25_000, id="adversarial-email"),
            pytest.param(
                ("2001:0db8:85a3:0000:0000:8a2e:0370:7334 " * 2500)[:100_000],
                id="ipv6-heavy",
            ),
        ],
    )
    def test_100kb_stays_in_tens_of_ms(self, policy: PIIPolicy, content: str) -> None:
        result = policy.evaluate(content)
        assert result.execution_time_ms < 250.0

    def test_violations_are_capped_per_pattern(self, policy: PIIPolicy) -> None:
        content = "SSN 123-45-6789. " * 400
        result = policy.evaluate(content)
        assert len(result.violations) == 100


class TestRejectedCandidatesDoNotConsumeTheCap:
    """S2: the per-pattern cap counted candidates, including rejected ones.

    `enumerate(pattern.finditer(...))` advanced on every candidate, so 100 cheap
    decoys that `_refine_match` throws away (a 16-digit run that fails Luhn, an
    SSN shape with no supporting keyword) exhausted the budget and switched the
    detector off for the rest of the window. ~1.7KB of junk was enough.
    """

    #: Fails Luhn (a valid test Visa ends 1111), so `_refine_card` rejects it.
    DECOY_CARD = "4111111111111112"
    REAL_CARD = "4111111111111111"
    #: Valid shape, no SSN keyword nearby, so `_refine_ssn` rejects it.
    DECOY_SSN = "078-05-1121"
    REAL_SSN = "078-05-1120"

    def test_decoy_card_is_not_reported(self, policy: PIIPolicy) -> None:
        """Precondition: the decoys really are rejected, not merely capped."""
        assert policy.evaluate(f"card {self.DECOY_CARD}").passed

    @pytest.mark.parametrize("decoys", [99, 100, 250, 1000])
    def test_real_card_survives_any_number_of_decoys(self, policy: PIIPolicy, decoys: int) -> None:
        content = f"{self.DECOY_CARD} " * decoys + f" card {self.REAL_CARD}"
        raws = [v.metadata.get("raw_match") for v in policy.evaluate(content).violations]
        assert self.REAL_CARD in raws, f"real card hidden by {decoys} decoys"

    @pytest.mark.parametrize("decoys", [100, 500])
    def test_real_ssn_survives_any_number_of_decoys(self, policy: PIIPolicy, decoys: int) -> None:
        content = f"{self.DECOY_SSN} " * decoys + f" SSN: {self.REAL_SSN}"
        raws = [v.metadata.get("raw_match") for v in policy.evaluate(content).violations]
        assert self.REAL_SSN in raws, f"real SSN hidden by {decoys} decoys"

    def test_the_cap_still_bounds_reported_violations(self, policy: PIIPolicy) -> None:
        """The cap must still apply — it now counts what is reported."""
        content = f"card {self.REAL_CARD}. " * 400
        cards = [
            v for v in policy.evaluate(content).violations if v.metadata["pattern"] == "credit_card"
        ]
        assert len(cards) == 100

    def test_a_wall_of_decoys_stays_cheap(self, policy: PIIPolicy) -> None:
        """The candidate bound keeps pathological input from getting expensive."""
        content = (f"{self.DECOY_CARD} " * 6_000)[:100_000]
        result = policy.evaluate(content)
        assert result.execution_time_ms < 500.0


class TestCardMatcherBoundaries:
    """S8: a 13-digit false positive, and one leading digit hiding a real card."""

    def _cards(self, policy: PIIPolicy, content: str) -> list[str]:
        return [
            v.metadata["raw_match"]
            for v in policy.evaluate(content).violations
            if v.metadata["pattern"] == "credit_card"
        ]

    def test_imei_is_not_a_visa(self, policy: PIIPolicy) -> None:
        """A 15-digit IMEI whose first 13 digits pass Luhn as a 13-digit Visa."""
        assert self._cards(policy, "IMEI 490154203237518") == []

    def test_thirteen_digit_visa_alone_is_still_detected(self, policy: PIIPolicy) -> None:
        """The FP fix must not cost the shortest legitimate format."""
        assert self._cards(policy, "card 4222222222222") == ["4222222222222"]

    def test_leading_digits_do_not_hide_a_card(self, policy: PIIPolicy) -> None:
        """`_refine_card` only tried runs anchored at the first digit."""
        assert self._cards(policy, "id=004111111111111111") == ["4111111111111111"]

    def test_non_digit_prefix_is_still_caught(self, policy: PIIPolicy) -> None:
        assert self._cards(policy, "x4111111111111111") == ["4111111111111111"]

    @pytest.mark.parametrize(
        "content",
        [
            "4111111111111111",
            "4111-1111-1111-1111",
            "4111 1111 1111 1111",
            "4111.1111.1111.1111",
            "4222222222222",
            "4012888888881881",
            "5555555555554444",
            "2223003122003222",
            "378282246310005",
            "3782 822463 10005",
            "6011111111111117",
            "3056930009020004",
            "3566002020360505",
            "6200000000000005",
        ],
    )
    def test_every_legitimate_format_still_works(self, policy: PIIPolicy, content: str) -> None:
        assert self._cards(policy, content), f"{content} no longer detected"

    def test_order_id_is_still_rejected(self, policy: PIIPolicy) -> None:
        assert self._cards(policy, "order 4111-2024-0001-5678") == []
