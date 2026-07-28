"""Generate deterministic, fabricated calibration and holdout corpora.

The two roles intentionally use independently authored template families. A
generation-time guard rejects reused planted values, document structures, or
plant contexts so future edits cannot quietly turn holdout into a seeded copy
of calibration.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import random
import re
import shutil
import string
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from xml.etree import ElementTree
from xml.sax.saxutils import escape

CORPUS_VERSION = "3.0.0"
CALIBRATION_SEED = 13_371
HOLDOUT_SEED = 91_973
CORPUS_DIR = Path(__file__).parent / "corpus"

STRUCTURE_SIGNATURE_VERSION = "3"
FABRICATION_POLICY = "reserved-and-published-test-values-v1"
TEMPLATE_FAMILIES = {
    "calibration": "configuration-and-export-calibration-v1",
    "holdout": "operations-and-casework-holdout-v1",
}

_W_NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
_S_NS = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
_A_NS = 'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"'
_P_NS = 'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"'
_R_NS = 'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
_ODF_DECL = (
    'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
    'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
    'office:version="1.3"'
)
_XML_DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'

# Published payment-network test numbers. They pass Luhn but are designated
# for testing rather than cardholder accounts. Each role receives a disjoint
# subset so holdout values cannot leak from calibration.
_CALIBRATION_TEST_CARDS = (
    "4242424242424242",
    "5555555555554444",
    "378282246310005",
    "6011111111111117",
)
_HOLDOUT_TEST_CARDS = (
    "4000056655665556",
    "5200828282828210",
    "371449635398431",
    "6011000990139424",
    "30569309025904",
)
_ALL_TEST_CARDS = _CALIBRATION_TEST_CARDS + _HOLDOUT_TEST_CARDS


@dataclass(frozen=True)
class Plant:
    file: str
    start: int
    end: int
    category: str
    is_positive: bool
    detector_id: str
    case_id: str


@dataclass(frozen=True)
class CorpusDocument:
    relative_path: str
    content: bytes


@dataclass(frozen=True)
class CorpusBundle:
    role: str
    seed: int
    documents: tuple[CorpusDocument, ...]
    plants: tuple[Plant, ...]


class DocumentBuilder:
    def __init__(self, relative_path: str) -> None:
        self.relative_path = relative_path
        self.text = ""
        self.plants: list[Plant] = []

    def line(self, text: str = "") -> DocumentBuilder:
        self.text += text + "\n"
        return self

    def plant_line(
        self,
        before: str,
        value: str,
        after: str,
        *,
        category: str,
        detector_id: str,
        case_id: str,
        is_positive: bool,
    ) -> DocumentBuilder:
        self.text += before
        start = len(self.text)
        self.text += value
        end = len(self.text)
        self.plants.append(
            Plant(
                file=self.relative_path,
                start=start,
                end=end,
                category=category,
                is_positive=is_positive,
                detector_id=detector_id,
                case_id=case_id,
            )
        )
        self.text += after + "\n"
        return self

    def as_text_document(self) -> CorpusDocument:
        # Encoding an explicitly assembled string keeps fixture line endings LF
        # on every host, unlike platform-default text writers.
        return CorpusDocument(self.relative_path, self.text.encode("utf-8"))

    def as_structured_document(self, format_name: str, role: str) -> CorpusDocument:
        text = self.text.removesuffix("\n")
        makers = {
            ("calibration", "docx"): _make_calibration_docx,
            ("calibration", "xlsx"): _make_calibration_xlsx,
            ("calibration", "pptx"): _make_calibration_pptx,
            ("calibration", "odt"): _make_calibration_odt,
            ("holdout", "docx"): _make_holdout_docx,
            ("holdout", "xlsx"): _make_holdout_xlsx,
            ("holdout", "pptx"): _make_holdout_pptx,
            ("holdout", "odt"): _make_holdout_odt,
        }
        return CorpusDocument(self.relative_path, makers[(role, format_name)](text))


def _random_token(rng: random.Random, length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(rng.choice(alphabet) for _ in range(length))


def _fake_password(rng: random.Random, length: int = 16) -> str:
    return _random_token(rng, length - 2) + "!7"


def _fake_aws_key(rng: random.Random, role: str) -> str:
    # The EXAMPLE suffix makes these recognizable fixture identifiers. Access
    # key IDs are not authenticators without their (absent) secret key.
    family = "C" if role == "calibration" else "H"
    prefix = family + "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    return "AKIA" + prefix + "EXAMPLE"


def _fake_jwt(rng: random.Random) -> str:
    # Deliberately not a signed JWT; it only exercises the detector's shape.
    return f"ey{_random_token(rng, 20)}.{_random_token(rng, 24)}.{_random_token(rng, 30)}"


def _fake_connection_string(rng: random.Random, role: str) -> str:
    user = "calibration_svc" if role == "calibration" else "holdout_worker"
    return f"postgres://{user}:{_fake_password(rng, 12)}@db.{role}.fabricated.invalid:5432/app"


def _fake_ssn(rng: random.Random, role: str) -> str:
    # SSA never assigns areas 900-999. Split that reserved range between roles.
    area = rng.randint(900, 949) if role == "calibration" else rng.randint(950, 999)
    return f"{area:03d}-{rng.randint(1, 99):02d}-{rng.randint(1, 9999):04d}"


def fake_valid_card_number(rng: random.Random | None = None) -> str:
    """Return a published payment test number, never a generated account."""

    rng = rng or random.Random(CALIBRATION_SEED)
    return rng.choice(_ALL_TEST_CARDS)


def fake_invalid_card_number(rng: random.Random | None = None) -> str:
    valid = fake_valid_card_number(rng)
    return valid[:-1] + str((int(valid[-1]) + 1) % 10)


def _test_card(role: str, index: int) -> str:
    values = _CALIBRATION_TEST_CARDS if role == "calibration" else _HOLDOUT_TEST_CARDS
    return values[index]


def _fake_email(rng: random.Random, role: str) -> str:
    return f"{role}-person-{rng.randint(100, 999)}@fabricated.invalid"


def _fake_phone(rng: random.Random, role: str) -> str:
    # NANPA reserves 555-0100 through 555-0199 for fictional use.
    area = "202" if role == "calibration" else "303"
    return f"{area}-555-{rng.randint(100, 199):04d}"


def _fake_private_key(rng: random.Random) -> str:
    body = "\n".join(_random_token(rng, 60) for _ in range(2))
    return f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"


def _benign_base64(rng: random.Random, role: str) -> str:
    payload = f"{role} public fixture asset {_random_token(rng, 36)}".encode()
    return base64.b64encode(payload).decode()


def _calibration_positive_documents(rng: random.Random) -> list[DocumentBuilder]:
    """Configuration/export scenarios used only for calibration."""

    settings = DocumentBuilder("python_service/app/settings.py")
    settings.plant_line(
        'PRODUCTION_PASSWORD = "',
        _fake_password(rng),
        '"',
        category="credential",
        detector_id="password_assignment",
        case_id="calibration-password-production",
        is_positive=True,
    )
    settings.plant_line(
        'AWS_ACCESS_KEY_ID = "',
        _fake_aws_key(rng, "calibration"),
        '"',
        category="credential",
        detector_id="aws_access_key",
        case_id="calibration-aws-service",
        is_positive=True,
    )
    settings.plant_line(
        'DATABASE_URL = "',
        _fake_connection_string(rng, "calibration"),
        '"',
        category="credential",
        detector_id="connection_string",
        case_id="calibration-connection-service",
        is_positive=True,
    )

    react = DocumentBuilder("react_application/.env.local")
    react.plant_line(
        "VITE_ADMIN_PASSWORD=",
        _fake_password(rng),
        "",
        category="credential",
        detector_id="password_assignment",
        case_id="calibration-password-react",
        is_positive=True,
    )
    react.plant_line(
        "VITE_SESSION_TOKEN=",
        _fake_jwt(rng),
        "",
        category="credential",
        detector_id="jwt",
        case_id="calibration-jwt-react",
        is_positive=True,
    )
    react.plant_line(
        "VITE_AWS_ACCESS_KEY_ID=",
        _fake_aws_key(rng, "calibration"),
        "",
        category="credential",
        detector_id="aws_access_key",
        case_id="calibration-aws-react",
        is_positive=True,
    )

    infra = DocumentBuilder("infrastructure/environments/prod.tfvars")
    infra.plant_line(
        'database_password = "',
        _fake_password(rng),
        '"',
        category="credential",
        detector_id="password_assignment",
        case_id="calibration-password-infra",
        is_positive=True,
    )
    infra.plant_line(
        'service_connection = "',
        _fake_connection_string(rng, "calibration"),
        '"',
        category="credential",
        detector_id="connection_string",
        case_id="calibration-connection-infra",
        is_positive=True,
    )

    auth = DocumentBuilder("python_service/app/auth_cache.log")
    for index in range(2):
        auth.plant_line(
            "authorization bearer ",
            _fake_jwt(rng),
            "",
            category="credential",
            detector_id="jwt",
            case_id=f"calibration-jwt-{index}",
            is_positive=True,
        )

    identities = DocumentBuilder("data_exports/customer_identities.csv")
    identities.line("customer_id,ssn")
    for index in range(3):
        identities.plant_line(
            f"fabricated-{index},",
            _fake_ssn(rng, "calibration"),
            "",
            category="personal_id",
            detector_id="us_ssn",
            case_id=f"calibration-ssn-{index}",
            is_positive=True,
        )

    billing = DocumentBuilder("data_exports/billing_records.csv")
    billing.line("customer,card_on_file")
    for index in range(3):
        billing.plant_line(
            f"fabricated-{index},",
            _test_card("calibration", index),
            "",
            category="financial",
            detector_id="credit_card",
            case_id=f"calibration-card-{index}",
            is_positive=True,
        )

    contacts = DocumentBuilder("support/private_contact_export.txt")
    for index in range(2):
        contacts.plant_line(
            "Best personal contact email is ",
            _fake_email(rng, "calibration"),
            ".",
            category="personal_id",
            detector_id="email",
            case_id=f"calibration-email-{index}",
            is_positive=True,
        )
        contacts.plant_line(
            "Call the customer at ",
            _fake_phone(rng, "calibration"),
            ".",
            category="personal_id",
            detector_id="phone",
            case_id=f"calibration-phone-{index}",
            is_positive=True,
        )

    opaque_builders = []
    for index in range(2):
        opaque = DocumentBuilder(f"worker/cache/opaque_payload_{index}.txt")
        opaque.plant_line(
            "opaque_value = ",
            _random_token(rng, 40),
            "",
            category="credential",
            detector_id="high_entropy_secret",
            case_id=f"calibration-entropy-{index}",
            is_positive=True,
        )
        opaque_builders.append(opaque)

    private_key = DocumentBuilder("security/backup_signing_key.pem")
    private_key.plant_line(
        "# calibration signing material\n",
        _fake_private_key(rng),
        "",
        category="credential",
        detector_id="private_key_header",
        case_id="calibration-private-key",
        is_positive=True,
    )
    return [
        settings,
        react,
        infra,
        auth,
        identities,
        billing,
        contacts,
        *opaque_builders,
        private_key,
    ]


def _holdout_positive_documents(rng: random.Random) -> list[DocumentBuilder]:
    """Operations/casework scenarios authored independently for holdout."""

    secret_inventory = DocumentBuilder("python_service/control/secrets/active_credentials.yaml")
    secret_inventory.plant_line(
        "payments_admin_password: ",
        _fake_password(rng),
        "",
        category="credential",
        detector_id="password_assignment",
        case_id="holdout-password-production",
        is_positive=True,
    )
    secret_inventory.plant_line(
        "cloud_access_identifier: ",
        _fake_aws_key(rng, "holdout"),
        "",
        category="credential",
        detector_id="aws_access_key",
        case_id="holdout-aws-service",
        is_positive=True,
    )
    secret_inventory.plant_line(
        "primary_ledger_dsn: ",
        _fake_connection_string(rng, "holdout"),
        "",
        category="credential",
        detector_id="connection_string",
        case_id="holdout-connection-service",
        is_positive=True,
    )

    bootstrap = DocumentBuilder("react_application/runtime/bootstrap.js")
    bootstrap.plant_line(
        "window.liveSupportSecret = ",
        _fake_password(rng),
        ";",
        category="credential",
        detector_id="password_assignment",
        case_id="holdout-password-react",
        is_positive=True,
    )
    bootstrap.plant_line(
        "window.sessionEnvelope = ",
        _fake_jwt(rng),
        ";",
        category="credential",
        detector_id="jwt",
        case_id="holdout-jwt-react",
        is_positive=True,
    )
    bootstrap.plant_line(
        "window.cloudPrincipal = ",
        _fake_aws_key(rng, "holdout"),
        ";",
        category="credential",
        detector_id="aws_access_key",
        case_id="holdout-aws-react",
        is_positive=True,
    )

    overlay = DocumentBuilder(
        "infrastructure/deployment_manifests/overlays/customer-api/sealed-values.conf"
    )
    overlay.plant_line(
        "live_worker_pwd: ",
        _fake_password(rng),
        "",
        category="credential",
        detector_id="password_assignment",
        case_id="holdout-password-infra",
        is_positive=True,
    )
    overlay.plant_line(
        "replication_endpoint: ",
        _fake_connection_string(rng, "holdout"),
        "",
        category="credential",
        detector_id="connection_string",
        case_id="holdout-connection-infra",
        is_positive=True,
    )

    traces = DocumentBuilder("edge_observability/traces/authentication_events.ndjson")
    for index in range(3):
        traces.plant_line(
            f'{{"event":"accepted-session-{index}","jwt":"',
            _fake_jwt(rng),
            '"}',
            category="credential",
            detector_id="jwt",
            case_id=f"holdout-jwt-{index}",
            is_positive=True,
        )

    subjects = DocumentBuilder("compliance_exports/access_reviews/subjects.ndjson")
    for index in range(2):
        subjects.plant_line(
            f'{{"subject":"fabricated-{index}","ssn":"',
            _fake_ssn(rng, "holdout"),
            '"}',
            category="personal_id",
            detector_id="us_ssn",
            case_id=f"holdout-ssn-{index}",
            is_positive=True,
        )

    snapshots = DocumentBuilder("finance_reconciliation/cardholder_snapshots.psv")
    for index in range(4):
        snapshots.plant_line(
            f"account-{index}|retained payment card|",
            _test_card("holdout", index),
            "|open",
            category="financial",
            detector_id="credit_card",
            case_id=f"holdout-card-{index}",
            is_positive=True,
        )

    escalations = DocumentBuilder("customer_success/escalations/open_cases.md")
    for index in range(3):
        escalations.plant_line(
            f"- Customer {index} escalation email: ",
            _fake_email(rng, "holdout"),
            "",
            category="personal_id",
            detector_id="email",
            case_id=f"holdout-email-{index}",
            is_positive=True,
        )
        escalations.plant_line(
            f"- Customer {index} mobile callback: ",
            _fake_phone(rng, "holdout"),
            "",
            category="personal_id",
            detector_id="phone",
            case_id=f"holdout-phone-{index}",
            is_positive=True,
        )

    lease = DocumentBuilder("job_orchestration/state/lease_record.json")
    lease.plant_line(
        '{"active_lease_api_key":"',
        _random_token(rng, 40),
        '"}',
        category="credential",
        detector_id="high_entropy_secret",
        case_id="holdout-entropy-0",
        is_positive=True,
    )

    private_key = DocumentBuilder("identity_material/offline/recovery-signing.pem")
    private_key.plant_line(
        "Recovery identity material follows:\n",
        _fake_private_key(rng),
        "",
        category="credential",
        detector_id="private_key_header",
        case_id="holdout-private-key",
        is_positive=True,
    )
    return [
        secret_inventory,
        bootstrap,
        overlay,
        traces,
        subjects,
        snapshots,
        escalations,
        lease,
        private_key,
    ]


def _calibration_negative_documents(rng: random.Random) -> list[DocumentBuilder]:
    """Suppressor examples used to choose the operating threshold."""

    values = DocumentBuilder("benign_project/build_and_runtime_ids.txt")
    values.plant_line(
        "migration_reference = ",
        "666-41-1201",
        "  # legacy report identifier, not a person",
        category="personal_id",
        detector_id="us_ssn",
        case_id="calibration-negative-ssn-shaped-id",
        is_positive=False,
    )
    values.plant_line(
        "build_uuid = ",
        "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        "",
        category="credential",
        detector_id="high_entropy_secret",
        case_id="calibration-negative-uuid",
        is_positive=False,
    )
    values.plant_line(
        "migration_id = ",
        "20260716_143522_add_customer_index",
        "",
        category="credential",
        detector_id="high_entropy_secret",
        case_id="calibration-negative-migration",
        is_positive=False,
    )

    public_contact = DocumentBuilder("documentation/public_contact.md")
    public_contact.plant_line(
        "Contact the documentation team at ",
        "docs-calibration@fabricated.invalid",
        ".",
        category="personal_id",
        detector_id="email",
        case_id="calibration-negative-public-email",
        is_positive=False,
    )
    public_contact.plant_line(
        "Call the public switchboard at ",
        "212-555-0100",
        ".",
        category="personal_id",
        detector_id="phone",
        case_id="calibration-negative-public-phone",
        is_positive=False,
    )

    lockfile = DocumentBuilder("react_application/package-lock.json")
    lockfile.plant_line(
        '"integrity": "sha512-',
        _random_token(rng, 48),
        '",',
        category="credential",
        detector_id="high_entropy_secret",
        case_id="calibration-negative-lock-integrity",
        is_positive=False,
    )
    lockfile.plant_line(
        '"resolved": "https://registry.calibration.invalid/pkg.tgz?cache=',
        _random_token(rng, 32),
        '"',
        category="credential",
        detector_id="high_entropy_secret",
        case_id="calibration-negative-long-url",
        is_positive=False,
    )

    encoded = DocumentBuilder("documentation/encoded_examples.txt")
    encoded.plant_line(
        "benign_base64_asset = ",
        _benign_base64(rng, "calibration"),
        "",
        category="credential",
        detector_id="high_entropy_secret",
        case_id="calibration-negative-base64",
        is_positive=False,
    )

    examples = DocumentBuilder("python_service/tests/fixtures/example_credentials.py")
    examples.plant_line(
        "# example password used only in tests\npassword = ",
        _fake_password(rng),
        "",
        category="credential",
        detector_id="password_assignment",
        case_id="calibration-negative-test-password",
        is_positive=False,
    )
    examples.plant_line(
        "# sample AWS access key\naws_access_key_id = ",
        _fake_aws_key(rng, "calibration"),
        "",
        category="credential",
        detector_id="aws_access_key",
        case_id="calibration-negative-test-aws",
        is_positive=False,
    )
    examples.plant_line(
        "# fake database connection example\nDATABASE_URL = ",
        _fake_connection_string(rng, "calibration"),
        "",
        category="credential",
        detector_id="connection_string",
        case_id="calibration-negative-example-connection",
        is_positive=False,
    )

    placeholder = DocumentBuilder("react_application/.env.example")
    placeholder.plant_line(
        "ADMIN_PASSWORD=",
        f"replace-before-use-{_random_token(rng, 20)}",
        " # documentation placeholder",
        category="credential",
        detector_id="password_assignment",
        case_id="calibration-negative-placeholder-password",
        is_positive=False,
    )
    placeholder.plant_line(
        "DATABASE_URL=",
        "postgres://calibration_docs:placeholder@db.example.fabricated.invalid:5432/example",
        " # example only",
        category="credential",
        detector_id="connection_string",
        case_id="calibration-negative-email-shaped-connection",
        is_positive=False,
    )

    timestamps = DocumentBuilder("operations/application.log")
    timestamps.line("2026-07-16T14:35:22.182Z INFO migration completed")
    timestamps.line("request_id=018f67a3-9da9-73c1-8b12-3e725f0ba8e0 status=200")
    timestamps.line("artifact=9f86d081884c7d659a2feaa0c55ad015 path=/health")
    return [values, public_contact, lockfile, encoded, examples, placeholder, timestamps]


def _holdout_negative_documents(rng: random.Random) -> list[DocumentBuilder]:
    """Independently phrased decoys that are not calibration templates."""

    registry = DocumentBuilder("release_tools/reference/fixture_registry.yaml")
    registry.plant_line(
        "non_person_legacy_code: ",
        "000-73-8246",
        " # migration fixture, not a person",
        category="personal_id",
        detector_id="us_ssn",
        case_id="holdout-negative-ssn-shaped-id",
        is_positive=False,
    )
    registry.plant_line(
        "namespace_uuid: ",
        "6ba7b811-9dad-11d1-80b4-00c04fd430c8",
        "",
        category="credential",
        detector_id="high_entropy_secret",
        case_id="holdout-negative-uuid",
        is_positive=False,
    )
    registry.plant_line(
        "schema_migration_label: ",
        "20260804_090711_rebuild_search_catalog",
        "",
        category="credential",
        detector_id="high_entropy_secret",
        case_id="holdout-negative-migration",
        is_positive=False,
    )

    handbook = DocumentBuilder("documentation/help_center/handbook/community_channels.md")
    handbook.plant_line(
        "Public help email (not customer data): ",
        "community-holdout@fabricated.invalid",
        "",
        category="personal_id",
        detector_id="email",
        case_id="holdout-negative-public-email",
        is_positive=False,
    )
    handbook.plant_line(
        "Published example hotline: ",
        "415-555-0198",
        "",
        category="personal_id",
        detector_id="phone",
        case_id="holdout-negative-public-phone",
        is_positive=False,
    )

    dependency_record = DocumentBuilder("web_client/vendor/pnpm-lock.yaml")
    dependency_record.plant_line(
        "resolution_integrity: sha512-",
        _random_token(rng, 48),
        "",
        category="credential",
        detector_id="high_entropy_secret",
        case_id="holdout-negative-lock-integrity",
        is_positive=False,
    )
    dependency_record.plant_line(
        "tarball_cache_url: https://packages.holdout.invalid/archive.tgz?digest=",
        _random_token(rng, 32),
        "",
        category="credential",
        detector_id="high_entropy_secret",
        case_id="holdout-negative-long-url",
        is_positive=False,
    )

    media_notes = DocumentBuilder("documentation/help_center/assets/embedding_notes.md")
    media_notes.plant_line(
        "Documentation sample image payload: ",
        _benign_base64(rng, "holdout"),
        "",
        category="credential",
        detector_id="high_entropy_secret",
        case_id="holdout-negative-base64",
        is_positive=False,
    )

    tutorial = DocumentBuilder("sdk_sandbox/samples/tutorial_secrets.toml")
    tutorial.plant_line(
        "# sample value for tests only\ntutorial_password: ",
        _fake_password(rng),
        "",
        category="credential",
        detector_id="password_assignment",
        case_id="holdout-negative-test-password",
        is_positive=False,
    )
    tutorial.plant_line(
        "# example cloud identifier for tests\ntutorial_cloud_id: ",
        _fake_aws_key(rng, "holdout"),
        "",
        category="credential",
        detector_id="aws_access_key",
        case_id="holdout-negative-test-aws",
        is_positive=False,
    )
    tutorial.plant_line(
        "# sample connection, never deployed\ntutorial_dsn: ",
        _fake_connection_string(rng, "holdout"),
        "",
        category="credential",
        detector_id="connection_string",
        case_id="holdout-negative-example-connection",
        is_positive=False,
    )

    onboarding = DocumentBuilder("deployment_templates/starter-values.example.yaml")
    onboarding.plant_line(
        "starter_secret: ",
        f"placeholder-docs-{_random_token(rng, 20)}",
        " # replace before use",
        category="credential",
        detector_id="password_assignment",
        case_id="holdout-negative-placeholder-password",
        is_positive=False,
    )
    onboarding.plant_line(
        "sample_endpoint: ",
        "mysql://holdout_reader:placeholder@tutorial.fabricated.invalid:3306/walkthrough",
        " # documentation example",
        category="credential",
        detector_id="connection_string",
        case_id="holdout-negative-email-shaped-connection",
        is_positive=False,
    )

    telemetry = DocumentBuilder("site_reliability/archive/worker-events.log")
    telemetry.line("event_at=2026-08-04T09:07:11.442Z result=checkpointed")
    telemetry.line("trace=01914f23-7e16-73a1-bc09-20a1e9bba6a4 worker=thumbnailer")
    telemetry.line("object=2c26b46b68ffc68ff99b453c1d304134 queue=public-assets")
    return [registry, handbook, dependency_record, media_notes, tutorial, onboarding, telemetry]


def _calibration_structured_documents(
    rng: random.Random,
) -> list[tuple[DocumentBuilder, str]]:
    cases = [
        (
            "office_documents/customer_notes.docx",
            "docx",
            "us_ssn",
            "personal_id",
            _fake_ssn(rng, "calibration"),
            "customer ssn: ",
        ),
        (
            "office_documents/billing_export.xlsx",
            "xlsx",
            "credit_card",
            "financial",
            _test_card("calibration", 3),
            "card on file: ",
        ),
        (
            "office_documents/support_briefing.pptx",
            "pptx",
            "email",
            "personal_id",
            _fake_email(rng, "calibration"),
            "personal contact email: ",
        ),
        (
            "office_documents/field_notes.odt",
            "odt",
            "phone",
            "personal_id",
            _fake_phone(rng, "calibration"),
            "call customer phone: ",
        ),
    ]
    builders = []
    for index, (path, format_name, detector_id, category, value, context) in enumerate(cases):
        builder = DocumentBuilder(path)
        builder.plant_line(
            context,
            value,
            "",
            category=category,
            detector_id=detector_id,
            case_id=f"calibration-structured-{index}-{format_name}",
            is_positive=True,
        )
        builders.append((builder, format_name))
    return builders


def _holdout_structured_documents(rng: random.Random) -> list[tuple[DocumentBuilder, str]]:
    cases = [
        (
            "office_documents/casework/identity/verification_record.docx",
            "docx",
            "us_ssn",
            "personal_id",
            _fake_ssn(rng, "holdout"),
            "Identity-verification record includes SSN ",
        ),
        (
            "office_documents/casework/finance/reconciliation_sample.xlsx",
            "xlsx",
            "credit_card",
            "financial",
            _test_card("holdout", 4),
            "Reconciliation worksheet retained payment card ",
        ),
        (
            "office_documents/casework/escalations/on_call_rotation.pptx",
            "pptx",
            "email",
            "personal_id",
            _fake_email(rng, "holdout"),
            "Escalation owner can be reached by email at ",
        ),
        (
            "office_documents/casework/field/callback_queue.odt",
            "odt",
            "phone",
            "personal_id",
            _fake_phone(rng, "holdout"),
            "Callback queue lists mobile number ",
        ),
    ]
    builders = []
    for index, (path, format_name, detector_id, category, value, context) in enumerate(cases):
        builder = DocumentBuilder(path)
        builder.plant_line(
            context,
            value,
            "",
            category=category,
            detector_id=detector_id,
            case_id=f"holdout-structured-{index}-{format_name}",
            is_positive=True,
        )
        builders.append((builder, format_name))
    return builders


def _calibration_clean_documents() -> list[DocumentBuilder]:
    texts = [
        "The service retries transient requests with bounded exponential backoff.",
        "The React dashboard renders account status and recent activity.",
        "Infrastructure changes require review before the production apply step.",
        "Documentation examples use reserved domains and labelled placeholder values.",
        "The release checklist records owners, dates, and rollback instructions.",
    ]
    builders = []
    for index, value in enumerate(texts):
        builder = DocumentBuilder(f"clean_documents/calibration_notes_{index}.md")
        builder.line(value).line("").line("Calibration hygiene note: no sensitive data is present.")
        builders.append(builder)
    return builders


def _holdout_clean_documents() -> list[DocumentBuilder]:
    texts = [
        "Workers persist idempotency markers only after durable queue acknowledgement.",
        "The case-routing view groups tickets by service region and response window.",
        "Deployment overlays inherit resource limits from the approved baseline.",
        "The community handbook directs public questions to published channels.",
        "Recovery exercises record elapsed time and the responsible incident role.",
        "Static media is fingerprinted before it reaches the delivery cache.",
        "Search indexing resumes from a monotonic checkpoint after maintenance.",
    ]
    builders = []
    for index, value in enumerate(texts):
        builder = DocumentBuilder(f"reference_material/holdout_operations_{index}.md")
        builder.line("Operational reference entry:").line(value).line("End of public procedure.")
        builders.append(builder)
    return builders


def _build_bundle(
    role: str,
    seed: int,
    text_builders: list[DocumentBuilder],
    structured: list[tuple[DocumentBuilder, str]],
) -> CorpusBundle:
    documents = [builder.as_text_document() for builder in text_builders]
    documents.extend(
        builder.as_structured_document(format_name, role) for builder, format_name in structured
    )
    plants = [plant for builder in text_builders for plant in builder.plants]
    plants.extend(plant for builder, _ in structured for plant in builder.plants)
    return CorpusBundle(role, seed, tuple(documents), tuple(plants))


def _generate_calibration(seed: int) -> CorpusBundle:
    rng = random.Random(seed)
    return _build_bundle(
        "calibration",
        seed,
        [
            *_calibration_positive_documents(rng),
            *_calibration_negative_documents(rng),
            *_calibration_clean_documents(),
        ],
        _calibration_structured_documents(rng),
    )


def _generate_holdout(seed: int) -> CorpusBundle:
    rng = random.Random(seed)
    return _build_bundle(
        "holdout",
        seed,
        [
            *_holdout_positive_documents(rng),
            *_holdout_negative_documents(rng),
            *_holdout_clean_documents(),
        ],
        _holdout_structured_documents(rng),
    )


def generate_role(role: str, seed: int) -> CorpusBundle:
    generators = {
        "calibration": _generate_calibration,
        "holdout": _generate_holdout,
    }
    try:
        return generators[role](seed)
    except KeyError as error:
        raise ValueError(f"unknown corpus role: {role}") from error


def _document_text(document: CorpusDocument) -> str:
    suffix = Path(document.relative_path).suffix.lower()
    if suffix not in {".docx", ".xlsx", ".pptx", ".odt"}:
        return document.content.decode("utf-8")
    member = {
        ".docx": "word/document.xml",
        ".xlsx": "xl/worksheets/sheet1.xml",
        ".pptx": "ppt/slides/slide1.xml",
        ".odt": "content.xml",
    }[suffix]
    with zipfile.ZipFile(io.BytesIO(document.content)) as archive:
        root = ElementTree.fromstring(archive.read(member))
    return "".join(root.itertext())


def _normalize_shape(value: str) -> str:
    return re.sub(r"\s+", " ", value.casefold()).strip()


def _xml_topology(element: ElementTree.Element) -> list:
    """Return XML structure without visible text or role-specific values.

    Element and attribute names plus child ordering describe package topology.
    Attribute values are deliberately excluded: changing a sheet/shape label
    must not disguise reuse of the same underlying layout.
    """

    return [
        element.tag,
        sorted(element.attrib),
        [_xml_topology(child) for child in element],
    ]


def _structured_topology_signature(document: CorpusDocument) -> str | None:
    suffix = Path(document.relative_path).suffix.casefold()
    if suffix not in {".docx", ".xlsx", ".pptx", ".odt"}:
        return None

    members = []
    with zipfile.ZipFile(io.BytesIO(document.content)) as archive:
        for info in sorted(archive.infolist(), key=lambda item: item.filename):
            content = archive.read(info)
            try:
                topology = _xml_topology(ElementTree.fromstring(content))
            except ElementTree.ParseError:
                # The member name already captures its package role. Payload
                # bytes are intentionally excluded so swapping an image or
                # other opaque asset cannot disguise reuse of the same layout.
                topology = ["opaque"]
            members.append([info.filename, topology])
    encoded = json.dumps([suffix, members], sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _bundle_signatures(
    bundle: CorpusBundle,
) -> tuple[set[str], set[str], set[str], set[str]]:
    documents = {document.relative_path: document for document in bundle.documents}
    plants_by_file: dict[str, list[Plant]] = {}
    planted_values: set[str] = set()
    context_signatures: set[str] = set()
    document_signatures: set[str] = set()
    structured_topology_signatures: set[str] = set()

    for plant in bundle.plants:
        plants_by_file.setdefault(plant.file, []).append(plant)

    for relative_path, document in documents.items():
        text = _document_text(document)
        if topology := _structured_topology_signature(document):
            structured_topology_signatures.add(topology)
        file_plants = sorted(plants_by_file.get(relative_path, []), key=lambda item: item.start)
        for plant in file_plants:
            planted_value = text[plant.start : plant.end]
            planted_values.add(planted_value)
            line_start = text.rfind("\n", 0, plant.start) + 1
            line_end = text.find("\n", plant.end)
            if line_end < 0:
                line_end = len(text)
            before = text[line_start : plant.start]
            after = text[plant.end : line_end]
            if not before and "\n" in planted_value and line_start:
                previous_line_start = text.rfind("\n", 0, max(0, line_start - 1)) + 1
                before = text[previous_line_start : plant.start]
            context_signatures.add(_normalize_shape(f"{before}<planted-value>{after}"))

        shaped = text
        for plant in reversed(file_plants):
            shaped = shaped[: plant.start] + "<planted-value>" + shaped[plant.end :]
        suffix = Path(relative_path).suffix.casefold()
        document_signatures.add(_normalize_shape(f"{suffix}|{shaped}"))
    return (
        planted_values,
        context_signatures,
        document_signatures,
        structured_topology_signatures,
    )


def role_separation_evidence(
    calibration: CorpusBundle, holdout: CorpusBundle
) -> dict[str, list[str] | str]:
    """Return deterministic overlap evidence for the independence gate."""

    (
        calibration_values,
        calibration_contexts,
        calibration_documents,
        calibration_topologies,
    ) = _bundle_signatures(calibration)
    (
        holdout_values,
        holdout_contexts,
        holdout_documents,
        holdout_topologies,
    ) = _bundle_signatures(holdout)
    return {
        "signature_version": STRUCTURE_SIGNATURE_VERSION,
        "planted_value_overlaps": sorted(calibration_values & holdout_values),
        "plant_context_overlaps": sorted(calibration_contexts & holdout_contexts),
        "document_structure_overlaps": sorted(calibration_documents & holdout_documents),
        "structured_topology_overlaps": sorted(calibration_topologies & holdout_topologies),
    }


def validate_role_separation(calibration: CorpusBundle, holdout: CorpusBundle) -> None:
    evidence = role_separation_evidence(calibration, holdout)
    overlap_keys = (
        "planted_value_overlaps",
        "plant_context_overlaps",
        "document_structure_overlaps",
        "structured_topology_overlaps",
    )
    failures = {key: evidence[key] for key in overlap_keys if evidence[key]}
    if failures:
        raise ValueError(f"calibration/holdout independence guard failed: {failures}")


def generate_all() -> dict[str, CorpusBundle]:
    bundles = {
        "calibration": generate_role("calibration", CALIBRATION_SEED),
        "holdout": generate_role("holdout", HOLDOUT_SEED),
    }
    validate_role_separation(bundles["calibration"], bundles["holdout"])
    return bundles


def _bundle_digest(bundle: CorpusBundle) -> str:
    digest = hashlib.sha256()
    for document in sorted(bundle.documents, key=lambda item: item.relative_path):
        digest.update(document.relative_path.encode())
        digest.update(b"\0")
        digest.update(document.content)
    labels = json.dumps(
        [asdict(plant) for plant in bundle.plants],
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    digest.update(labels)
    return digest.hexdigest()


def manifest_for(bundle: CorpusBundle) -> dict:
    return {
        "corpus_version": CORPUS_VERSION,
        "role": bundle.role,
        "seed": bundle.seed,
        "template_family": TEMPLATE_FAMILIES[bundle.role],
        "structure_signature_version": STRUCTURE_SIGNATURE_VERSION,
        "fabrication_policy": FABRICATION_POLICY,
        "document_count": len(bundle.documents),
        "positive_plant_count": sum(plant.is_positive for plant in bundle.plants),
        "decoy_plant_count": sum(not plant.is_positive for plant in bundle.plants),
        "sha256": _bundle_digest(bundle),
    }


def write_bundle(bundle: CorpusBundle, destination: Path) -> None:
    documents_dir = destination / "documents"
    if destination.exists():
        for path in sorted(destination.rglob("*"), reverse=True):
            if path.is_file():
                path.unlink()
            else:
                path.rmdir()
    documents_dir.mkdir(parents=True, exist_ok=True)
    for document in bundle.documents:
        path = documents_dir / document.relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(document.content)
    (destination / "labels.json").write_bytes(
        json.dumps([asdict(plant) for plant in bundle.plants], indent=2).encode("utf-8") + b"\n"
    )
    (destination / "manifest.json").write_bytes(
        json.dumps(manifest_for(bundle), indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )


def write_all_corpora(destination: Path = CORPUS_DIR) -> dict[str, dict]:
    _remove_legacy_root_artifacts(destination)
    manifests = {}
    for role, bundle in generate_all().items():
        write_bundle(bundle, destination / role)
        manifests[role] = manifest_for(bundle)
    return manifests


def _remove_legacy_root_artifacts(destination: Path) -> None:
    """Remove the obsolete single-corpus layout from a corpus root.

    Version 1 wrote ``documents/`` and ``labels.json`` directly below the
    corpus root. Leaving those files beside the role-separated corpora is
    misleading and can retain values that do not satisfy the current
    fabrication policy.
    """

    legacy_documents = destination / "documents"
    if legacy_documents.is_symlink() or legacy_documents.is_file():
        legacy_documents.unlink()
    elif legacy_documents.is_dir():
        shutil.rmtree(legacy_documents)
    for name in ("labels.json", "manifest.json"):
        legacy_file = destination / name
        if legacy_file.is_file() or legacy_file.is_symlink():
            legacy_file.unlink()


def _zip_bytes(members: dict[str, str | bytes]) -> bytes:
    """Return a byte-stable package independent of the host OS.

    Stored members avoid zlib-version drift. Explicit DOS metadata prevents
    Unix permission bits, timestamps, insertion order, or creator platform
    from changing the bytes. ODF's mimetype member is always first as required.
    """

    ordered_names = sorted(members, key=lambda name: (name != "mimetype", name))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.comment = b""
        for name in ordered_names:
            content = members[name]
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 0
            info.external_attr = 0x20
            info.internal_attr = 0
            info.extra = b""
            info.comment = b""
            archive.writestr(info, content.encode("utf-8") if isinstance(content, str) else content)
    return buffer.getvalue()


def _opc_content_types(overrides: list[tuple[str, str]]) -> str:
    entries = "".join(
        f'<Override PartName="{part}" ContentType="{content_type}"/>'
        for part, content_type in overrides
    )
    return (
        _XML_DECL
        + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        + '<Default Extension="rels" '
        'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        + '<Default Extension="xml" ContentType="application/xml"/>'
        + entries
        + "</Types>"
    )


def _root_relationship(target: str, relationship_type: str) -> str:
    return (
        _XML_DECL
        + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + f'<Relationship Id="rId1" Type="{relationship_type}" Target="{target}"/>'
        + "</Relationships>"
    )


def _docx_package(document: str) -> bytes:
    content_types = _opc_content_types(
        [
            (
                "/word/document.xml",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
            )
        ]
    )
    relationships = _root_relationship(
        "word/document.xml",
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument",
    )
    return _zip_bytes(
        {
            "[Content_Types].xml": content_types,
            "_rels/.rels": relationships,
            "word/document.xml": document,
        }
    )


def _make_calibration_docx(text: str) -> bytes:
    document = (
        _XML_DECL
        + f"<w:document {_W_NS}><w:body><w:p><w:r>"
        + f'<w:t xml:space="preserve">{escape(text)}</w:t>'
        + '</w:r></w:p><w:sectPr><w:pgSz w:w="12240" w:h="15840"/>'
        + "</w:sectPr></w:body></w:document>"
    )
    return _docx_package(document)


def _make_holdout_docx(text: str) -> bytes:
    # Casework uses a one-cell review table rather than calibration's body
    # paragraph. The extracted text is unchanged, but the package topology is
    # independently representative of a different Word workflow.
    document = (
        _XML_DECL
        + f'<w:document {_W_NS}><w:body><w:tbl><w:tblPr><w:tblW w:w="0" w:type="auto"/>'
        + '</w:tblPr><w:tblGrid><w:gridCol w:w="9000"/></w:tblGrid><w:tr><w:tc>'
        + '<w:tcPr><w:tcW w:w="9000" w:type="dxa"/></w:tcPr><w:p><w:r>'
        + f'<w:t xml:space="preserve">{escape(text)}</w:t>'
        + '</w:r></w:p></w:tc></w:tr></w:tbl><w:sectPr><w:pgSz w:w="12240" w:h="15840"/>'
        + "</w:sectPr></w:body></w:document>"
    )
    return _docx_package(document)


def _xlsx_package(workbook: str, sheet: str) -> bytes:
    content_types = _opc_content_types(
        [
            (
                "/xl/workbook.xml",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
            ),
            (
                "/xl/worksheets/sheet1.xml",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml",
            ),
        ]
    )
    root_rels = _root_relationship(
        "xl/workbook.xml",
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument",
    )
    workbook_rels = (
        _XML_DECL
        + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="worksheets/sheet1.xml"/></Relationships>'
    )
    return _zip_bytes(
        {
            "[Content_Types].xml": content_types,
            "_rels/.rels": root_rels,
            "xl/_rels/workbook.xml.rels": workbook_rels,
            "xl/workbook.xml": workbook,
            "xl/worksheets/sheet1.xml": sheet,
        }
    )


def _make_calibration_xlsx(text: str) -> bytes:
    workbook = (
        _XML_DECL
        + f"<workbook {_S_NS} {_R_NS}><bookViews><workbookView/></bookViews><sheets>"
        + '<sheet name="Review" sheetId="1" r:id="rId1"/></sheets></workbook>'
    )
    sheet = (
        _XML_DECL
        + f'<worksheet {_S_NS}><dimension ref="B2"/><sheetViews><sheetView workbookViewId="0"/>'
        + '</sheetViews><sheetData><row r="2"><c r="B2" t="inlineStr"><is>'
        + f'<t xml:space="preserve">{escape(text)}</t>'
        + "</is></c></row></sheetData></worksheet>"
    )
    return _xlsx_package(workbook, sheet)


def _make_holdout_xlsx(text: str) -> bytes:
    # The holdout casework sheet uses a distinct sparse reconciliation layout
    # with column metadata and a leading empty row. Attribute values alone are
    # not relied upon for separation; the XML element topology also differs.
    workbook = (
        _XML_DECL
        + f"<workbook {_S_NS} {_R_NS}><bookViews><workbookView/></bookViews><sheets>"
        + '<sheet name="Casework" sheetId="1" r:id="rId1"/></sheets>'
        + '<calcPr calcId="0"/></workbook>'
    )
    sheet = (
        _XML_DECL
        + f'<worksheet {_S_NS}><dimension ref="D4"/><sheetViews><sheetView workbookViewId="0"/>'
        + '</sheetViews><cols><col min="4" max="4" width="32" customWidth="1"/></cols>'
        + '<sheetData><row r="1"/><row r="4"><c r="D4" t="inlineStr"><is>'
        + f'<t xml:space="preserve">{escape(text)}</t>'
        + "</is></c></row></sheetData></worksheet>"
    )
    return _xlsx_package(workbook, sheet)


def _group_shape_xml() -> str:
    return (
        '<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/>'
        '<p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/>'
        '<a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/>'
        '<a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>'
    )


def _split_structured_text(text: str) -> tuple[str, str]:
    split_at = text.find(" ", max(1, len(text) // 2))
    if split_at < 0:
        split_at = max(1, len(text) // 2)
    else:
        split_at += 1
    return text[:split_at], text[split_at:]


def _make_calibration_pptx(text: str) -> bytes:
    slide = (
        _XML_DECL
        + f"<p:sld {_P_NS} {_A_NS} {_R_NS}><p:cSld><p:spTree>{_group_shape_xml()}"
        + '<p:sp><p:nvSpPr><p:cNvPr id="2" name="Corpus text"/><p:cNvSpPr txBox="1"/>'
        + '<p:nvPr/></p:nvSpPr><p:spPr><a:xfrm><a:off x="457200" y="457200"/>'
        + '<a:ext cx="8229600" cy="1371600"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/>'
        + "</a:prstGeom><a:noFill/></p:spPr><p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r>"
        + f"<a:t>{escape(text)}</a:t>"
        + '</a:r><a:endParaRPr lang="en-US"/></a:p></p:txBody></p:sp></p:spTree>'
        + "<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:cSld></p:sld>"
    )
    return _pptx_package(slide)


def _make_holdout_pptx(text: str) -> bytes:
    first, second = _split_structured_text(text)
    # Holdout casework uses two styled runs in a differently positioned shape;
    # this exercises a distinct presentation layout while preserving the exact
    # extracted string and plant offsets.
    slide = (
        _XML_DECL
        + f"<p:sld {_P_NS} {_A_NS} {_R_NS}><p:cSld><p:spTree>{_group_shape_xml()}"
        + '<p:sp><p:nvSpPr><p:cNvPr id="3" name="Casework record"/><p:cNvSpPr txBox="1"/>'
        + '<p:nvPr/></p:nvSpPr><p:spPr><a:xfrm><a:off x="914400" y="1371600"/>'
        + '<a:ext cx="7315200" cy="1828800"/></a:xfrm><a:prstGeom prst="roundRect">'
        + '<a:avLst/></a:prstGeom><a:noFill/></p:spPr><p:txBody><a:bodyPr wrap="square"/>'
        + '<a:lstStyle/><a:p><a:r><a:rPr lang="en-US"/>'
        + f'<a:t>{escape(first)}</a:t></a:r><a:r><a:rPr lang="en-US" b="1"/>'
        + f"<a:t>{escape(second)}</a:t></a:r>"
        + '<a:endParaRPr lang="en-US"/></a:p></p:txBody></p:sp></p:spTree>'
        + "<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:cSld></p:sld>"
    )
    return _pptx_package(slide)


def _pptx_package(slide: str) -> bytes:
    content_types = _opc_content_types(
        [
            (
                "/ppt/presentation.xml",
                "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
            ),
            (
                "/ppt/slides/slide1.xml",
                "application/vnd.openxmlformats-officedocument.presentationml.slide+xml",
            ),
            (
                "/ppt/slideLayouts/slideLayout1.xml",
                "application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml",
            ),
            (
                "/ppt/slideMasters/slideMaster1.xml",
                "application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml",
            ),
            (
                "/ppt/theme/theme1.xml",
                "application/vnd.openxmlformats-officedocument.theme+xml",
            ),
        ]
    )
    root_rels = _root_relationship(
        "ppt/presentation.xml",
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument",
    )
    presentation = (
        _XML_DECL
        + f"<p:presentation {_P_NS} {_A_NS} {_R_NS}><p:sldMasterIdLst>"
        + '<p:sldMasterId id="2147483648" r:id="rId2"/></p:sldMasterIdLst><p:sldIdLst>'
        + '<p:sldId id="256" r:id="rId1"/></p:sldIdLst>'
        + '<p:sldSz cx="9144000" cy="6858000" type="screen4x3"/>'
        + '<p:notesSz cx="6858000" cy="9144000"/></p:presentation>'
    )
    presentation_rels = (
        _XML_DECL
        + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" '
        'Target="slides/slide1.xml"/><Relationship Id="rId2" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" '
        'Target="slideMasters/slideMaster1.xml"/></Relationships>'
    )
    slide_rels = (
        _XML_DECL
        + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" '
        'Target="../slideLayouts/slideLayout1.xml"/></Relationships>'
    )
    layout = (
        _XML_DECL
        + f'<p:sldLayout {_P_NS} {_A_NS} {_R_NS} type="blank" preserve="1"><p:cSld name="Blank">'
        + f"<p:spTree>{_group_shape_xml()}</p:spTree></p:cSld>"
        + "<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>"
    )
    layout_rels = (
        _XML_DECL
        + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" '
        'Target="../slideMasters/slideMaster1.xml"/></Relationships>'
    )
    master = (
        _XML_DECL
        + f"<p:sldMaster {_P_NS} {_A_NS} {_R_NS}><p:cSld><p:spTree>{_group_shape_xml()}"
        + '</p:spTree></p:cSld><p:clrMap accent1="accent1" accent2="accent2" '
        + 'accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" '
        + 'bg1="lt1" bg2="lt2" folHlink="folHlink" hlink="hlink" tx1="dk1" tx2="dk2"/>'
        + '<p:sldLayoutIdLst><p:sldLayoutId id="1" r:id="rId1"/></p:sldLayoutIdLst>'
        + "<p:txStyles><p:titleStyle/><p:bodyStyle/><p:otherStyle/></p:txStyles></p:sldMaster>"
    )
    master_rels = (
        _XML_DECL
        + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" '
        'Target="../slideLayouts/slideLayout1.xml"/><Relationship Id="rId2" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" '
        'Target="../theme/theme1.xml"/></Relationships>'
    )
    colors = "".join(
        f'<a:{name}><a:srgbClr val="{value}"/></a:{name}>'
        for name, value in (
            ("dk1", "000000"),
            ("lt1", "FFFFFF"),
            ("dk2", "1F497D"),
            ("lt2", "EEECE1"),
            ("accent1", "4F81BD"),
            ("accent2", "C0504D"),
            ("accent3", "9BBB59"),
            ("accent4", "8064A2"),
            ("accent5", "4BACC6"),
            ("accent6", "F79646"),
            ("hlink", "0000FF"),
            ("folHlink", "800080"),
        )
    )
    theme = (
        _XML_DECL
        + f'<a:theme {_A_NS} name="Corpus Theme"><a:themeElements><a:clrScheme name="Corpus">'
        + colors
        + '</a:clrScheme><a:fontScheme name="Corpus"><a:majorFont><a:latin typeface="Arial"/>'
        + '</a:majorFont><a:minorFont><a:latin typeface="Arial"/></a:minorFont></a:fontScheme>'
        + '<a:fmtScheme name="Corpus"><a:fillStyleLst/><a:lnStyleLst/><a:effectStyleLst/>'
        + "<a:bgFillStyleLst/></a:fmtScheme></a:themeElements></a:theme>"
    )
    return _zip_bytes(
        {
            "[Content_Types].xml": content_types,
            "_rels/.rels": root_rels,
            "ppt/_rels/presentation.xml.rels": presentation_rels,
            "ppt/presentation.xml": presentation,
            "ppt/slideLayouts/_rels/slideLayout1.xml.rels": layout_rels,
            "ppt/slideLayouts/slideLayout1.xml": layout,
            "ppt/slideMasters/_rels/slideMaster1.xml.rels": master_rels,
            "ppt/slideMasters/slideMaster1.xml": master,
            "ppt/slides/_rels/slide1.xml.rels": slide_rels,
            "ppt/slides/slide1.xml": slide,
            "ppt/theme/theme1.xml": theme,
        }
    )


def _make_calibration_odt(text: str) -> bytes:
    content = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        + f"<office:document-content {_ODF_DECL}><office:automatic-styles/><office:body>"
        + f"<office:text><text:p>{escape(text)}</text:p></office:text>"
        + "</office:body></office:document-content>"
    )
    return _odt_package(content)


def _make_holdout_odt(text: str) -> bytes:
    first, second = _split_structured_text(text)
    # Field casework is grouped in a named section and split across spans,
    # unlike calibration's single direct paragraph text node.
    content = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        + f"<office:document-content {_ODF_DECL}><office:automatic-styles/><office:body>"
        + '<office:text><text:section text:name="CaseworkRecord"><text:p>'
        + f"<text:span>{escape(first)}</text:span><text:span>{escape(second)}</text:span>"
        + "</text:p></text:section></office:text></office:body></office:document-content>"
    )
    return _odt_package(content)


def _odt_package(content: str) -> bytes:
    mimetype = "application/vnd.oasis.opendocument.text"
    styles = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        + "<office:document-styles "
        + 'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
        + 'xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" '
        + 'office:version="1.3"><office:styles/></office:document-styles>'
    )
    manifest = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        + "<manifest:manifest "
        + 'xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" '
        + 'manifest:version="1.3">'
        + f'<manifest:file-entry manifest:full-path="/" manifest:media-type="{mimetype}"/>'
        + '<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>'
        + '<manifest:file-entry manifest:full-path="styles.xml" manifest:media-type="text/xml"/>'
        + "</manifest:manifest>"
    )
    return _zip_bytes(
        {
            "mimetype": mimetype,
            "META-INF/manifest.xml": manifest,
            "content.xml": content,
            "styles.xml": styles,
        }
    )


def main() -> None:
    manifests = write_all_corpora()
    for role, manifest in manifests.items():
        print(
            f"{role}: {manifest['document_count']} documents, "
            f"{manifest['positive_plant_count']} positive plants, "
            f"{manifest['decoy_plant_count']} decoys, sha256={manifest['sha256'][:12]}"
        )


if __name__ == "__main__":
    main()
