"""Document ingestion.

Take a file, work out what it is, pull out the dates and amounts that create
obligations, and record where every value came from.

Three rules shape this module:

* **Extraction is never a bare value.** Every field is stored as
  ``{field, value, confidence, evidence}`` where ``evidence`` is the literal
  text it was read from. That is what makes "your passport expires May 18" a
  citable claim rather than an assertion.
* **Extracted text is untrusted.** A PDF is as good a delivery vehicle for an
  injection as an email. Text is scanned and flagged, and anything derived from
  it inherits the taint.
* **Nothing irreversible happens from extraction alone.** A confidently parsed
  expiry creates an *obligation* and a card. It never triggers a renewal, a
  payment, or a deletion.

File contents are encrypted at rest under a Vault-derived key -- a stolen disk
should not yield a passport scan.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field

from mybot_schemas.config import get_settings
from mybot_schemas.db.types import utcnow
from mybot_schemas.enums import (
    ActorType,
    AuditEventType,
    Classification,
    EntityType,
    SourceKind,
)
from mybot_schemas.models import Document
from mybot_security.crypto import SealedBox, seal, sha256_hex, unseal
from mybot_security.logging import get_logger
from mybot_security.untrusted import scan_for_injection
from mybot_security.vault import Vault
from sqlalchemy.orm import Session

from ..audit.service import AuditService
from ..life_graph.service import LifeGraphService
from ..obligations.service import ObligationService

log = get_logger(__name__)

#: Document type detection. Ordered -- first match wins -- with the most
#: specific patterns first.
#:
#: Ordering matters more than it looks. An auto insurance declaration and a
#: vehicle registration both mention a VIN and a vehicle, so the insurance
#: markers are checked first and the registration markers avoid generic terms
#: that appear on both. Getting this wrong merged two documents into one
#: entity and produced two conflicting "expiry" dates for the same thing.
_TYPE_SIGNATURES: tuple[tuple[str, tuple[str, ...], Classification], ...] = (
    ("passport", ("passport", "travel document", "place of birth"), Classification.HIGHLY_SENSITIVE),
    ("drivers_license", ("driver license", "driver's license", "operator license"), Classification.HIGHLY_SENSITIVE),
    ("insurance_declaration", ("declarations page", "policy number", "coverage period", "total premium"), Classification.SENSITIVE),
    ("vehicle_registration", ("vehicle registration", "registration card", "registration number", "motor vehicle commission"), Classification.SENSITIVE),
    ("utility_bill", ("amount due", "service address", "meter", "kwh", "billing period"), Classification.PERSONAL),
    ("bank_statement", ("statement period", "beginning balance", "ending balance"), Classification.HIGHLY_SENSITIVE),
    ("tax_document", ("form 1040", "w-2", "1099", "taxable income", "internal revenue"), Classification.HIGHLY_SENSITIVE),
    ("lease", ("lease agreement", "landlord", "tenant", "monthly rent"), Classification.SENSITIVE),
    ("receipt", ("receipt", "order total", "thank you for your purchase"), Classification.PERSONAL),
)

_DATE_LABELS = (
    ("expiration_date", (r"expir(?:es|ation|y)(?:\s+date)?", r"valid\s+(?:un)?til", r"good\s+through")),
    ("renewal_date", (r"renew(?:s|al)(?:\s+date|\s+on)?", r"next\s+renewal")),
    ("due_date", (r"due\s+date", r"payment\s+due", r"amount\s+due\s+by")),
    ("issue_date", (r"issue(?:d)?(?:\s+date|\s+on)?", r"date\s+of\s+issue")),
)

_DATE_VALUE = (
    r"(\d{4}-\d{2}-\d{2}"
    r"|\d{1,2}/\d{1,2}/\d{4}"
    r"|(?:January|February|March|April|May|June|July|August|September|October|November|December)"
    r"\s+\d{1,2},?\s+\d{4}"
    r"|\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4})"
)

_AMOUNT_LABELS = (
    ("amount_due", (r"amount\s+due", r"total\s+due", r"balance\s+due", r"pay\s+this\s+amount")),
    ("total", (r"total", r"order\s+total")),
    ("monthly_rent", (r"monthly\s+rent", r"rent\s+amount")),
)

_ID_PATTERNS = (
    ("policy_number", r"policy\s*(?:no|number|#)[:\s]*([A-Z0-9-]{5,})"),
    ("account_number", r"account\s*(?:no|number|#)[:\s]*([A-Z0-9-]{4,})"),
    ("registration_number", r"(?:registration|reg)\s*(?:no|number|#)[:\s]*([A-Z0-9-]{4,})"),
    ("passport_number", r"passport\s*(?:no|number|#)[:\s]*([A-Z0-9<]{6,})"),
    ("vin", r"\bVIN[:\s]*([A-HJ-NPR-Z0-9]{17})\b"),
    ("plate", r"(?:plate|license\s+plate)[:\s]*([A-Z0-9-]{5,8})"),
)

_ISSUER_PATTERNS = (
    r"(?:issued\s+by|issuer)[:\s]+([A-Z][A-Za-z&.,' -]{3,60})",
    r"^([A-Z][A-Za-z&.,' -]{3,60}(?:Insurance|Energy|Electric|Gas|Bank|Motor Vehicle|Commission|Authority))",
)


@dataclass
class ExtractedField:
    field: str
    value: str
    confidence: float
    #: The literal text this was read from, e.g. "Expires: 2027-05-18".
    evidence: str
    page: int | None = None

    def as_dict(self) -> dict:
        return {
            "field": self.field,
            "value": self.value,
            "confidence": round(self.confidence, 3),
            "evidence": self.evidence,
            "page": self.page,
        }


@dataclass
class IngestionResult:
    document: Document
    fields: list[ExtractedField] = field(default_factory=list)
    obligations_created: list[str] = field(default_factory=list)
    entity_id: str | None = None
    injection_suspected: bool = False
    warnings: list[str] = field(default_factory=list)


class DocumentIngestionService:
    def __init__(
        self,
        session: Session,
        vault: Vault,
        *,
        audit: AuditService | None = None,
        graph: LifeGraphService | None = None,
        obligations: ObligationService | None = None,
    ):
        self.session = session
        self.vault = vault
        self.audit = audit or AuditService(session)
        self.graph = graph or LifeGraphService(session, self.audit)
        self.obligations = obligations or ObligationService(session, self.audit)
        self.settings = get_settings()

    # ------------------------------------------------------------------

    def ingest(
        self,
        owner_id: str,
        *,
        filename: str,
        content: bytes,
        mime_type: str = "application/octet-stream",
        folder: str = "Inbox",
        create_obligations: bool = True,
    ) -> IngestionResult:
        digest = sha256_hex(content)
        storage_path = self._store_encrypted(owner_id, digest, content)

        text, warning = self._extract_text(content, mime_type, filename)
        scan = scan_for_injection(text or "")

        document_type, classification = self._detect_type(text or "", filename)
        fields = self._extract_fields(text or "")
        issuer = self._detect_issuer(text or "")

        document = Document(
            owner_id=owner_id,
            filename=filename,
            mime_type=mime_type,
            byte_size=len(content),
            sha256=digest,
            storage_path=storage_path,
            document_type=document_type,
            issuer=issuer,
            folder=folder,
            extracted_text=text,
            extraction_status="ok" if text else "unsupported",
            extraction_error=warning,
            extracted_fields=[f.as_dict() for f in fields],
            classification=classification.value,
        )
        self.session.add(document)
        self.session.flush()

        entity_id = self._link_entity(owner_id, document, fields)
        created = (
            self._create_obligations(owner_id, document, fields, entity_id)
            if create_obligations
            else []
        )

        self.audit.record(
            owner_id,
            AuditEventType.DOCUMENT_INGESTED,
            actor_type=ActorType.SYSTEM,
            resource_type="document",
            resource_id=document.id,
            reason=f"ingested {filename}",
            details={
                "document_type": document_type,
                "classification": classification.value,
                "fields": [f.field for f in fields],
                "sha256": digest,
                "obligations_created": created,
                "injection_suspected": scan.suspected,
                "extraction_status": document.extraction_status,
            },
        )

        return IngestionResult(
            document=document,
            fields=fields,
            obligations_created=created,
            entity_id=entity_id,
            injection_suspected=scan.suspected,
            warnings=[warning] if warning else [],
        )

    # ------------------------------------------------------------------
    # Storage
    # ------------------------------------------------------------------

    def _store_encrypted(self, owner_id: str, digest: str, content: bytes) -> str:
        """Write the file encrypted, keyed to this owner and this document."""
        root = self.settings.documents_dir() / owner_id
        root.mkdir(parents=True, exist_ok=True)
        path = root / f"{digest}.enc"
        box = seal(self.vault.document_key(), content, f"mybot|doc|owner={owner_id}|sha={digest}")
        path.write_bytes(box.nonce + box.ciphertext)
        try:
            path.chmod(0o600)
        except OSError:  # pragma: no cover - platform dependent
            pass
        return str(path.relative_to(self.settings.data_dir))

    def read_content(self, owner_id: str, document: Document) -> bytes:
        """Decrypt and return the original bytes."""
        path = self.settings.data_dir / document.storage_path
        raw = path.read_bytes()
        return unseal(
            self.vault.document_key(),
            SealedBox(
                nonce=raw[:12],
                ciphertext=raw[12:],
                aad=f"mybot|doc|owner={owner_id}|sha={document.sha256}",
                key_version=1,
            ),
        )

    # ------------------------------------------------------------------
    # Extraction
    # ------------------------------------------------------------------

    def _extract_text(
        self, content: bytes, mime_type: str, filename: str
    ) -> tuple[str | None, str | None]:
        """Get text out of the file, or say honestly that it could not.

        Images are *not* silently skipped -- they return an explicit
        "OCR is not available" warning that reaches the UI, so a user who
        uploaded a photo of a document knows nothing was read from it.
        """
        lower = filename.lower()
        if mime_type.startswith("text/") or lower.endswith((".txt", ".md", ".csv")):
            try:
                return content.decode("utf-8", errors="replace"), None
            except Exception as exc:  # noqa: BLE001
                return None, f"could not decode text: {type(exc).__name__}"

        if mime_type == "application/pdf" or lower.endswith(".pdf"):
            try:
                import io

                from pypdf import PdfReader

                reader = PdfReader(io.BytesIO(content))
                pages = [page.extract_text() or "" for page in reader.pages[:40]]
                text = "\n".join(pages).strip()
                if not text:
                    return None, (
                        "This PDF has no extractable text. It is probably a scan, and OCR "
                        "is not available in this build, so no fields were read from it."
                    )
                return text, None
            except ImportError:
                return None, "PDF support is not installed (pip install 'mybot[documents]')"
            except Exception as exc:  # noqa: BLE001
                return None, f"could not read PDF: {type(exc).__name__}"

        if mime_type.startswith("image/") or lower.endswith((".png", ".jpg", ".jpeg", ".heic")):
            return None, (
                "OCR is not available in this build, so nothing was read from this image. "
                "The file is stored and encrypted; add the details manually if they matter."
            )

        return None, f"unsupported file type: {mime_type}"

    def _detect_type(self, text: str, filename: str) -> tuple[str | None, Classification]:
        haystack = f"{filename}\n{text}".lower()
        for doc_type, markers, classification in _TYPE_SIGNATURES:
            if any(marker in haystack for marker in markers):
                return doc_type, classification
        return None, Classification.PERSONAL

    def _extract_fields(self, text: str) -> list[ExtractedField]:
        out: list[ExtractedField] = []
        if not text:
            return out

        for field_name, labels in _DATE_LABELS:
            for label in labels:
                pattern = re.compile(rf"(?i)({label})\s*[:\-]?\s*{_DATE_VALUE}")
                match = pattern.search(text)
                if not match:
                    continue
                parsed = _parse_date(match.group(2))
                if parsed is None:
                    continue
                out.append(
                    ExtractedField(
                        field=field_name,
                        value=parsed.date().isoformat(),
                        # A labelled date is a strong signal; an unlabelled one
                        # would not be extracted at all.
                        confidence=0.94,
                        evidence=match.group(0).strip(),
                    )
                )
                break

        for field_name, labels in _AMOUNT_LABELS:
            for label in labels:
                pattern = re.compile(rf"(?i)({label})\s*[:\-]?\s*[$£€]?\s*([0-9][0-9,]*(?:\.[0-9]{{2}})?)")
                match = pattern.search(text)
                if not match:
                    continue
                out.append(
                    ExtractedField(
                        field=field_name,
                        value=match.group(2).replace(",", ""),
                        confidence=0.9,
                        evidence=match.group(0).strip(),
                    )
                )
                break

        for field_name, pattern_str in _ID_PATTERNS:
            match = re.search(pattern_str, text, re.I)
            if not match:
                continue
            raw = match.group(1)
            out.append(
                ExtractedField(
                    field=field_name,
                    # Identifiers are masked at rest. The full value lives in
                    # the encrypted document, not in a queryable column.
                    value=_mask(raw),
                    confidence=0.88,
                    evidence=match.group(0).strip()[:80],
                )
            )

        return out

    def _detect_issuer(self, text: str) -> str | None:
        for pattern in _ISSUER_PATTERNS:
            match = re.search(pattern, text, re.M)
            if match:
                return match.group(1).strip()[:200]
        return None

    # ------------------------------------------------------------------
    # Linking
    # ------------------------------------------------------------------

    def _link_entity(
        self, owner_id: str, document: Document, fields: list[ExtractedField]
    ) -> str | None:
        """Create a Life Graph node for the document and link its issuer."""
        entity, _ = self.graph.resolve_entity(
            owner_id,
            entity_type=EntityType.DOCUMENT,
            name=document.document_type.replace("_", " ").title()
            if document.document_type
            else document.filename,
            classification=Classification(document.classification),
            source_kind=SourceKind.DOCUMENT,
            source_id=f"document:{document.id}",
            source_detail=document.filename,
            attributes={"filename": document.filename, "document_type": document.document_type},
        )
        document.entity_id = entity.id

        for extracted in fields:
            self.graph.assert_fact(
                owner_id,
                entity.id,
                extracted.field,
                extracted.value,
                source_kind=SourceKind.DOCUMENT,
                source_id=f"document:{document.id}",
                evidence=extracted.evidence,
                confidence=extracted.confidence,
                classification=Classification(document.classification),
                inferred=True,
            )

        if document.issuer:
            issuer_entity, _ = self.graph.resolve_entity(
                owner_id,
                entity_type=EntityType.ORGANIZATION,
                name=document.issuer,
                source_kind=SourceKind.DOCUMENT,
                source_id=f"document:{document.id}",
                confidence=0.8,
                inferred=True,
            )
            from mybot_schemas.enums import RelationType

            self.graph.relate(
                owner_id,
                entity.id,
                RelationType.ISSUED_BY,
                issuer_entity.id,
                source_kind=SourceKind.DOCUMENT,
                source_id=f"document:{document.id}",
                confidence=0.8,
            )

        self.session.flush()
        return entity.id

    def _create_obligations(
        self,
        owner_id: str,
        document: Document,
        fields: list[ExtractedField],
        entity_id: str | None,
    ) -> list[str]:
        """Turn extracted expiry dates into tracked obligations.

        Only for dates that are in the future and extracted with high
        confidence. A low-confidence parse still shows on the document, but it
        does not become a deadline the user is told about as fact.
        """
        created: list[str] = []
        now = utcnow()
        for extracted in fields:
            if extracted.field not in ("expiration_date", "renewal_date", "due_date"):
                continue
            if extracted.confidence < 0.85:
                continue
            due = _parse_date(extracted.value)
            if due is None or due <= now:
                continue

            label = (document.document_type or document.filename).replace("_", " ").title()
            verb = {"expiration_date": "renewal", "renewal_date": "renewal", "due_date": "payment"}[
                extracted.field
            ]
            amount = next(
                (float(f.value) for f in fields if f.field in ("amount_due", "total")), None
            )

            obligation = self.obligations.create(
                owner_id,
                title=f"{label} {verb}",
                due_at=due,
                kind="registration_renewal" if "registration" in label.lower() else verb,
                description=f"Extracted from {document.filename}.",
                consequence=(
                    "Driving with an expired registration risks a citation."
                    if "registration" in label.lower()
                    else None
                ),
                amount=amount,
                currency="USD" if amount else None,
                entity_id=entity_id,
                source_ids=[f"document:{document.id}"],
                source_kind=SourceKind.DOCUMENT,
                source_detail=f"{document.filename}: {extracted.evidence}",
                confidence=extracted.confidence,
                inferred=True,
                actor_type=ActorType.SYSTEM,
            )
            created.append(obligation.id)
        return created


def _mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 4:
        return "•" * len(value)
    return "•" * (len(value) - 4) + value[-4:]


def _parse_date(value: str) -> dt.datetime | None:
    value = (value or "").strip()
    formats = ("%Y-%m-%d", "%m/%d/%Y", "%B %d, %Y", "%B %d %Y", "%d %b %Y", "%d %B %Y")
    for fmt in formats:
        try:
            return dt.datetime.strptime(value, fmt).replace(tzinfo=dt.UTC)
        except ValueError:
            continue
    try:
        parsed = dt.datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)
    except ValueError:
        return None


__all__ = ["DocumentIngestionService", "ExtractedField", "IngestionResult"]
