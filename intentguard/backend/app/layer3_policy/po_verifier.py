"""
IntentGuard Layer 3 — Supply-Chain PO-vs-Invoice Bank & Amount Verifier
========================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01 — Separating Data from Authority

Task 17: Deterministic cross-checker that validates extracted invoice fields
against the trusted Purchase Order database (TRUSTED_PO_DB), blocking:
  - Spoofed bank account / IBAN substitution  (Risk #10, #16, #18)
  - Invoice amount exceeding PO approved limit (Risk #10, #16, #18)
  - Unverified delivery receipts              (Risk #10, #18)
  - Unknown / forged PO identifiers           (Risk #10, #16, #18)

On any discrepancy, execution is halted and a Step-Back Human Approval Card
is generated, referencing the exact PDF source page and line number carried
inside the ProvenanceEnvelope so security analysts can trace the attack origin.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Path resolution — finds purchase_orders.json relative to this module
# ---------------------------------------------------------------------------

def _resolve_po_db_path() -> Path:
    candidates = [
        Path(__file__).resolve().parents[2] / "data" / "purchase_orders.json",
        Path(__file__).resolve().parents[3] / "backend" / "data" / "purchase_orders.json",
        Path(__file__).resolve().parents[3] / "data" / "purchase_orders.json",
    ]
    for c in candidates:
        if c.exists():
            return c
    return candidates[0]

_PO_DB_PATH = _resolve_po_db_path()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class TrustedPORecord(BaseModel):
    """A single trusted Purchase Order record loaded from TRUSTED_PO_DB."""

    po_id: str
    aliases: List[str] = Field(default_factory=list)
    buyer_id: str
    buyer_enterprise_id: Optional[str] = None
    supplier_id: str
    supplier_enterprise_id: Optional[str] = None
    supplier_name: Optional[str] = None
    approved_amount_inr: float
    currency: str = "INR"
    approved_bank_account: str
    delivery_receipt: str  # "VERIFIED" | "PENDING" | etc.
    allowed_invoices: List[str] = Field(default_factory=list)
    origin: str = "TRUSTED_PO_DB"


class StepBackApprovalCardPayload(BaseModel):
    """Human-in-the-loop escalation card emitted when a policy check fails."""

    card_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    escalation_type: str  # e.g. "BANK_ACCOUNT_MISMATCH"
    po_id: str
    invoice_id: Optional[str] = None
    buyer_id: str
    supplier_id: str
    expected_bank_account: Optional[str] = None
    proposed_bank_account: Optional[str] = None
    expected_amount_inr: Optional[float] = None
    proposed_amount_inr: Optional[float] = None
    source_file: Optional[str] = None
    source_page_number: int = 1
    source_line_number: int = 1
    risk_category_ids: List[int] = Field(default_factory=list)
    human_prompt_summary: str


class POVerificationResult(BaseModel):
    """Full verification result returned to Hook 2 and callers."""

    verified: bool
    execution_permitted: bool
    action_taken: str  # "SAFE_EXECUTED" | "HUMAN_APPROVAL_REQUIRED" | "BLOCKED"
    po_id: str
    buyer_id: Optional[str] = None
    supplier_id: Optional[str] = None
    matched_po: Optional[TrustedPORecord] = None
    discrepancies: List[str] = Field(default_factory=list)
    risk_category_ids: List[int] = Field(default_factory=list)
    source_file: Optional[str] = None
    source_page_number: Optional[int] = None
    source_line_number: Optional[int] = None
    requires_human_approval_card: bool = False
    approval_card: Optional[StepBackApprovalCardPayload] = None
    reason: str


# ---------------------------------------------------------------------------
# PurchaseOrderVerifier
# ---------------------------------------------------------------------------


class PurchaseOrderVerifier:
    """
    Loads purchase_orders.json once at startup and provides deterministic
    PO-vs-Invoice verification for Hook 2 of the OpenClaw Interceptor Bridge.
    """

    def __init__(self, po_db_path: Optional[Path] = None) -> None:
        path = po_db_path or _PO_DB_PATH
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            po_dict: Dict[str, Any] = raw.get("purchase_orders", {})
        except FileNotFoundError:
            logger.warning("purchase_orders.json not found at %s — verifier will reject all POs", path)
            po_dict = {}
        except json.JSONDecodeError as exc:
            logger.error("Malformed purchase_orders.json: %s", exc)
            po_dict = {}

        # Primary index: po_id -> TrustedPORecord
        self._po_by_id: Dict[str, TrustedPORecord] = {}
        # Alias index: normalized_alias -> po_id
        self._alias_index: Dict[str, str] = {}

        for raw_id, raw_record in po_dict.items():
            try:
                record = TrustedPORecord(**raw_record)
            except Exception as exc:
                logger.warning("Skipping malformed PO record '%s': %s", raw_id, exc)
                continue
            self._po_by_id[raw_id] = record
            # Index by po_id and all aliases
            for alias in [raw_id] + record.aliases:
                norm = self._normalize(alias)
                self._alias_index[norm] = raw_id

        logger.info("PurchaseOrderVerifier loaded %d POs from %s", len(self._po_by_id), path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize(po_str: str) -> str:
        """
        Normalize a PO string to a canonical form for lookup.
        Strips 'PO', '#', spaces, dashes and uppercases so that
        'PO-402', 'PO #402', 'po#402', '402' all resolve to '402'.
        """
        s = str(po_str).upper()
        s = re.sub(r"\bPO\b", "", s)
        s = re.sub(r"[#\s\-]", "", s)
        return s.strip()

    def _lookup_po(self, po_str: str) -> Optional[TrustedPORecord]:
        norm = self._normalize(po_str)
        canonical_id = self._alias_index.get(norm)
        if canonical_id:
            return self._po_by_id.get(canonical_id)
        return None

    @staticmethod
    def _extract_provenance(
        field_name: str,
        provenance_map: Optional[Dict[str, Any]],
        args: Dict[str, Any],
    ):
        """
        Returns (source_file, page_number, line_number) for a given field,
        scanning both a provenance_map dict and direct args keys.
        """
        source_file = args.get("source_file")
        page_num: int = int(args.get("source_page_number", 1))
        line_num: int = int(args.get("source_line_number", 1))

        if provenance_map:
            entry = provenance_map.get(field_name) or provenance_map.get("default")
            if isinstance(entry, dict):
                source_file = entry.get("source_file", source_file)
                page_num = int(entry.get("page_number", entry.get("source_page_number", page_num)))
                line_num = int(entry.get("line_number", entry.get("source_line_number", line_num)))
            # ProvenanceEnvelope objects
            elif hasattr(entry, "source_file"):
                source_file = getattr(entry, "source_file", source_file)
                page_num = int(getattr(entry, "page_number", page_num))
                line_num = int(getattr(entry, "line_number", line_num))

        return source_file, page_num, line_num

    # ------------------------------------------------------------------
    # Core verification
    # ------------------------------------------------------------------

    def verify_invoice_against_po(  # noqa: C901
        self,
        invoice_data: Dict[str, Any],
        provenance_map: Optional[Dict[str, Any]] = None,
    ) -> POVerificationResult:
        """
        Deterministically verifies extracted invoice fields against the trusted
        Purchase Order database.

        Accepted invoice_data keys (flexible naming):
          po_id / po_number / po_ref          -> PO identifier
          invoice_id                          -> Invoice reference
          supplier_id / vendor_id             -> Supplier identifier
          amount_inr / amount                 -> Invoice amount in INR
          iban_account / beneficiary_iban /
            bank_account / approved_bank_account -> Bank account to credit
          source_file, source_page_number,
            source_line_number               -> Direct provenance override
        """
        args = invoice_data

        # -- Resolve PO identifier -----------------------------------------
        raw_po_id: str = str(
            args.get("po_id")
            or args.get("po_number")
            or args.get("po_ref")
            or ""
        ).strip()

        # -- Resolve optional fields ----------------------------------------
        invoice_id: Optional[str] = args.get("invoice_id")
        supplier_id: Optional[str] = (
            args.get("supplier_id") or args.get("vendor_id")
        )
        amount_raw = args.get("amount_inr") or args.get("amount")
        try:
            amount_inr: Optional[float] = float(amount_raw) if amount_raw is not None else None
        except (TypeError, ValueError):
            amount_inr = None

        iban_account: Optional[str] = (
            args.get("iban_account")
            or args.get("beneficiary_iban")
            or args.get("bank_account")
            or args.get("approved_bank_account")
        )

        # -- Provenance extraction ------------------------------------------
        iban_src_file, iban_page, iban_line = self._extract_provenance(
            "iban_account", provenance_map, args
        )
        amount_src_file, amount_page, amount_line = self._extract_provenance(
            "amount_inr", provenance_map, args
        )

        # -- Fallback resolution: Look up PO by approved bank account if po_id is omitted
        if not raw_po_id and iban_account:
            for cand_id, cand_po in self._po_by_id.items():
                if cand_po.approved_bank_account == iban_account:
                    raw_po_id = cand_id
                    break

        # -- Check 1: PO Existence -----------------------------------------
        if not raw_po_id:
            src_file, src_page, src_line = iban_src_file or amount_src_file, iban_page, iban_line
            return POVerificationResult(
                verified=False,
                execution_permitted=False,
                action_taken="HUMAN_APPROVAL_REQUIRED",
                po_id="UNKNOWN",
                buyer_id=None,
                supplier_id=supplier_id,
                discrepancies=["No PO identifier provided in invoice data."],
                risk_category_ids=[10, 16, 18],
                source_file=src_file,
                source_page_number=src_page,
                source_line_number=src_line,
                requires_human_approval_card=True,
                approval_card=StepBackApprovalCardPayload(
                    escalation_type="UNKNOWN_PURCHASE_ORDER",
                    po_id="UNKNOWN",
                    invoice_id=invoice_id,
                    buyer_id="UNKNOWN",
                    supplier_id=supplier_id or "UNKNOWN",
                    source_file=src_file,
                    source_page_number=src_page,
                    source_line_number=src_line,
                    risk_category_ids=[10, 16, 18],
                    human_prompt_summary=(
                        "No PO identifier was found in the invoice data. "
                        "Manual review required before any payment is authorized."
                    ),
                ),
                reason="Payment blocked: No PO identifier in invoice. Manual review required.",
            )

        po_record = self._lookup_po(raw_po_id)
        if po_record is None:
            src_file = iban_src_file or amount_src_file
            return POVerificationResult(
                verified=False,
                execution_permitted=False,
                action_taken="HUMAN_APPROVAL_REQUIRED",
                po_id=raw_po_id,
                buyer_id=None,
                supplier_id=supplier_id,
                discrepancies=[f"PO '{raw_po_id}' not found in TRUSTED_PO_DB."],
                risk_category_ids=[10, 16, 18],
                source_file=src_file,
                source_page_number=iban_page,
                source_line_number=iban_line,
                requires_human_approval_card=True,
                approval_card=StepBackApprovalCardPayload(
                    escalation_type="UNKNOWN_PURCHASE_ORDER",
                    po_id=raw_po_id,
                    invoice_id=invoice_id,
                    buyer_id="UNKNOWN",
                    supplier_id=supplier_id or "UNKNOWN",
                    source_file=src_file,
                    source_page_number=iban_page,
                    source_line_number=iban_line,
                    risk_category_ids=[10, 16, 18],
                    human_prompt_summary=(
                        f"PO '{raw_po_id}' was not found in the trusted Purchase Order database. "
                        "This may indicate a forged or fabricated PO reference. "
                        "Do NOT authorize payment without manual verification."
                    ),
                ),
                reason=f"Payment blocked: PO '{raw_po_id}' not found in TRUSTED_PO_DB.",
            )

        discrepancies: List[str] = []

        # -- Check 2: Delivery Receipt -------------------------------------
        if po_record.delivery_receipt != "VERIFIED":
            return POVerificationResult(
                verified=False,
                execution_permitted=False,
                action_taken="HUMAN_APPROVAL_REQUIRED",
                po_id=po_record.po_id,
                buyer_id=po_record.buyer_id,
                supplier_id=po_record.supplier_id,
                matched_po=po_record,
                discrepancies=[
                    f"Delivery receipt status is '{po_record.delivery_receipt}', not 'VERIFIED'. "
                    "Payment cannot proceed until goods are confirmed delivered."
                ],
                risk_category_ids=[10, 18],
                source_file=iban_src_file,
                source_page_number=iban_page,
                source_line_number=iban_line,
                requires_human_approval_card=True,
                approval_card=StepBackApprovalCardPayload(
                    escalation_type="UNVERIFIED_DELIVERY_RECEIPT",
                    po_id=po_record.po_id,
                    invoice_id=invoice_id,
                    buyer_id=po_record.buyer_id,
                    supplier_id=po_record.supplier_id,
                    source_file=iban_src_file,
                    source_page_number=iban_page,
                    source_line_number=iban_line,
                    risk_category_ids=[10, 18],
                    human_prompt_summary=(
                        f"PO '{po_record.po_id}': Delivery receipt is '{po_record.delivery_receipt}'. "
                        "Payment must not be initiated until delivery is confirmed (status=VERIFIED)."
                    ),
                ),
                reason=(
                    f"Payment blocked: PO '{po_record.po_id}' delivery_receipt='{po_record.delivery_receipt}' "
                    "is not VERIFIED. Human approval required."
                ),
            )

        # -- Check 3: Bank Account / IBAN Match ----------------------------
        if iban_account is not None and iban_account != po_record.approved_bank_account:
            return POVerificationResult(
                verified=False,
                execution_permitted=False,
                action_taken="HUMAN_APPROVAL_REQUIRED",
                po_id=po_record.po_id,
                buyer_id=po_record.buyer_id,
                supplier_id=po_record.supplier_id,
                matched_po=po_record,
                discrepancies=[
                    f"Bank account mismatch: invoice specifies '{iban_account}' "
                    f"but PO '{po_record.po_id}' approves '{po_record.approved_bank_account}'. "
                    f"Detected at {iban_src_file or 'unknown source'} page {iban_page} line {iban_line}."
                ],
                risk_category_ids=[10, 16, 18],
                source_file=iban_src_file,
                source_page_number=iban_page,
                source_line_number=iban_line,
                requires_human_approval_card=True,
                approval_card=StepBackApprovalCardPayload(
                    escalation_type="BANK_ACCOUNT_MISMATCH",
                    po_id=po_record.po_id,
                    invoice_id=invoice_id,
                    buyer_id=po_record.buyer_id,
                    supplier_id=po_record.supplier_id,
                    expected_bank_account=po_record.approved_bank_account,
                    proposed_bank_account=iban_account,
                    source_file=iban_src_file,
                    source_page_number=iban_page,
                    source_line_number=iban_line,
                    risk_category_ids=[10, 16, 18],
                    human_prompt_summary=(
                        f"CRITICAL: Invoice for PO '{po_record.po_id}' requests payment to "
                        f"'{iban_account}' but the trusted PO database specifies "
                        f"'{po_record.approved_bank_account}'. "
                        f"Discrepancy found at {iban_src_file or 'PDF'} page {iban_page}, "
                        f"line {iban_line}. This is a potential supply-chain fraud attack "
                        "(Risk #10, #16, #18). DO NOT authorize payment without direct "
                        "confirmation from the supplier."
                    ),
                ),
                reason=(
                    f"SUPPLY-CHAIN FRAUD ALERT: Bank account '{iban_account}' does not match "
                    f"approved account '{po_record.approved_bank_account}' for PO '{po_record.po_id}'. "
                    f"Source: {iban_src_file or 'unknown'} page {iban_page} line {iban_line}. "
                    "Payment blocked. Human approval required. Risk #10, #16, #18."
                ),
            )

        # -- Check 4: Amount Limit ----------------------------------------
        if amount_inr is not None:
            if amount_inr <= 0 or amount_inr > po_record.approved_amount_inr:
                return POVerificationResult(
                    verified=False,
                    execution_permitted=False,
                    action_taken="HUMAN_APPROVAL_REQUIRED",
                    po_id=po_record.po_id,
                    buyer_id=po_record.buyer_id,
                    supplier_id=po_record.supplier_id,
                    matched_po=po_record,
                    discrepancies=[
                        f"Amount mismatch: invoice amount INR {amount_inr} exceeds "
                        f"PO approved amount INR {po_record.approved_amount_inr}. "
                        f"Source: {amount_src_file or 'unknown'} page {amount_page} line {amount_line}."
                    ],
                    risk_category_ids=[10, 16, 18],
                    source_file=amount_src_file,
                    source_page_number=amount_page,
                    source_line_number=amount_line,
                    requires_human_approval_card=True,
                    approval_card=StepBackApprovalCardPayload(
                        escalation_type="AMOUNT_EXCEEDS_PO_LIMIT",
                        po_id=po_record.po_id,
                        invoice_id=invoice_id,
                        buyer_id=po_record.buyer_id,
                        supplier_id=po_record.supplier_id,
                        expected_amount_inr=po_record.approved_amount_inr,
                        proposed_amount_inr=amount_inr,
                        source_file=amount_src_file,
                        source_page_number=amount_page,
                        source_line_number=amount_line,
                        risk_category_ids=[10, 16, 18],
                        human_prompt_summary=(
                            f"Invoice for PO '{po_record.po_id}' claims INR {amount_inr}, "
                            f"but approved limit is INR {po_record.approved_amount_inr}. "
                            f"Discrepancy at {amount_src_file or 'PDF'} page {amount_page} "
                            f"line {amount_line}. Manual approval required. Risk #10, #16, #18."
                        ),
                    ),
                    reason=(
                        f"Payment blocked: Invoice amount INR {amount_inr} exceeds PO limit "
                        f"INR {po_record.approved_amount_inr} for PO '{po_record.po_id}'. "
                        f"Source: {amount_src_file or 'unknown'} page {amount_page} line {amount_line}. "
                        "Risk #10, #16, #18."
                    ),
                )

        # -- Check 5: Supplier ID consistency ------------------------------
        if supplier_id is not None:
            allowed_supplier_ids = {
                po_record.supplier_id,
                po_record.supplier_enterprise_id,
            } - {None}
            if supplier_id not in allowed_supplier_ids:
                discrepancies.append(
                    f"Supplier ID '{supplier_id}' does not match PO record "
                    f"(expected: {po_record.supplier_id} / {po_record.supplier_enterprise_id})."
                )
                return POVerificationResult(
                    verified=False,
                    execution_permitted=False,
                    action_taken="HUMAN_APPROVAL_REQUIRED",
                    po_id=po_record.po_id,
                    buyer_id=po_record.buyer_id,
                    supplier_id=supplier_id,
                    matched_po=po_record,
                    discrepancies=discrepancies,
                    risk_category_ids=[10, 16],
                    source_file=iban_src_file,
                    source_page_number=iban_page,
                    source_line_number=iban_line,
                    requires_human_approval_card=True,
                    approval_card=StepBackApprovalCardPayload(
                        escalation_type="SUPPLIER_MISMATCH",
                        po_id=po_record.po_id,
                        invoice_id=invoice_id,
                        buyer_id=po_record.buyer_id,
                        supplier_id=supplier_id,
                        source_file=iban_src_file,
                        source_page_number=iban_page,
                        source_line_number=iban_line,
                        risk_category_ids=[10, 16],
                        human_prompt_summary=(
                            f"Supplier ID '{supplier_id}' in the invoice does not match the "
                            f"trusted PO record '{po_record.po_id}'. Manual verification required."
                        ),
                    ),
                    reason=(
                        f"Payment blocked: Supplier '{supplier_id}' mismatch on PO "
                        f"'{po_record.po_id}'. Risk #10, #16."
                    ),
                )

        # -- All checks passed -> SAFE_EXECUTED ----------------------------
        return POVerificationResult(
            verified=True,
            execution_permitted=True,
            action_taken="SAFE_EXECUTED",
            po_id=po_record.po_id,
            buyer_id=po_record.buyer_id,
            supplier_id=po_record.supplier_id,
            matched_po=po_record,
            discrepancies=[],
            risk_category_ids=[],
            source_file=iban_src_file,
            source_page_number=iban_page,
            source_line_number=iban_line,
            requires_human_approval_card=False,
            approval_card=None,
            reason=(
                f"PO '{po_record.po_id}' verified: amount INR {amount_inr} within limit "
                f"INR {po_record.approved_amount_inr}, bank account matches, "
                "delivery receipt VERIFIED. Payment authorized. TRUSTED_PO_DB."
            ),
        )


# Singleton instance
purchase_order_verifier = PurchaseOrderVerifier()
