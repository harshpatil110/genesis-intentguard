"""
IntentGuard Layer 1 Multi-Modal Pre-OCR De-Cloaker (Audio, Voice Notes & Video)
================================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01
Separating Data from Authority: Securing AI Agents Against Indirect Prompt Injection

Neutralizes media-based indirect prompt injection attacks:
- Risk #4: Multimodal Prompt Injections (Spoken audio commands, flashed video text)
- Risk #13: Trust Escalation (Laundering spoken attacks into trusted summaries)
- Risk #14: Instruction Override (Subliminal video frames overriding agent goals)
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import re
import shutil
import tempfile
import uuid
from typing import Any, Dict, List, Optional, Tuple

import cv2
import numpy as np
import pytesseract

try:
    from moviepy import VideoFileClip
except ImportError:
    try:
        from moviepy.editor import VideoFileClip  # type: ignore[no-redef]
    except ImportError:
        VideoFileClip = None  # type: ignore[assignment]

from app.config import settings
from app.layer1_decloaker.pdf_docx_decloaker import (
    CloakedSpanFinding,
    DocumentDeCloakResult,
)

logger = logging.getLogger(__name__)

# Ensure Tesseract executable path is resolved on Windows environments
_DEFAULT_WIN_TESSERACT_PATHS = [
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
    r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe"),
]
if shutil.which("tesseract") is None:
    for candidate in _DEFAULT_WIN_TESSERACT_PATHS:
        if os.path.isfile(candidate):
            pytesseract.pytesseract.tesseract_cmd = candidate
            break

# Injection keywords across spoken audio and video frames
_MEDIA_INJECTION_KEYWORD_RE = re.compile(
    r"(?i)(?:\b(?:ignore\s+(?:all\s+)?(?:previous\s+)?(?:instructions?|rules?|restrictions?|the\s+rest\s+of\s+this\s+audio)|"
    r"system\s+(?:override|update|prompt)|"
    r"override\s+(?:all\s+)?(?:previous\s+)?(?:instructions?|rules?)|"
    r"disregard\s+(?:all\s+)?(?:previous\s+)?instructions?|"
    r"forward\s+all\s+(?:files?|emails?|data|secrets?)|"
    r"delete\s+(?:all\s+)?(?:files?|calendar|database|records?)|"
    r"transfer\s+(?:all\s+)?(?:funds?|money|balance)|"
    r"wire\s+(?:all\s+)?(?:funds?|money)|"
    r"send\s+api\s+key|admin\s+override|bypass\s+security|"
    r"exfiltrate\s+(?:all|data|logs)|"
    r"steal\s+(?:credentials|tokens|keys))\b|"
    r"\[(?:hidden\s+voice|spoken\s+(?:command|override)|voice\s+injection|ultrasonic\s+(?:directive|command)|subliminal\s+(?:voice|command))\])",
    re.I,
)


class AudioVideoDeCloaker:
    """
    Layer 1 Pre-OCR Audio & Video De-Cloaker Engine.
    Performs:
    1. Whisper speech-to-text transcription for voice notes & audio files.
    2. Surgical redaction of spoken prompt injections to preserve Task Continuity.
    3. 1fps video frame sampling & OCR to detect subliminal flashed text.
    4. Subtitle (.srt / .vtt) metadata scanning.
    5. Disguised executable payload verification.
    """

    def __init__(self) -> None:
        self._whisper_model: Any = None

    def _get_whisper_model(self) -> Any:
        """Lazily load local Whisper model to conserve resources."""
        if self._whisper_model is None:
            import whisper

            model_name = getattr(settings, "WHISPER_MODEL", "base")
            logger.info("Loading local Whisper model: '%s'", model_name)
            self._whisper_model = whisper.load_model(model_name)
        return self._whisper_model

    # ───────────────────────────────────────────────────────────────────────
    # 1. Audio Transcription via Whisper
    # ───────────────────────────────────────────────────────────────────────

    def transcribe_audio_whisper(
        self, audio_bytes: bytes, audio_format: str = "wav"
    ) -> str:
        """
        Transcribes audio bytes to raw text using OpenAI Whisper.
        Saves bytes to a temporary file, invokes Whisper, and cleans up.
        """
        if not audio_bytes:
            return ""

        suffix = f".{audio_format.lstrip('.')}"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as temp_audio:
            temp_audio.write(audio_bytes)
            temp_audio_path = temp_audio.name

        try:
            model = self._get_whisper_model()
            result = model.transcribe(temp_audio_path)
            transcript = result.get("text", "")
            return transcript.strip() if isinstance(transcript, str) else ""
        except Exception as exc:
            logger.warning("Whisper transcription error: %s", exc)
            return ""
        finally:
            if os.path.exists(temp_audio_path):
                try:
                    os.remove(temp_audio_path)
                except OSError:
                    pass

    # ───────────────────────────────────────────────────────────────────────
    # 2. Spoken Prompt Injection Surgical Redactor
    # ───────────────────────────────────────────────────────────────────────

    def redact_malicious_transcript(
        self, raw_transcript: str, modality: str = "audio"
    ) -> Tuple[str, List[CloakedSpanFinding]]:
        """
        Surgically redacts spoken prompt injection commands from transcripts.
        Replaces imperative attack sentences with '[REDACTED_MALICIOUS_AUDIO_COMMAND]'
        while preserving legitimate surrounding meeting notes or voice message context.
        """
        findings: List[CloakedSpanFinding] = []
        if not raw_transcript.strip():
            return "", findings

        # Split on sentence boundaries preserving delimiters (. ! ? \n)
        parts = re.split(r"(\. |\? |\! |\n+)", raw_transcript)
        sanitized_parts: List[str] = []

        for i in range(0, len(parts), 2):
            sentence = parts[i]
            delim = parts[i + 1] if i + 1 < len(parts) else ""

            if _MEDIA_INJECTION_KEYWORD_RE.search(sentence):
                matched_text = sentence.strip()
                findings.append(
                    CloakedSpanFinding(
                        finding_id=f"audio-{uuid.uuid4().hex[:8]}",
                        modality=modality,  # type: ignore[arg-type]
                        page_or_paragraph=len(findings) + 1,
                        cloak_reason="SPOKEN_PROMPT_INJECTION",
                        hidden_text=f"Spoken command neutralized: '{matched_text}'",
                        risk_category_ids=[4, 13],
                    )
                )
                sanitized_parts.append(f"[REDACTED_MALICIOUS_AUDIO_COMMAND]{delim}")
            else:
                sanitized_parts.append(sentence + delim)

        sanitized_transcript = "".join(sanitized_parts).strip()
        return sanitized_transcript, findings

    redact_spoken_injections = redact_malicious_transcript

    # ───────────────────────────────────────────────────────────────────────
    # 3. Video Frame Flashed-Text OCR (1 frame per second)
    # ───────────────────────────────────────────────────────────────────────

    def scan_video_frames(
        self, video_bytes: bytes, max_seconds_to_scan: int = 120
    ) -> Tuple[List[CloakedSpanFinding], List[str]]:
        """
        Samples video frames at 1 frame per second and executes OCR via Tesseract.
        Detects subliminal flashed text injection directives.
        """
        findings: List[CloakedSpanFinding] = []
        sampled_ocr_texts: List[str] = []

        if not video_bytes:
            return findings, sampled_ocr_texts

        with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as temp_video:
            temp_video.write(video_bytes)
            temp_video_path = temp_video.name

        cap = cv2.VideoCapture(temp_video_path)
        try:
            fps = cap.get(cv2.CAP_PROP_FPS)
            if fps <= 0 or np.isnan(fps):
                fps = 24.0

            frame_interval = max(1, int(round(fps)))
            frame_idx = 0
            seconds_processed = 0

            while cap.isOpened() and seconds_processed < max_seconds_to_scan:
                ret, frame = cap.read()
                if not ret:
                    break

                if frame_idx % frame_interval == 0:
                    seconds_processed += 1
                    second_timestamp = seconds_processed

                    # Convert to grayscale and run OCR
                    try:
                        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                        _, thresh = cv2.threshold(
                            gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU
                        )
                        frame_text = pytesseract.image_to_string(thresh).strip()
                    except Exception as ocr_exc:
                        logger.debug("Frame OCR error at sec %d: %s", second_timestamp, ocr_exc)
                        frame_text = ""

                    if frame_text:
                        sampled_ocr_texts.append(f"[sec {second_timestamp}] {frame_text}")

                        # Check for subliminal injection directives
                        for line in frame_text.splitlines():
                            line_clean = line.strip()
                            if _MEDIA_INJECTION_KEYWORD_RE.search(line_clean):
                                findings.append(
                                    CloakedSpanFinding(
                                        finding_id=f"video-{uuid.uuid4().hex[:8]}",
                                        modality="video",
                                        page_or_paragraph=second_timestamp,
                                        cloak_reason="SUBLIMINAL_VIDEO_TEXT",
                                        hidden_text=(
                                            f"Subliminal flashed text at second {second_timestamp}: "
                                            f"'{line_clean}'"
                                        ),
                                        risk_category_ids=[4, 14],
                                    )
                                )

                frame_idx += 1
        except Exception as exc:
            logger.warning("Video frame scanning error: %s", exc)
        finally:
            cap.release()
            if os.path.exists(temp_video_path):
                try:
                    os.remove(temp_video_path)
                except OSError:
                    pass

        return findings, sampled_ocr_texts

    # ───────────────────────────────────────────────────────────────────────
    # 4. Subtitle Parsing & Scanning
    # ───────────────────────────────────────────────────────────────────────

    def scan_subtitles(self, subtitle_text: str) -> Tuple[List[CloakedSpanFinding], str]:
        """
        Scans embedded or metadata subtitle text (.srt / .vtt) for injection keywords.
        """
        findings: List[CloakedSpanFinding] = []
        if not subtitle_text or not subtitle_text.strip():
            return findings, ""

        clean_lines: List[str] = []
        for line in subtitle_text.splitlines():
            line_clean = line.strip()
            if _MEDIA_INJECTION_KEYWORD_RE.search(line_clean):
                findings.append(
                    CloakedSpanFinding(
                        finding_id=f"sub-{uuid.uuid4().hex[:8]}",
                        modality="video",
                        page_or_paragraph=1,
                        cloak_reason="MALICIOUS_SUBTITLES",
                        hidden_text=f"Malicious subtitle directive: '{line_clean}'",
                        risk_category_ids=[4, 14],
                    )
                )
                clean_lines.append("[REDACTED_MALICIOUS_SUBTITLE]")
            else:
                clean_lines.append(line)

        return findings, "\n".join(clean_lines)

    # ───────────────────────────────────────────────────────────────────────
    # 5. Video Audio Track Extraction
    # ───────────────────────────────────────────────────────────────────────

    def extract_audio_from_video(self, video_bytes: bytes) -> bytes:
        """Extracts the audio track from an MP4 video container as audio bytes."""
        if not video_bytes:
            return b""

        with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as temp_video:
            temp_video.write(video_bytes)
            temp_video_path = temp_video.name

        temp_audio_path = temp_video_path + ".wav"
        try:
            if VideoFileClip is not None:
                clip = VideoFileClip(temp_video_path)
                if clip.audio is not None:
                    clip.audio.write_audiofile(
                        temp_audio_path,
                        logger=None,
                        fps=16000,
                        nbytes=2,
                        codec="pcm_s16le",
                    )
                    clip.close()
                    if os.path.exists(temp_audio_path):
                        with open(temp_audio_path, "rb") as af:
                            return af.read()
                clip.close()
        except Exception as exc:
            logger.warning("Could not extract audio track via moviepy: %s", exc)
        finally:
            if os.path.exists(temp_video_path):
                try:
                    os.remove(temp_video_path)
                except OSError:
                    pass
            if os.path.exists(temp_audio_path):
                try:
                    os.remove(temp_audio_path)
                except OSError:
                    pass

        return b""

    # ───────────────────────────────────────────────────────────────────────
    # 6. Main Media De-Cloaking Pipeline
    # ───────────────────────────────────────────────────────────────────────

    def decloak_media_bytes(
        self,
        file_bytes: bytes,
        modality: str = "audio",
        filename: str = "audio.wav",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> DocumentDeCloakResult:
        """
        Full de-cloaking pipeline for Audio & Video inputs:
        - Audio: Whisper transcription + spoken injection redaction.
        - Video: Audio track extraction + Whisper transcription + 1fps OCR.
        - Subtitle scanning if provided in metadata.
        Returns a structured DocumentDeCloakResult.
        """
        raw_evidence_sha256 = hashlib.sha256(file_bytes).hexdigest().lower()
        findings: List[CloakedSpanFinding] = []
        risk_category_ids: List[int] = []
        metadata = metadata or {}

        normalized_modality = "video" if modality in ("video", "mp4") or filename.lower().endswith((".mp4", ".mov", ".m4v", ".webm")) else "audio"

        raw_transcript = ""
        sanitized_transcript = ""

        # 1. Audio Processing
        if normalized_modality == "audio":
            # Extract format from filename or default to wav
            ext = os.path.splitext(filename)[1].lstrip(".").lower() or "wav"
            raw_transcript = self.transcribe_audio_whisper(file_bytes, audio_format=ext)
            sanitized_transcript, spoken_findings = self.redact_malicious_transcript(
                raw_transcript, modality="audio"
            )
            for f in spoken_findings:
                findings.append(f)
                for r_id in f.risk_category_ids:
                    if r_id not in risk_category_ids:
                        risk_category_ids.append(r_id)

        # 2. Video Processing
        elif normalized_modality == "video":
            # 2a. Extract and transcribe audio track
            audio_track_bytes = self.extract_audio_from_video(file_bytes)
            if audio_track_bytes:
                raw_transcript = self.transcribe_audio_whisper(
                    audio_track_bytes, audio_format="wav"
                )
                sanitized_transcript, spoken_findings = (
                    self.redact_malicious_transcript(raw_transcript, modality="video")
                )
                for f in spoken_findings:
                    findings.append(f)
                    for r_id in f.risk_category_ids:
                        if r_id not in risk_category_ids:
                            risk_category_ids.append(r_id)

            # 2b. Scan video frames at 1 frame per second
            frame_findings, frame_texts = self.scan_video_frames(file_bytes)
            for f in frame_findings:
                findings.append(f)
                for r_id in f.risk_category_ids:
                    if r_id not in risk_category_ids:
                        risk_category_ids.append(r_id)

            # 2c. Scan subtitles if present in metadata
            subtitles_text = metadata.get("subtitles") or metadata.get("srt") or metadata.get("vtt")
            if isinstance(subtitles_text, str) and subtitles_text.strip():
                sub_findings, clean_subs = self.scan_subtitles(subtitles_text)
                for f in sub_findings:
                    findings.append(f)
                    for r_id in f.risk_category_ids:
                        if r_id not in risk_category_ids:
                            risk_category_ids.append(r_id)

        visible_clean_text = sanitized_transcript
        threat_detected = len(findings) > 0

        diff_payload = f"RAW:{raw_evidence_sha256}|CLEAN:{visible_clean_text}|FINDINGS:{len(findings)}"
        redacted_diff_sha256 = (
            hashlib.sha256(diff_payload.encode("utf-8")).hexdigest().lower()
        )

        summary = (
            f"Media De-Cloaker neutralized {len(findings)} threat(s) across audio/video stream."
            if threat_detected
            else f"Media file is clean: no spoken prompt injections or subliminal video threats found."
        )

        return DocumentDeCloakResult(
            raw_evidence_sha256=raw_evidence_sha256,
            redacted_diff_sha256=redacted_diff_sha256,
            modality=normalized_modality,  # type: ignore[arg-type]
            visible_clean_text=visible_clean_text,
            raw_unfiltered_text=raw_transcript,
            cloaked_findings=findings,
            metadata_sanitized={},
            threat_detected=threat_detected,
            risk_category_ids=sorted(list(set(risk_category_ids))),
            summary=summary,
        )


# Singleton instance for application-wide use
audio_video_decloaker = AudioVideoDeCloaker()
