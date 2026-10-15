"""
IntentGuard Layer 1 Multi-Modal Pre-OCR De-Cloaker
===================================================
GENESIS 2.0 | Track: EVA 03 | PS 01

Mechanical de-cloaking of hidden prompt injections in PDFs and DOCX files.
Detects 0.1pt micro-fonts, white-on-white text, off-page cropbox traps,
opaque vector occlusions, suspicious metadata, embedded JavaScript,
and DOCX hidden runs.
"""

from app.layer1_decloaker.audio_video_decloaker import (
    AudioVideoDeCloaker,
    audio_video_decloaker,
)
from app.layer1_decloaker.image_decloaker import (
    ImageDeCloaker,
    image_decloaker,
)
from app.layer1_decloaker.pdf_docx_decloaker import (
    CloakedSpanFinding,
    DocumentDeCloakResult,
    PDFDocxDeCloaker,
    compute_contrast_ratio,
    int_color_to_rgb,
    pdf_docx_decloaker,
    relative_luminance,
)

__all__ = [
    "CloakedSpanFinding",
    "DocumentDeCloakResult",
    "PDFDocxDeCloaker",
    "compute_contrast_ratio",
    "int_color_to_rgb",
    "pdf_docx_decloaker",
    "relative_luminance",
    "ImageDeCloaker",
    "image_decloaker",
    "AudioVideoDeCloaker",
    "audio_video_decloaker",
]


