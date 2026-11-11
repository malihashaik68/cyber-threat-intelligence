"""Image checks for suspected fakes. None of these PROVE an image is real or fake;
they give evidence to weigh, and the app says so.

  * metadata: camera make/model, dates, editing software
  * AI-generator traces: tags written by common generators/editors (e.g. Stable Diffusion
    'parameters', IPTC 'trainedAlgorithmicMedia', 'Midjourney', 'DALL-E', 'Firefly')
  * Content Credentials (C2PA): presence of a C2PA manifest (signature not verified here)
  * Error Level Analysis (ELA): re-save as JPEG and amplify the difference; regions edited
    after the last save often stand out
"""
from __future__ import annotations

import io
import re

from PIL import ExifTags, Image, ImageChops, ImageEnhance

AI_MARKERS = {
    "trainedalgorithmicmedia": "IPTC tag says the image was created by AI (trainedAlgorithmicMedia)",
    "compositewithtrainedalgorithmicmedia": "IPTC tag says the image was edited with AI",
    "stable diffusion": "Stable Diffusion", "sampler:": "Stable Diffusion generation settings",
    "negative prompt": "AI generation prompt", "midjourney": "Midjourney", "dall-e": "DALL-E", "dall·e": "DALL-E",
    "openai": "OpenAI", "adobe firefly": "Adobe Firefly", "generative fill": "Adobe Generative Fill",
    "comfyui": "ComfyUI", "novelai": "NovelAI", "leonardo.ai": "Leonardo.Ai", "imagen": "Google Imagen",
}
EDITORS = ["photoshop", "lightroom", "gimp", "canva", "snapseed", "facetune", "picsart", "affinity", "pixelmator"]


def inspect_image(data: bytes) -> dict:
    img = Image.open(io.BytesIO(data))
    info = {"format": img.format, "size": f"{img.width} x {img.height}", "mode": img.mode}
    exif = {}
    try:
        raw = img.getexif()
        exif = {ExifTags.TAGS.get(k, str(k)): str(v)[:200] for k, v in raw.items()}
        for k, v in raw.get_ifd(0x8769).items():  # Exif sub-IFD (dates, lens...)
            exif[ExifTags.TAGS.get(k, str(k))] = str(v)[:200]
    except Exception:
        pass
    text_chunks = {k: str(v)[:500] for k, v in (img.info or {}).items() if isinstance(v, (str, bytes))
                   and k not in ("icc_profile", "exif")}

    haystack = (" ".join(exif.values()) + " " + " ".join(text_chunks.values()) + " " +
                data[:2_000_000].decode("latin-1", errors="ignore")).lower()
    ai = sorted({label for marker, label in AI_MARKERS.items() if marker in haystack})
    editors = sorted({e.title() for e in EDITORS if e in haystack})
    c2pa = bool(re.search(r"c2pa|jumbf|contentauth", haystack))

    findings = []
    if ai:
        findings.append(("high", "AI-generation traces found: " + ", ".join(ai)))
    if c2pa:
        findings.append(("info", "Content Credentials (C2PA) data is present. Inspect it at contentcredentials.org/verify "
                                 "to see who made or edited the image (signature not verified here)."))
    if editors:
        findings.append(("medium", "Edited with: " + ", ".join(editors) + " (editing is common and not proof of a fake)"))
    camera = " ".join(x for x in (exif.get("Make"), exif.get("Model")) if x)
    if camera:
        findings.append(("info", f"Camera recorded: {camera}" + (f", taken {exif['DateTimeOriginal']}"
                                                                  if exif.get("DateTimeOriginal") else "")))
    if not exif and not text_chunks:
        findings.append(("info", "No metadata. Common for screenshots and images re-shared on social media "
                                 "(platforms strip it), so this alone proves nothing."))
    return {"info": info, "exif": exif, "text_chunks": text_chunks, "ai_markers": ai, "editors": editors,
            "c2pa": c2pa, "camera": camera, "findings": findings}


def error_level_analysis(data: bytes, quality: int = 90, scale: float = 15.0) -> Image.Image:
    """Return an ELA image: bright areas changed more when re-compressed."""
    original = Image.open(io.BytesIO(data)).convert("RGB")
    buf = io.BytesIO()
    original.save(buf, "JPEG", quality=quality)
    resaved = Image.open(io.BytesIO(buf.getvalue()))
    diff = ImageChops.difference(original, resaved)
    return ImageEnhance.Brightness(diff).enhance(scale)


CHECKLIST = [
    ("Face and edges", "Are edges around the face, hair or ears blurry, smeared or flickering?"),
    ("Eyes and blinking", "Do the eyes blink naturally? Do reflections in both eyes match?"),
    ("Mouth and speech", "Do lips match the words? Do teeth look natural?"),
    ("Hands and details", "Extra or merged fingers, odd jewellery, earrings that don't match?"),
    ("Lighting and shadows", "Do shadows and lighting match the rest of the scene?"),
    ("Text and background", "Is text in the image garbled? Do background objects melt or repeat?"),
    ("Voice", "Is the voice flat or robotic, with odd pauses or breathing?"),
    ("Context", "Is it pushing urgency, money, or secrecy? Is a trusted source reporting it?"),
]
