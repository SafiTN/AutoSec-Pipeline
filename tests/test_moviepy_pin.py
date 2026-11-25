"""Smoke test for task T03 - Pin MoviePy 2.

Guards against an accidental regression to MoviePy 1.x (removed
``moviepy.editor`` layout, ``set_duration``/``set_audio`` API) or a
broken/partial moviepy install. Fully offline: only imports and checks
attributes, never renders a real video or touches ffmpeg.
"""

import importlib.metadata

import moviepy
from moviepy import AudioFileClip, ImageClip, concatenate_videoclips


def test_moviepy_installed_major_version_is_2():
    """Assert the installed moviepy wheel is major version 2.

    ``moviepy.__version__`` can lag behind the actual installed wheel
    version in some 2.x releases, so we treat
    ``importlib.metadata.version("moviepy")`` (the authoritative,
    installer-reported version) as the source of truth. We also check
    ``moviepy.__version__`` as a secondary sanity check, but only assert
    on its major version too (not exact equality with the metadata
    version), since the two are allowed to drift within the 2.x line.
    """
    installed_version = importlib.metadata.version("moviepy")
    installed_major = int(installed_version.split(".")[0])
    assert installed_major == 2, (
        f"requirements.txt pins moviepy>=2.0,<3 but the installed wheel reports version {installed_version!r}"
    )

    module_version = getattr(moviepy, "__version__", None)
    assert module_version is not None, "moviepy.__version__ is missing"
    module_major = int(module_version.split(".")[0])
    assert module_major == 2, (
        f"moviepy.__version__ reports {module_version!r}, "
        f"expected major version 2 (metadata version is {installed_version!r})"
    )


def test_moviepy_top_level_import_matches_2x_layout():
    """Importing directly from ``moviepy`` (not ``moviepy.editor``) must work.

    This is the import style used by
    ``modules/content_pipeline/media_generator.py``. In MoviePy 1.x these
    names lived under ``moviepy.editor``; that module was removed in 2.x,
    so a regression to 1.x would make this import fail.
    """
    assert AudioFileClip is not None
    assert ImageClip is not None
    assert concatenate_videoclips is not None


def test_imageclip_exposes_2x_immutable_api():
    """``media_generator.py`` relies on the 2.x ``with_*`` clip API.

    MoviePy 1.x used mutating ``set_duration``/``set_audio`` methods
    instead. Checking for their presence on the class (not an instance)
    keeps this test fast and avoids loading any real image/video data.
    """
    assert hasattr(ImageClip, "with_duration") is True
    assert hasattr(ImageClip, "with_audio") is True
