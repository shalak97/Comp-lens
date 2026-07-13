"""Load GRC platform profiles from YAML — adding a platform is dropping a file.

Profiles are discovered from (in order):
  1. built-in profiles (app.grc_platforms.profiles.ALL_PROFILES)
  2. YAML files in GRC_PROFILE_DIR (env var) or app/grc_platforms/profiles_yaml/

A YAML profile only needs the platform's API shape + which frameworks it speaks;
the shared standards crosswalk does the control translation. This is the
"trust sources as code" extension of the compliance-as-code model.
"""
from __future__ import annotations

import glob
import os

from app.grc_platforms.base import PlatformProfile


def _builtin() -> dict[str, PlatformProfile]:
    from app.grc_platforms.profiles import ALL_PROFILES
    return dict(ALL_PROFILES)


def _yaml_dir() -> str:
    return os.getenv("GRC_PROFILE_DIR") or os.path.join(
        os.path.dirname(__file__), "profiles_yaml")


def load_yaml_profiles(directory: str = None) -> dict[str, PlatformProfile]:
    """Parse every *.yaml/*.yml in the profile directory into PlatformProfiles."""
    directory = directory or _yaml_dir()
    out: dict[str, PlatformProfile] = {}
    if not os.path.isdir(directory):
        return out
    try:
        import yaml
    except ImportError:
        return out
    for path in sorted(glob.glob(os.path.join(directory, "*.y*ml"))):
        try:
            with open(path) as fh:
                for doc in yaml.safe_load_all(fh):
                    if not isinstance(doc, dict) or "platform" not in doc:
                        continue
                    prof = PlatformProfile.from_dict(doc, source=f"yaml:{os.path.basename(path)}")
                    out[prof.platform.upper()] = prof
        except Exception:
            # a malformed profile file should never crash the registry
            continue
    return out


def load_all_profiles() -> dict[str, PlatformProfile]:
    """Built-in profiles, with YAML profiles layered on top (YAML can override)."""
    profiles = _builtin()
    profiles.update(load_yaml_profiles())
    return profiles
