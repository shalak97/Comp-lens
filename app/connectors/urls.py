"""Safe construction of upstream URL paths from caller-supplied references.

Every connector takes an `asset_id` from the request body and puts it into an
upstream path. Interpolated raw, that reference decides which endpoint is
called, not just which object:

    asset_id = "../../api/v1/apps"  ->  https://acme.okta.com/api/api/v1/apps
    asset_id = "u1?expand=all"      ->  .../users/u1?expand=all

`requests` normalises dot-segments before the request goes out, so the traversal
is real. The host is pinned and every connector is GET-only, so this is not SSRF
to an arbitrary host — it is endpoint redirection *inside the customer's own
tenant, using their token*. A finding recorded for control X on asset Y can be
backed by a payload fetched from an unrelated endpoint, which is evidence
provenance corruption in a product whose whole value is evidence integrity.

Two helpers, because connectors have two shapes of reference:

    segment("u1?expand=all")     -> "u1%3Fexpand%3Dall"      one path segment
    multi_segment("owner/repo")  -> "owner/repo"             a known-arity path

`segment` percent-encodes everything, `/` included, so a reference can never
grow a path. `multi_segment` keeps the separators a reference legitimately has
(GitHub's `owner/repo`) but encodes each part and refuses `.`/`..`, so it cannot
traverse either.
"""
from __future__ import annotations

from urllib.parse import quote

#: Segments that would change what the path means rather than what it names.
_TRAVERSAL = {"", ".", ".."}


class UnsafeReferenceError(ValueError):
    """A caller-supplied reference that cannot be placed in a URL path."""


def segment(value: object) -> str:
    """Percent-encode one path segment. `/`, `?`, `#` and `..` cannot survive."""
    text = str(value)
    if not text.strip():
        raise UnsafeReferenceError("empty path reference")
    if text.strip() in _TRAVERSAL:
        raise UnsafeReferenceError(f"invalid path reference: {text!r}")
    return quote(text, safe="")


def multi_segment(value: object, *, expected_parts: int | None = None) -> str:
    """Encode a reference that legitimately spans several segments.

    Used for references whose shape includes a separator — GitHub's
    `owner/repo`. Each part is encoded independently and the separators are
    preserved, so `owner/repo` survives intact while `owner/../../x` is refused.
    `expected_parts` pins the arity when the connector knows it.
    """
    text = str(value).strip()
    if not text:
        raise UnsafeReferenceError("empty path reference")
    parts = text.split("/")
    if expected_parts is not None and len(parts) != expected_parts:
        raise UnsafeReferenceError(
            f"expected {expected_parts} path part(s) in {text!r}, got {len(parts)}")
    for p in parts:
        if p.strip() in _TRAVERSAL:
            raise UnsafeReferenceError(f"invalid path reference: {text!r}")
    return "/".join(quote(p, safe="") for p in parts)


__all__ = ["UnsafeReferenceError", "segment", "multi_segment"]
