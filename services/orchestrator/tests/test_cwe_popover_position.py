"""CWE popover positioning behavior (mirrors shift_left/ui/static/app.js)."""

from __future__ import annotations

from pathlib import Path


def _compute_popover_position(
    *,
    trigger_top: float,
    trigger_bottom: float,
    trigger_left: float,
    trigger_width: float,
    pop_width: float,
    pop_height: float,
    viewport_width: float,
    viewport_height: float,
    margin: float = 8.0,
) -> tuple[float, float, bool]:
    """Return (left, top, flipped_below). Must stay aligned with app.js positionPopover."""
    left = trigger_left + trigger_width / 2 - pop_width / 2
    left = max(margin, min(left, viewport_width - pop_width - margin))
    top = trigger_top - pop_height - margin
    flipped = False
    if top < margin:
        top = trigger_bottom + margin
        flipped = True
    return round(left), round(top), flipped


def test_popover_flips_below_when_trigger_near_viewport_top() -> None:
    left, top, flipped = _compute_popover_position(
        trigger_top=20,
        trigger_bottom=40,
        trigger_left=100,
        trigger_width=60,
        pop_width=200,
        pop_height=120,
        viewport_width=800,
        viewport_height=600,
    )
    assert flipped is True
    assert top == 48  # trigger_bottom (40) + margin (8)


def test_popover_stays_above_when_room_available() -> None:
    left, top, flipped = _compute_popover_position(
        trigger_top=300,
        trigger_bottom=320,
        trigger_left=100,
        trigger_width=60,
        pop_width=200,
        pop_height=120,
        viewport_width=800,
        viewport_height=600,
    )
    assert flipped is False
    assert top == 172  # 300 - 120 - 8


def test_popover_repositions_on_scroll_via_capture_listener() -> None:
    app_js = (Path(__file__).resolve().parents[1] / "shift_left" / "ui" / "static" / "app.js").read_text()
    assert 'window.addEventListener(\n    "scroll"' in app_js or 'window.addEventListener("scroll"' in app_js
    assert "positionPopover(activeTrigger)" in app_js
    assert app_js.count("positionPopover") >= 2
    # Capture phase so nested scroll containers (e.g. findings table) trigger reposition.
    scroll_block = app_js.split('window.addEventListener("scroll"', 1)[-1]
    assert ",\n    true\n  )" in app_js or ", true)" in scroll_block


def test_popover_repositions_on_resize() -> None:
    app_js = (Path(__file__).resolve().parents[1] / "shift_left" / "ui" / "static" / "app.js").read_text()
    assert 'window.addEventListener("resize"' in app_js
    resize_tail = app_js.split('window.addEventListener("resize"', 1)[-1]
    assert "positionPopover(activeTrigger)" in resize_tail


def test_app_js_shows_unrecognized_model_cwe_notice() -> None:
    app_js = (Path(__file__).resolve().parents[1] / "shift_left" / "ui" / "static" / "app.js").read_text()
    assert "data-cwe-unrecognized" in app_js
    assert "Unrecognized identifier" in app_js
