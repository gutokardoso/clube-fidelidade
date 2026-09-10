from pathlib import Path


def test_automation_controls_align_to_message_bottom():
    css = (Path(__file__).parents[1] / "static" / "styles.css").read_text(encoding="utf-8")
    assert "/* v209 — alinhamento da base dos controles das automações */" in css
    block = css.split("/* v209 — alinhamento da base dos controles das automações */", 1)[1]
    assert ".automation-row .automation-settings" in block
    assert "align-self:end" in block
    assert ".automation-row .automation-actions" in block
    assert "padding-top:0" in block
