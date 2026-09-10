from pathlib import Path


def test_v210_alignment_uses_separate_help_row():
    root = Path(__file__).parents[1]
    css = (root / "static" / "styles.css").read_text(encoding="utf-8")
    html = (root / "static" / "attendant.html").read_text(encoding="utf-8")
    assert "/* v210 — base dos controles alinhada exatamente ao textarea */" in css
    block = css.split("/* v210 — base dos controles alinhada exatamente ao textarea */", 1)[1]
    assert '"settings message actions"' in block
    assert '". emailhelp ."' in block
    assert "grid-area:emailhelp" in block
    assert "align-self:end" in block
    # helper text is no longer inside the editor box whose height drives alignment
    assert '</textarea></div><div class="automation-whatsapp-inline hidden">' in html
    assert '</div><small class="muted automation-email-help">O texto do e-mail' in html
