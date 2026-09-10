from pathlib import Path

def test_v211_automation_layout_and_cache_bust():
    root=Path(__file__).resolve().parents[1]
    html=(root/'static'/'attendant.html').read_text(encoding='utf-8')
    css=(root/'static'/'styles.css').read_text(encoding='utf-8')
    assert '/static/styles.css?v=212' in html
    assert '/* v211 — correção definitiva do layout das automações e cache-busting */' in css
    block=css.split('/* v211 — correção definitiva do layout das automações e cache-busting */',1)[1]
    assert 'grid-template-columns:minmax(360px, .95fr) minmax(560px, 2fr) minmax(230px, .72fr)!important' in block
    assert 'align-items:end!important' in block
    assert 'height:108px!important' in block
    assert 'grid-area:emailhelp!important' in block
    assert 'width:100%!important' in block

def test_v211_preserves_whatsapp_locked_visual():
    root=Path(__file__).resolve().parents[1]
    css=(root/'static'/'styles.css').read_text(encoding='utf-8')
    recent=css.split('/* v208 — automações reorganizadas conforme layout de referência */',1)[1]
    assert 'background:transparent' in recent
    assert 'border:0' in recent
