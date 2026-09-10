from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def test_automation_layout_v208():
    html=(ROOT/'static'/'attendant.html').read_text(encoding='utf-8')
    css=(ROOT/'static'/'styles.css').read_text(encoding='utf-8')
    assert 'automation-head-main' in html
    assert 'automation-content' in html
    assert 'O texto do e-mail pode ser personalizado livremente. Use {nome} e {cliente}.' in html
    assert '.automation-row .automation-whatsapp-copy' in css
    block=css.split('.automation-row .automation-whatsapp-copy',1)[1].split('}',1)[0]
    assert 'background:transparent' in block
    assert 'border:0' in block
    assert 'white-space:nowrap' in css
    assert '/static/styles.css?v=213' in html
