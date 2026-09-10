from pathlib import Path

def test_v213_automation_no_rigid_desktop_overflow():
    css=Path('static/styles.css').read_text(encoding='utf-8')
    html=Path('static/attendant.html').read_text(encoding='utf-8')
    assert '/static/styles.css?v=213' in html
    block=css.split('/* v212 — automações: alinhamento sem overflow e responsividade validada */',1)[1]
    assert 'minmax(0,2.25fr)' in block
    assert 'min-width:0!important' in block
    assert 'max-width:100%!important' in block
    assert 'overflow:hidden!important' in block
    assert 'min-width:230px!important' not in block
    assert 'minmax(560px' not in block

def test_v213_has_safe_tablet_and_mobile_breakpoints():
    css=Path('static/styles.css').read_text(encoding='utf-8')
    block=css.split('/* v212 — automações: alinhamento sem overflow e responsividade validada */',1)[1]
    assert '@media (max-width:1180px)' in block
    assert '@media (max-width:640px)' in block
    assert '"actions actions"' in block
    assert 'grid-template-columns:minmax(0,1fr)!important' in block
