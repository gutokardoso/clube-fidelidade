from pathlib import Path

def test_archive_button_is_rendered_for_active_companies():
    html=Path('static/manager.html').read_text(encoding='utf-8')
    assert 'manager-archive-btn' in html
    assert '>Arquivar</button>' in html
    assert "archiveClient(${c.id})" in html

def test_restore_button_is_rendered_for_archived_companies():
    html=Path('static/manager.html').read_text(encoding='utf-8')
    assert 'manager-restore-btn' in html
    assert '>Restaurar</button>' in html

def test_company_actions_css_forces_visibility():
    css=Path('static/styles.css').read_text(encoding='utf-8')
    assert '.manager-company-table .manager-company-actions' in css
    assert '.manager-company-table .manager-archive-btn' in css
    assert 'display:inline-flex!important' in css
