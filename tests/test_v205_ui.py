from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def test_v205_finance_chart_matches_growth_visual_language():
    attendant=(ROOT/'static/attendant.html').read_text(encoding='utf-8')
    styles=(ROOT/'static/styles.css').read_text(encoding='utf-8')
    assert 'manager-growth-line growth-current' in attendant
    assert 'manager-chart-gridline' in attendant
    assert 'manager-last-value' in attendant
    assert 'source.slice(-3)' in attendant
    assert '.finance-line-chart.manager-line-chart' in styles
    assert 'stroke:#e27a00' in styles

def test_v205_company_action_labels_and_responsive_breakpoint():
    manager=(ROOT/'static/manager.html').read_text(encoding='utf-8')
    styles=(ROOT/'static/styles.css').read_text(encoding='utf-8')
    assert '>Excluir empresa</button>' not in manager
    assert '>Excluir definitivamente</button>' not in manager
    assert manager.count('>Excluir</button>') >= 2
    assert '@media(max-width:1180px)' in styles
    assert '.manager-company-table tbody>tr:not(:first-child)' in styles
    assert 'grid-template-columns:repeat(4,minmax(0,1fr))' in styles

def test_v205_cache_and_migration_history():
    manager=(ROOT/'static/manager.html').read_text(encoding='utf-8')
    db=(ROOT/'db.py').read_text(encoding='utf-8')
    assert 'styles.css?v=206' in manager
    assert "VALUES('v204',?)" in db
    assert "VALUES('v205',?)" in db
