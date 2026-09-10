from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def test_finance_chart_has_growth_interactions_and_portuguese_months():
    html=(ROOT/'static'/'attendant.html').read_text(encoding='utf-8')
    assert 'manager-chart-guide' in html
    assert 'financeChartTooltip' in html
    assert 'box.onmousemove' in html
    assert "['jan','fev','mar','abr','mai','jun','jul','ago','set','out','nov','dez']" in html
    assert 'financeMonthLabel(item.month)' in html

def test_finance_chart_white_background_and_cache():
    css=(ROOT/'static'/'styles.css').read_text(encoding='utf-8')
    html=(ROOT/'static'/'attendant.html').read_text(encoding='utf-8')
    assert '.finance-dashboard{background:#fff!important' in css
    assert '.finance-line-chart.manager-line-chart .manager-chart-tooltip' in css
    assert '/static/styles.css?v=209' in html

def test_v206_migration_present():
    db=(ROOT/'db.py').read_text(encoding='utf-8')
    assert "VALUES('v205',?)" in db
    assert "VALUES('v206',?)" in db
