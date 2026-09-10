from pathlib import Path

def test_dashboard_order_nav_and_tooltip():
    html=Path("static/attendant.html").read_text()
    css=Path("static/styles.css").read_text()
    assert 'href="#dashboardCard">Dashboard</a>' in html
    assert html.index('id="financeDashboard"') < html.index('RETENÇÃO E DESEMPENHO')
    assert html.index('id="demographicDashboard"') < html.index('RETENÇÃO E DESEMPENHO')
    assert '<b>Dispositivos</b>' in html
    assert '>.manager-chart-tooltip{' in css
    assert 'height:auto!important' in css
    assert 'min-width:150px!important' in css

def test_v207_migration_present():
    db=Path("db.py").read_text()
    assert "VALUES('v207',?)" in db
