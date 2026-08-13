import os, unittest

ROOT=os.path.dirname(os.path.dirname(__file__))

class V27UITests(unittest.TestCase):
    def read(self,name):
        with open(os.path.join(ROOT,name),encoding='utf-8') as f: return f.read()

    def test_manager_goal_options_and_logo_default(self):
        html=self.read('static/manager.html')
        self.assertIn('<select id="cgoal" required>',html)
        for value in ('3','5','8','10','15'):
            self.assertIn(f'<option value="{value}"',html)
        self.assertIn('<option value="logo" selected>Usar a logo do cliente</option>',html)
        self.assertIn('<select id="ecgoal" required>',html)

    def test_birthday_background(self):
        html=self.read('static/attendant.html'); css=self.read('static/styles.css')
        self.assertIn('class="card birthday-card"',html)
        self.assertIn('.birthday-card{background:#fefac8}',css)

    def test_card_stamp_layout_rules(self):
        html=self.read('static/card.html'); css=self.read('static/styles.css')
        self.assertIn('const stampCols=c.goal===3?3:c.goal===8?4:5;',html)
        self.assertIn('repeat(var(--stamp-cols,5),48px)',css)
        self.assertIn('repeat(var(--stamp-cols,5),40px)',css)

    def test_build_marker_v27(self):
        for name in ('static/index.html','static/login.html','static/join.html','static/card.html','static/attendant.html','static/manager.html'):
            self.assertIn('v27',self.read(name),name)

if __name__=='__main__': unittest.main()
