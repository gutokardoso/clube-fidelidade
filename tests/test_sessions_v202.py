import unittest
import server
class SessionIsolationV202Tests(unittest.TestCase):
    def test_role_cookie_names_are_distinct(self):
        self.assertNotEqual(server.MANAGER_SESSION_COOKIE,server.COMPANY_SESSION_COOKIE)
        self.assertIn("fidelizae_manager_session=",server._session_cookie("abc",role="manager"))
        self.assertIn("fidelizae_company_session=",server._session_cookie("xyz",role="attendant"))
    def test_cookie_security_attributes_are_kept(self):
        value=server._session_cookie("abc",role="manager")
        self.assertIn("HttpOnly",value);self.assertIn("SameSite=Strict",value);self.assertIn("Path=/",value)
    def test_manager_delete_is_archive_not_destructive(self):
        html=open("static/manager.html",encoding="utf-8").read()
        self.assertIn("managerPost('/api/manager/campaign/delete',{campaign_id:id})",html)
        self.assertNotIn("permanent:true",html[html.index("async function deleteClient"):html.index("async function deleteStaff")])
    def test_internal_session_error_is_translated(self):
        html=open("static/manager.html",encoding="utf-8").read();self.assertIn("Sua sessão do Administrador Geral expirou ou foi substituída",html)

    def test_security_iframes_keep_their_auth_context(self):
        manager=open("static/manager.html",encoding="utf-8").read(); attendant=open("static/attendant.html",encoding="utf-8").read()
        self.assertIn("/security?embed=1&context=manager",manager)
        self.assertIn("/security?embed=1&context=company",attendant)
