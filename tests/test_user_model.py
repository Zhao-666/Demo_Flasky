import unittest
from app.models import User, Role, Permission, AnonymousUser
from app import create_app, db
import time


class UserModelTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing")
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_password_setter(self):
        u = User(password="cat")
        self.assertTrue(u.password_hash is not None)

    def test_no_password_getter(self):
        u = User(password="cat")
        with self.assertRaises(AttributeError):
            u.password

    def test_password_verification(self):
        u = User(password="cat")
        self.assertTrue(u.verify_password("cat"))
        self.assertFalse(u.verify_password("dog"))

    def test_password_salts_are_random(self):
        u = User(password="cat")
        u2 = User(password="dog")
        self.assertTrue(u.password_hash != u2.password_hash)

    def test_valid_confirmation_token(self):
        u = User(password="cat")
        db.session.add(u)
        db.session.commit()
        token = u.generate_confirmation_token()
        self.assertTrue(u.confirm(token))

    def test_invalid_confirmation_token(self):
        u = User(password="cat")
        u2 = User(password="dog")
        db.session.add(u)
        db.session.add(u2)
        db.session.commit()
        token = u.generate_confirmation_token()
        self.assertFalse(u2.confirm(token))

    def test_expired_confirmation_token(self):
        u = User(password="cat")
        db.session.add(u)
        db.session.commit()
        token = u.generate_confirmation_token(0.1)
        time.sleep(1)
        self.assertFalse(u.confirm(token))

    def test_valid_reset_token(self):
        u = User(email="123@qq.com")
        db.session.add(u)
        db.session.commit()
        token = u.generate_reset_token()
        self.assertTrue(u.confirm_reset(token))

    def test_invalid_reset_token(self):
        u = User(email="123@qq.com")
        u2 = User(email="111@qq.com")
        db.session.add(u)
        db.session.add(u2)
        db.session.commit()
        token = u.generate_reset_token()
        self.assertFalse(u2.confirm_reset(token))

    def test_valid_change_email_token(self):
        u = User(email="123@qq.com")
        db.session.add(u)
        db.session.commit()
        token = u.generate_change_email_token()
        self.assertTrue(u.confirm_change_email(token))

    def test_invalid_change_email_token(self):
        u = User(email="123@qq.com")
        u2 = User(email="111@qq.com")
        db.session.add(u)
        db.session.add(u2)
        db.session.commit()
        token = u.generate_change_email_token()
        self.assertFalse(u2.confirm_change_email(token))

    def test_roles_and_permissions(self):
        Role.insert_roles()
        u = User(email="john@example.com", password="cat")
        self.assertTrue(u.can(Permission.WRITE_ARTICLES))
        self.assertFalse(u.can(Permission.MODERATE_COMMENTS))

    def test_anonymous_user(self):
        u = AnonymousUser()
        self.assertFalse(u.can(Permission.FOLLOW))

    def test_gravatar(self):
        u = User(email="john@example.com", password="cat")
        with self.app.test_request_context("/"):
            gravatar = u.gravatar()
            gravatar_256 = u.gravatar(size=256)
            gravatar_pg = u.gravatar(rating="pg")
            gravatar_retro = u.gravatar(default="retro")

        with self.app.test_request_context("/", base_url="https://example.com"):
            gravatar_ssl = u.gravatar()
        self.assertTrue("http://www.gravatar.com/avatar/" +
                        'd4c74594d841139328695756648b6bd6' in gravatar)
        self.assertTrue("s=256" in gravatar_256)
        self.assertTrue('r=pg' in gravatar_pg)
        self.assertTrue('d=retro' in gravatar_retro)
        self.assertTrue('https://secure.gravatar.com/avatar/' +
                        'd4c74594d841139328695756648b6bd6' in gravatar_ssl)