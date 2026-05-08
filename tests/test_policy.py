import unittest

from controller.policy import AccessPolicyService


class AccessPolicyServiceTest(unittest.TestCase):
    def setUp(self):
        self.installed = []
        self.removed = []

        self.policy = AccessPolicyService(
            drop_installer=self.installed.append,
            drop_remover=self.removed.append,
        )

    def test_new_token_can_bind_and_allow_host(self):
        token = self.policy.create_token()

        ok, message = self.policy.authenticate_host("10.0.0.1", token)

        self.assertTrue(ok)
        self.assertEqual("host authenticated and token bound", message)
        self.assertEqual("10.0.0.1", self.policy.tokens[token]["bound_ip"])
        self.assertIn("10.0.0.1", self.policy.authenticated_hosts)
        self.assertIn("10.0.0.1", self.removed)
        self.assertTrue(self.policy.is_host_allowed("10.0.0.1"))

    def test_token_cannot_be_reused_by_different_host(self):
        token = self.policy.create_token()
        self.policy.authenticate_host("10.0.0.1", token)

        ok, message = self.policy.authenticate_host("10.0.0.2", token)

        self.assertFalse(ok)
        self.assertEqual("token already bound to another host", message)
        self.assertIn("10.0.0.2", self.installed)
        self.assertNotIn("10.0.0.2", self.policy.authenticated_hosts)

    def test_logout_unbinds_token_and_blocks_host(self):
        token = self.policy.create_token()
        self.policy.authenticate_host("10.0.0.1", token)

        self.policy.logout_host("10.0.0.1")

        self.assertIsNone(self.policy.tokens[token]["bound_ip"])
        self.assertNotIn("10.0.0.1", self.policy.authenticated_hosts)
        self.assertIn("10.0.0.1", self.installed)

    def test_revoke_removes_token_and_blocks_bound_host(self):
        token = self.policy.create_token()
        self.policy.authenticate_host("10.0.0.1", token)

        ok, message = self.policy.revoke_token(token)

        self.assertTrue(ok)
        self.assertEqual("token revoked", message)
        self.assertNotIn(token, self.policy.tokens)
        self.assertIn("10.0.0.1", self.installed)

    def test_manual_block_overrides_allow(self):
        self.policy.allow_host("10.0.0.3")
        self.assertTrue(self.policy.is_host_allowed("10.0.0.3"))

        self.policy.block_host("10.0.0.3")

        self.assertFalse(self.policy.is_host_allowed("10.0.0.3"))
        self.assertIn("10.0.0.3", self.installed)


if __name__ == "__main__":
    unittest.main()
