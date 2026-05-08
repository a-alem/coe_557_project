import uuid


class AccessPolicyService:
    def __init__(self, drop_installer, drop_remover):
        self.blocked_ips = set()
        self.manual_allowed_ips = set()
        self.tokens = {}
        self.authenticated_hosts = {}
        self._install_drop = drop_installer
        self._remove_drop = drop_remover

    def create_token(self):
        token = str(uuid.uuid4())
        self.tokens[token] = {
            "active": True,
            "bound_ip": None,
        }
        return token

    def revoke_token(self, token):
        if token not in self.tokens:
            return False, "token not found"

        bound_ip = self.tokens[token]["bound_ip"]
        if bound_ip:
            self.authenticated_hosts.pop(bound_ip, None)
            self._install_drop(bound_ip)

        del self.tokens[token]
        return True, "token revoked"

    def authenticate_host(self, ip, token):
        if token not in self.tokens:
            self._install_drop(ip)
            return False, "invalid token"

        token_record = self.tokens[token]
        if not token_record["active"]:
            self._install_drop(ip)
            return False, "token is inactive"

        bound_ip = token_record["bound_ip"]

        if bound_ip is None:
            token_record["bound_ip"] = ip
            self.authenticated_hosts[ip] = token
            self.blocked_ips.discard(ip)
            self._remove_drop(ip)
            return True, "host authenticated and token bound"

        if bound_ip == ip:
            self.authenticated_hosts[ip] = token
            self.blocked_ips.discard(ip)
            self._remove_drop(ip)
            return True, "host already authenticated"

        self._install_drop(ip)
        return False, "token already bound to another host"

    def logout_host(self, ip):
        token = self.authenticated_hosts.pop(ip, None)

        if token and token in self.tokens:
            self.tokens[token]["bound_ip"] = None

        self._install_drop(ip)
        return True

    def is_host_allowed(self, ip):
        if ip in self.blocked_ips:
            return False

        if ip in self.manual_allowed_ips:
            return True

        if ip in self.authenticated_hosts:
            return True

        return False

    def block_host(self, ip):
        self.blocked_ips.add(ip)
        self.manual_allowed_ips.discard(ip)
        self.authenticated_hosts.pop(ip, None)

        for _, record in self.tokens.items():
            if record["bound_ip"] == ip:
                record["bound_ip"] = None

        self._install_drop(ip)

    def allow_host(self, ip):
        self.blocked_ips.discard(ip)
        self.manual_allowed_ips.add(ip)
        self._remove_drop(ip)

    def snapshot(self):
        return {
            "blocked_ips": sorted(list(self.blocked_ips)),
            "manual_allowed_ips": sorted(list(self.manual_allowed_ips)),
            "authenticated_hosts": self.authenticated_hosts,
            "tokens": self.tokens,
        }
