import json

from webob import Response

from ryu.app.wsgi import ControllerBase, route

from .constants import APP_INSTANCE_NAME, CLOUD_SERVER_IP


class IoTRESTController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(IoTRESTController, self).__init__(req, link, data, **config)
        self.iot_app = data[APP_INSTANCE_NAME]

    def json_response(self, data, status=200):
        return Response(
            content_type="application/json",
            charset="utf-8",
            status=status,
            body=json.dumps(data, indent=2).encode("utf-8"),
        )

    def parse_body(self, req):
        try:
            return json.loads(req.body.decode("utf-8"))
        except Exception:
            return {}

    @route("iot", "/state", methods=["GET"])
    def get_state(self, req, **kwargs):
        state = self.iot_app.policy.snapshot()
        state["cloud_server_ip"] = CLOUD_SERVER_IP
        return self.json_response(state)

    @route("iot", "/acl", methods=["GET"])
    def get_acl(self, req, **kwargs):
        return self.json_response({
            "blocked_ips": sorted(list(self.iot_app.policy.blocked_ips)),
            "manual_allowed_ips": sorted(list(self.iot_app.policy.manual_allowed_ips)),
        })

    @route("iot", "/acl/block", methods=["POST"])
    def acl_block(self, req, **kwargs):
        body = self.parse_body(req)
        ip = body.get("ip")

        if not ip:
            return self.json_response({"error": "missing ip"}, status=400)

        self.iot_app.policy.block_host(ip)
        return self.json_response({
            "message": "host blocked",
            "ip": ip,
        })

    @route("iot", "/acl/allow", methods=["POST"])
    def acl_allow(self, req, **kwargs):
        body = self.parse_body(req)
        ip = body.get("ip")

        if not ip:
            return self.json_response({"error": "missing ip"}, status=400)

        self.iot_app.policy.allow_host(ip)
        return self.json_response({
            "message": "host manually allowed",
            "ip": ip,
        })

    @route("iot", "/token", methods=["GET"])
    def list_tokens(self, req, **kwargs):
        return self.json_response({"tokens": self.iot_app.policy.tokens})

    @route("iot", "/token/create", methods=["POST"])
    def token_create(self, req, **kwargs):
        token = self.iot_app.policy.create_token()
        return self.json_response({
            "message": "token created",
            "token": token,
        })

    @route("iot", "/token/revoke", methods=["POST"])
    def token_revoke(self, req, **kwargs):
        body = self.parse_body(req)
        token = body.get("token")

        if not token:
            return self.json_response({"error": "missing token"}, status=400)

        ok, message = self.iot_app.policy.revoke_token(token)
        if not ok:
            return self.json_response({"error": message}, status=404)

        return self.json_response({
            "message": message,
            "token": token,
        })

    @route("iot", "/auth/login", methods=["POST"])
    def auth_login(self, req, **kwargs):
        body = self.parse_body(req)
        ip = body.get("ip")
        token = body.get("token")

        if not ip:
            return self.json_response({"error": "missing ip"}, status=400)

        if not token:
            return self.json_response({"error": "missing token"}, status=400)

        ok, message = self.iot_app.policy.authenticate_host(ip, token)
        status = 200 if ok else 403

        return self.json_response({
            "authenticated": ok,
            "message": message,
            "ip": ip,
        }, status=status)

    @route("iot", "/auth/logout", methods=["POST"])
    def auth_logout(self, req, **kwargs):
        body = self.parse_body(req)
        ip = body.get("ip")

        if not ip:
            return self.json_response({"error": "missing ip"}, status=400)

        self.iot_app.policy.logout_host(ip)
        return self.json_response({
            "message": "host logged out and blocked",
            "ip": ip,
        })
