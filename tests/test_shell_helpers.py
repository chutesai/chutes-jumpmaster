import asyncio
import io
import json
import sys
import types
import unittest
from argparse import Namespace
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import NamedTemporaryFile
from types import SimpleNamespace
from unittest import mock
from urllib.error import HTTPError


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import shell_helpers  # noqa: E402


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class ShellHelpersTests(unittest.TestCase):
    def test_emit_tsv(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            shell_helpers.emit_tsv(["a\tb", None, 3])
        self.assertEqual(buf.getvalue(), "a b\t\t3\n")

    def test_find_first(self):
        data = {"outer": [{"ignored": ""}, {"nested": {"user_id": "abc-123"}}]}
        self.assertEqual(shell_helpers.find_first(data, ["user_id", "id"]), "abc-123")

    def test_get_signing_message(self):
        self.assertEqual(shell_helpers.get_signing_message("hot", "123", "me"), "hot:123:me")

    def test_parse_hotkey_file(self):
        with NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
            json.dump({"ss58Address": "5abc", "secretSeed": "0xdeadbeef"}, tmp)
            path = tmp.name

        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                status = shell_helpers.parse_hotkey_file(Namespace(path=path))
            self.assertEqual(status, 0)
            self.assertEqual(buf.getvalue(), "5abc\tdeadbeef\n")
        finally:
            Path(path).unlink()

    def test_parse_hotkey_file_missing_fields(self):
        with NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
            json.dump({"ss58Address": "5abc"}, tmp)
            path = tmp.name

        try:
            err = io.StringIO()
            with redirect_stderr(err):
                status = shell_helpers.parse_hotkey_file(Namespace(path=path))
            self.assertEqual(status, 1)
            self.assertIn("missing ss58Address or secretSeed", err.getvalue())
        finally:
            Path(path).unlink()

    def test_derive_user_id(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            status = shell_helpers.derive_user_id(Namespace(fingerprint="example"))
        self.assertEqual(status, 0)
        self.assertEqual(buf.getvalue().strip(), "2935cc19-261a-5807-8ed0-2f99958c745c")

    @mock.patch("shell_helpers.urllib.request.urlopen")
    def test_login_with_fingerprint(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse(b'{"token":"jwt-token"}')
        token = shell_helpers.login_with_fingerprint("https://api.chutes.ai", "fp")
        self.assertEqual(token, "jwt-token")

    @mock.patch("shell_helpers.urllib.request.urlopen")
    def test_login_with_fingerprint_http_error(self, mock_urlopen):
        error = HTTPError("https://api.chutes.ai/users/login", 403, "Forbidden", {}, io.BytesIO(b"nope"))
        mock_urlopen.side_effect = error
        with self.assertRaises(SystemExit) as exc:
            shell_helpers.login_with_fingerprint("https://api.chutes.ai", "fp")
        self.assertIn("fingerprint login failed (HTTP 403)", str(exc.exception))

    @mock.patch("shell_helpers.urllib.request.urlopen")
    def test_fetch_self_with_bearer(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse(b'{"user_id":"u1"}')
        data = shell_helpers.fetch_self_with_bearer("https://api.chutes.ai", "token")
        self.assertEqual(data["user_id"], "u1")

    @mock.patch("shell_helpers.fetch_self_with_bearer")
    @mock.patch("shell_helpers.login_with_fingerprint")
    def test_fetch_self_with_fingerprint(self, mock_login, mock_fetch):
        mock_login.return_value = "jwt-token"
        mock_fetch.return_value = {
            "username": "sirouk_dev",
            "user_id": "user-1",
            "payment_address": "addr",
            "hotkey": "hot",
            "coldkey": "cold",
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            status = shell_helpers.fetch_self_with_fingerprint(
                Namespace(base_url="https://api.chutes.ai/", fingerprint="fp")
            )
        self.assertEqual(status, 0)
        self.assertEqual(buf.getvalue(), "sirouk_dev\tuser-1\taddr\thot\tcold\n")
        mock_login.assert_called_once_with("https://api.chutes.ai", "fp")

    @mock.patch("shell_helpers.urllib.request.urlopen")
    def test_fetch_self_with_config(self, mock_urlopen):
        requests = []

        def fake_urlopen(request, timeout=0):
            requests.append((request, timeout))
            return FakeResponse(
                b'{"username":"sirouk_dev","user_id":"u1","payment_address":"addr","balance":12.5}'
            )

        mock_urlopen.side_effect = fake_urlopen

        fake_keypair = SimpleNamespace(sign=lambda message: bytes.fromhex("aabb"))
        fake_module = types.ModuleType("substrateinterface")
        fake_module.Keypair = SimpleNamespace(
            create_from_seed=lambda seed_hex: fake_keypair if seed_hex == "deadbeef" else None
        )

        with NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
            tmp.write(
                "[api]\nbase_url = https://api.chutes.ai\n"
                "[auth]\nhotkey_ss58address = 5abc\nhotkey_seed = 0xdeadbeef\nuser_id = u1\n"
            )
            path = tmp.name

        try:
            buf = io.StringIO()
            with mock.patch.dict(sys.modules, {"substrateinterface": fake_module}):
                with redirect_stdout(buf):
                    status = shell_helpers.fetch_self_with_config(Namespace(config_path=path))
            self.assertEqual(status, 0)
            self.assertEqual(buf.getvalue(), "sirouk_dev\tu1\taddr\t12.5\n")
            self.assertEqual(len(requests), 1)
            request, timeout = requests[0]
            self.assertEqual(timeout, 15)
            self.assertTrue(request.full_url.endswith("/users/me"))
            self.assertEqual(request.headers["X-chutes-hotkey"], "5abc")
            self.assertEqual(request.headers["X-chutes-signature"], "aabb")
            self.assertEqual(request.headers["X-chutes-userid"], "u1")
        finally:
            Path(path).unlink()

    def test_parse_account_response(self):
        payload = {"profile": {"username": "sirouk_dev", "user_id": "u1", "paymentAddress": "addr"}}
        with NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
            json.dump(payload, tmp)
            path = tmp.name

        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                status = shell_helpers.parse_account_response(Namespace(path=path))
            self.assertEqual(status, 0)
            self.assertEqual(buf.getvalue(), "sirouk_dev\tu1\taddr\t\n")
        finally:
            Path(path).unlink()

    def test_get_image_name_prefers_constants(self):
        with NamedTemporaryFile("w", encoding="utf-8", suffix=".py", delete=False) as tmp:
            tmp.write('CHUTE_NAME = "demo"\nCHUTE_TAG = "v1"\n')
            path = tmp.name

        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                status = shell_helpers.get_image_name(Namespace(path=path))
            self.assertEqual(status, 0)
            self.assertEqual(buf.getvalue(), "demo:v1\n")
        finally:
            Path(path).unlink()

    def test_get_image_name_falls_back_to_image_constructor(self):
        with NamedTemporaryFile("w", encoding="utf-8", suffix=".py", delete=False) as tmp:
            tmp.write('image = Image(name="demo", tag="v2")\n')
            path = tmp.name

        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                status = shell_helpers.get_image_name(Namespace(path=path))
            self.assertEqual(status, 0)
            self.assertEqual(buf.getvalue(), "demo:v2\n")
        finally:
            Path(path).unlink()

    def test_openapi_paths(self):
        buf = io.StringIO()
        stdin = io.StringIO('{"paths": {"/alpha": {}, "/beta": {}}}')
        with mock.patch("sys.stdin", stdin):
            with redirect_stdout(buf):
                status = shell_helpers.openapi_paths(Namespace())
        self.assertEqual(status, 0)
        self.assertEqual(buf.getvalue(), "/alpha\n/beta\n")

    def test_parse_instance_ids(self):
        payload = {
            "instances": [
                {"instance_id": "cold", "active": False, "verified": True, "last_verified_at": "2026-01-01"},
                {"instance_id": "best", "active": True, "verified": True, "last_verified_at": "2026-03-01"},
                {"instance_id": "mid", "active": True, "verified": False, "last_verified_at": "2026-02-01"},
            ]
        }
        with NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
            tmp.write(f"noise before\n{json.dumps(payload)}\nnoise after")
            path = tmp.name

        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                status = shell_helpers.parse_instance_ids(Namespace(path=path))
            self.assertEqual(status, 0)
            self.assertEqual(buf.getvalue(), "best\nmid\ncold\n")
        finally:
            Path(path).unlink()

    def test_fetch_all_items(self):
        class FakeHTTPResponse:
            def __init__(self, payload):
                self.status = 200
                self._payload = payload

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def text(self):
                return json.dumps(self._payload)

            async def json(self):
                return self._payload

        class FakeClientSession:
            calls = []

            def __init__(self, base_url):
                self.base_url = base_url

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def get(self, path, headers=None, params=None):
                FakeClientSession.calls.append((path, headers, dict(params or {})))
                page = int((params or {}).get("page", 0))
                payload = (
                    {"items": [{"chute_id": "1"}], "total": 2}
                    if page == 0
                    else {"items": [{"chute_id": "2"}], "total": 2}
                )
                return FakeHTTPResponse(payload)

        fake_aiohttp = types.ModuleType("aiohttp")
        fake_aiohttp.ClientSession = FakeClientSession

        fake_chutes_config = types.ModuleType("chutes.config")
        fake_chutes_config.get_config = lambda: SimpleNamespace(
            generic=SimpleNamespace(api_base_url="https://api.chutes.ai")
        )

        fake_chutes_auth = types.ModuleType("chutes.util.auth")
        fake_chutes_auth.sign_request = lambda purpose: ({"Authorization": f"sig-{purpose}"}, None)

        with mock.patch.dict(
            sys.modules,
            {
                "aiohttp": fake_aiohttp,
                "chutes.config": fake_chutes_config,
                "chutes.util.auth": fake_chutes_auth,
            },
        ):
            items = asyncio.run(shell_helpers.fetch_all_items("chutes", True))

        self.assertEqual(items, [{"chute_id": "1"}, {"chute_id": "2"}])
        self.assertEqual(FakeClientSession.calls[0][2]["include_public"], "true")
        self.assertEqual(FakeClientSession.calls[1][2]["page"], "1")

    @mock.patch("shell_helpers.fetch_all_items")
    def test_list_api_tsv_for_chutes(self, mock_fetch):
        mock_fetch.return_value = [
            {"chute_id": "c1", "name": "demo", "hot": True, "slug": "demo-slug"},
        ]
        buf = io.StringIO()
        with redirect_stdout(buf):
            status = shell_helpers.list_api_tsv(Namespace(object_type="chutes", include_public="true"))
        self.assertEqual(status, 0)
        self.assertEqual(buf.getvalue(), "c1\tdemo\thot\tdemo-slug\n")

    @mock.patch("shell_helpers.fetch_all_items")
    def test_list_api_tsv_for_images(self, mock_fetch):
        mock_fetch.return_value = [
            {"image_id": "i1", "name": "demo", "tag": "v1", "status": "built"},
        ]
        buf = io.StringIO()
        with redirect_stdout(buf):
            status = shell_helpers.list_api_tsv(Namespace(object_type="images", include_public="false"))
        self.assertEqual(status, 0)
        self.assertEqual(buf.getvalue(), "i1\tdemo\tv1\tbuilt\n")

    def test_invoke_tool_main_restores_argv(self):
        original_argv = list(sys.argv)
        fake_module = SimpleNamespace(main=lambda: 7)
        with mock.patch("shell_helpers.importlib.import_module", return_value=fake_module):
            status = shell_helpers.invoke_tool_main("discover_routes", ["--flag", "value"])
        self.assertEqual(status, 7)
        self.assertEqual(sys.argv, original_argv)

    @mock.patch("shell_helpers.invoke_tool_main")
    def test_discover_routes_entry(self, mock_invoke):
        mock_invoke.return_value = 0
        status = shell_helpers.discover_routes_entry(Namespace(tool_args=["--flag"]))
        self.assertEqual(status, 0)
        mock_invoke.assert_called_once_with("discover_routes", ["--flag"])

    @mock.patch("shell_helpers.invoke_tool_main")
    def test_create_chute_from_image_entry(self, mock_invoke):
        mock_invoke.return_value = 0
        status = shell_helpers.create_chute_from_image_entry(Namespace(tool_args=["image:tag"]))
        self.assertEqual(status, 0)
        mock_invoke.assert_called_once_with("create_chute_from_image", ["image:tag"])

    def test_build_parser(self):
        parser = shell_helpers.build_parser()
        args = parser.parse_args(["derive-user-id", "example"])
        self.assertEqual(args.command, "derive-user-id")
        self.assertIs(args.func, shell_helpers.derive_user_id)

    def test_main(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            status = shell_helpers.main(["derive-user-id", "example"])
        self.assertEqual(status, 0)
        self.assertEqual(buf.getvalue().strip(), "2935cc19-261a-5807-8ed0-2f99958c745c")


if __name__ == "__main__":
    unittest.main()
