#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import importlib
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
import uuid
from configparser import ConfigParser
from pathlib import Path
from typing import Any


def emit_tsv(fields: list[Any]) -> None:
    sys.stdout.write(
        "\t".join("" if value is None else str(value).replace("\t", " ") for value in fields) + "\n"
    )


def find_first(obj: Any, keys: list[str]) -> str:
    if isinstance(obj, dict):
        for key in keys:
            value = obj.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        for value in obj.values():
            result = find_first(value, keys)
            if result:
                return result
    elif isinstance(obj, list):
        for value in obj:
            result = find_first(value, keys)
            if result:
                return result
    return ""


def get_signing_message(hotkey: str, nonce: str, purpose: str) -> str:
    return f"{hotkey}:{nonce}:{purpose}"


def parse_hotkey_file(args: argparse.Namespace) -> int:
    with open(args.path, "r", encoding="utf-8") as infile:
        data = json.load(infile)

    ss58 = find_first(data, ["ss58Address", "ss58_address", "ss58"])
    seed = find_first(data, ["secretSeed", "secret_seed", "seed"])
    if seed.startswith("0x"):
        seed = seed[2:]

    if not ss58 or not seed:
        sys.stderr.write("missing ss58Address or secretSeed\n")
        return 1

    emit_tsv([ss58, seed])
    return 0


def derive_user_id(args: argparse.Namespace) -> int:
    fingerprint_hash = hashlib.blake2b(args.fingerprint.encode()).hexdigest()
    sys.stdout.write(f"{uuid.uuid5(uuid.NAMESPACE_OID, fingerprint_hash)}\n")
    return 0


def login_with_fingerprint(base_url: str, fingerprint: str) -> str:
    request = urllib.request.Request(
        f"{base_url}/users/login",
        data=json.dumps({"fingerprint": fingerprint}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            token = json.load(response).get("token")
    except urllib.error.HTTPError as exc:
        body = exc.read(300).decode("utf-8", "replace")
        raise SystemExit(f"fingerprint login failed (HTTP {exc.code}): {body}")
    except Exception as exc:  # pragma: no cover - network dependent
        raise SystemExit(f"fingerprint login failed: {exc}")

    if not token:
        raise SystemExit("fingerprint login failed: missing token in response")
    return token


def fetch_self_with_bearer(base_url: str, token: str) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{base_url}/users/me",
        headers={"Authorization": f"Bearer {token}"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        body = exc.read(300).decode("utf-8", "replace")
        raise SystemExit(f"self lookup failed (HTTP {exc.code}): {body}")
    except Exception as exc:  # pragma: no cover - network dependent
        raise SystemExit(f"self lookup failed: {exc}")


def fetch_self_with_fingerprint(args: argparse.Namespace) -> int:
    base_url = args.base_url.rstrip("/")
    token = login_with_fingerprint(base_url, args.fingerprint)
    data = fetch_self_with_bearer(base_url, token)
    emit_tsv(
        [
            data.get("username", ""),
            data.get("user_id", ""),
            data.get("payment_address", ""),
            data.get("hotkey", ""),
            data.get("coldkey", ""),
        ]
    )
    return 0


def fetch_self_with_config(args: argparse.Namespace) -> int:
    try:
        from substrateinterface import Keypair
    except ModuleNotFoundError as exc:  # pragma: no cover - env dependent
        raise SystemExit(str(exc))

    config = ConfigParser()
    config.read(args.config_path)

    base_url = config.get("api", "base_url", fallback="https://api.chutes.ai").rstrip("/")
    hotkey = config.get("auth", "hotkey_ss58address", fallback="").strip()
    seed = config.get("auth", "hotkey_seed", fallback="").strip().removeprefix("0x")
    user_id = config.get("auth", "user_id", fallback="").strip()

    if not hotkey or not seed:
        raise SystemExit(1)

    nonce = str(int(time.time()))
    signature = Keypair.create_from_seed(seed_hex=seed).sign(
        get_signing_message(hotkey, nonce, "me").encode()
    ).hex()
    headers = {
        "X-Chutes-Hotkey": hotkey,
        "X-Chutes-Nonce": nonce,
        "X-Chutes-Signature": signature,
    }
    if user_id:
        headers["X-Chutes-UserID"] = user_id

    request = urllib.request.Request(f"{base_url}/users/me", headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            data = json.load(response)
    except urllib.error.HTTPError as exc:
        body = exc.read(300).decode("utf-8", "replace")
        raise SystemExit(f"HTTP {exc.code}: {body}")
    except Exception as exc:  # pragma: no cover - network dependent
        raise SystemExit(str(exc))

    emit_tsv(
        [
            data.get("username", ""),
            data.get("user_id", ""),
            data.get("payment_address", ""),
            "" if data.get("balance") is None else str(data.get("balance")),
        ]
    )
    return 0


def parse_account_response(args: argparse.Namespace) -> int:
    with open(args.path, "r", encoding="utf-8") as infile:
        data = json.load(infile)

    emit_tsv(
        [
            find_first(data, ["username", "user_name", "name"]),
            find_first(data, ["user_id", "id", "uid"]),
            find_first(data, ["payment_address", "paymentAddress", "address"]),
            find_first(
                data,
                [
                    "developer_payment_address",
                    "developerPaymentAddress",
                    "developer_address",
                    "developerAddress",
                ],
            ),
        ]
    )
    return 0


def get_image_name(args: argparse.Namespace) -> int:
    content = Path(args.path).read_text(encoding="utf-8")

    name_match = re.search(r'^CHUTE_NAME\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE)
    tag_match = re.search(r'^CHUTE_TAG\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE)
    if name_match and tag_match:
        sys.stdout.write(f"{name_match.group(1)}:{tag_match.group(1)}\n")
        return 0

    name_match = re.search(r'Image\s*\([^)]*name\s*=\s*["\']([^"\']+)["\']', content, re.DOTALL)
    tag_match = re.search(r'Image\s*\([^)]*tag\s*=\s*["\']([^"\']+)["\']', content, re.DOTALL)
    if name_match and tag_match:
        sys.stdout.write(f"{name_match.group(1)}:{tag_match.group(1)}\n")
    return 0


def openapi_paths(_: argparse.Namespace) -> int:
    data = json.load(sys.stdin)
    paths = data.get("paths", {})
    if paths:
        sys.stdout.write("\n".join(paths.keys()) + "\n")
    return 0


def parse_instance_ids(args: argparse.Namespace) -> int:
    text = Path(args.path).read_text(encoding="utf-8", errors="replace")
    match = re.search(r"\{[\s\S]*\}", text)
    if not match:
        return 0

    data = json.loads(match.group())
    instances = data.get("instances") or []
    if not instances:
        return 0

    def sort_key(instance: dict[str, Any]) -> tuple[Any, Any, Any]:
        return (
            not instance.get("active", False),
            not instance.get("verified", False),
            instance.get("last_verified_at") or "",
        )

    instances = sorted(instances, key=sort_key)
    sys.stdout.write("\n".join(instance["instance_id"] for instance in instances) + "\n")
    return 0


async def fetch_all_items(object_type: str, include_public: bool) -> list[dict[str, Any]]:
    import aiohttp
    from chutes.config import get_config
    from chutes.util.auth import sign_request

    config = get_config()
    headers, _ = sign_request(purpose=object_type)
    items: list[dict[str, Any]] = []
    page = 0
    limit = 200
    base_params: dict[str, str] = {}
    if include_public:
        base_params["include_public"] = "true"

    async with aiohttp.ClientSession(base_url=config.generic.api_base_url) as session:
        while True:
            params = dict(base_params)
            params["limit"] = str(limit)
            params["page"] = str(page)
            async with session.get(f"/{object_type}/", headers=headers, params=params) as response:
                if response.status != 200:
                    text = await response.text()
                    raise SystemExit(f"Failed to list {object_type}: {response.status} {text[:300]}")
                data = await response.json()

            batch = data.get("items") or []
            items.extend(batch)
            total = int(data.get("total") or 0)
            if not batch or len(items) >= total:
                break
            page += 1

    return items


def list_api_tsv(args: argparse.Namespace) -> int:
    include_public = str(args.include_public).strip().lower() in {"1", "true", "yes", "y", "on"}
    items = asyncio.run(fetch_all_items(args.object_type, include_public))
    for item in items:
        if args.object_type == "chutes":
            emit_tsv(
                [
                    item.get("chute_id"),
                    item.get("name"),
                    "hot" if item.get("hot") else "cold",
                    item.get("slug"),
                ]
            )
        elif args.object_type == "images":
            emit_tsv([item.get("image_id"), item.get("name"), item.get("tag"), item.get("status")])
    return 0


def invoke_tool_main(module_name: str, tool_args: list[str]) -> int:
    module = importlib.import_module(module_name)
    main_func = getattr(module, "main")
    old_argv = sys.argv
    sys.argv = [module_name, *tool_args]
    try:
        result = main_func()
    finally:
        sys.argv = old_argv
    return 0 if result is None else int(result)


def discover_routes_entry(args: argparse.Namespace) -> int:
    return invoke_tool_main("discover_routes", args.tool_args)


def create_chute_from_image_entry(args: argparse.Namespace) -> int:
    return invoke_tool_main("create_chute_from_image", args.tool_args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    cmd = subparsers.add_parser("parse-hotkey-file")
    cmd.add_argument("path")
    cmd.set_defaults(func=parse_hotkey_file)

    cmd = subparsers.add_parser("derive-user-id")
    cmd.add_argument("fingerprint")
    cmd.set_defaults(func=derive_user_id)

    cmd = subparsers.add_parser("fetch-self-with-fingerprint")
    cmd.add_argument("base_url")
    cmd.add_argument("fingerprint")
    cmd.set_defaults(func=fetch_self_with_fingerprint)

    cmd = subparsers.add_parser("fetch-self-with-config")
    cmd.add_argument("config_path")
    cmd.set_defaults(func=fetch_self_with_config)

    cmd = subparsers.add_parser("parse-account-response")
    cmd.add_argument("path")
    cmd.set_defaults(func=parse_account_response)

    cmd = subparsers.add_parser("get-image-name")
    cmd.add_argument("path")
    cmd.set_defaults(func=get_image_name)

    cmd = subparsers.add_parser("openapi-paths")
    cmd.set_defaults(func=openapi_paths)

    cmd = subparsers.add_parser("parse-instance-ids")
    cmd.add_argument("path")
    cmd.set_defaults(func=parse_instance_ids)

    cmd = subparsers.add_parser("list-api-tsv")
    cmd.add_argument("object_type")
    cmd.add_argument("include_public")
    cmd.set_defaults(func=list_api_tsv)

    cmd = subparsers.add_parser("discover-routes")
    cmd.add_argument("tool_args", nargs=argparse.REMAINDER)
    cmd.set_defaults(func=discover_routes_entry)

    cmd = subparsers.add_parser("create-chute-from-image")
    cmd.add_argument("tool_args", nargs=argparse.REMAINDER)
    cmd.set_defaults(func=create_chute_from_image_entry)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
