#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


IMAGE_STEP_RE = re.compile(r"^STEP\s+(?P<step>\d+)/(?P<total>\d+):\s+(?P<instruction>.*)$")
TOKEN_RE = re.compile(r'''(?:[^\s"']+|"[^"]*"|'[^']*')+''')
IMAGE_REF_RE = re.compile(
    r"^(?:(?P<username>[a-z0-9][a-z0-9_.-]*)/)?"
    r"(?P<name>[a-z0-9][a-z0-9_.\\/-]*)"
    r"(?::(?P<tag>[a-z0-9][a-z0-9_.\\/-]*))?$",
    re.I,
)
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)
RETRYABLE_STATUSES = {429, 500, 502, 503, 504}


def retry_exhausted_message(operation: str, status: int, text: str, max_retries: int) -> str:
    detail = text[:300].replace("\n", " ")
    if status == 429:
        return (
            f"{operation}: HTTP 429 after {max_retries} retries; Chutes API rate limited "
            f"the requests. Try again later or scan with lower --scan-concurrency/greater "
            f"--scan-delay. Response: {detail}"
        )
    return f"{operation}: HTTP {status}: {detail}"


@dataclass(frozen=True)
class ImageRef:
    raw: str
    image_id: str | None = None
    username: str | None = None
    name: str | None = None
    tag: str | None = None


def py_string(value: Any) -> str:
    return json.dumps("" if value is None else str(value))


def parse_image_ref(value: str) -> ImageRef:
    value = value.strip()
    if not value:
        raise ValueError("image reference cannot be empty")
    if UUID_RE.match(value):
        return ImageRef(raw=value, image_id=value)

    match = IMAGE_REF_RE.match(value)
    if not match:
        raise ValueError(
            "image reference must be an image ID, image name, name:tag, or username/name:tag"
        )
    return ImageRef(
        raw=value,
        username=match.group("username"),
        name=match.group("name"),
        tag=match.group("tag"),
    )


def image_username(image: dict[str, Any]) -> str:
    user = image.get("user") or {}
    return str(user.get("username") or "")


def image_user_id(image: dict[str, Any]) -> str:
    user = image.get("user") or {}
    return str(user.get("user_id") or image.get("user_id") or "")


def image_sort_key(image: dict[str, Any]) -> tuple[str, str]:
    return (str(image.get("created_at") or ""), str(image.get("image_id") or ""))


def select_image(images: list[dict[str, Any]], ref: ImageRef) -> dict[str, Any]:
    if ref.image_id:
        for image in images:
            if image.get("image_id") == ref.image_id:
                return image
        raise ValueError(f"image ID not found: {ref.image_id}")

    candidates = [
        image
        for image in images
        if image.get("name") == ref.name and (not ref.username or image_username(image) == ref.username)
    ]
    if ref.tag:
        candidates = [image for image in candidates if image.get("tag") == ref.tag]
    else:
        nightly = [
            image
            for image in candidates
            if str(image.get("tag") or "").startswith("nightly-")
            and str(image.get("status") or "").startswith("built and pushed")
        ]
        candidates = nightly or [
            image
            for image in candidates
            if str(image.get("status") or "").startswith("built and pushed")
        ]

    if not candidates:
        raise ValueError(f"no matching public image found for {ref.raw}")

    if ref.tag:
        built = [
            image
            for image in candidates
            if str(image.get("status") or "").startswith("built and pushed")
        ]
        candidates = built or candidates

    return sorted(candidates, key=image_sort_key, reverse=True)[0]


def extract_original_dockerfile_steps(log_text: str) -> list[str]:
    steps: list[str] = []
    expected_total: int | None = None
    expected_next = 1

    for line in log_text.splitlines():
        match = IMAGE_STEP_RE.match(line)
        if not match:
            continue

        step = int(match.group("step"))
        total = int(match.group("total"))
        instruction = match.group("instruction")

        if not steps:
            if step != 1:
                continue
            expected_total = total
        elif step != expected_next:
            # A second build started before we completed the first; reset if it
            # looks like the first step of a new build, otherwise keep scanning.
            if step == 1:
                steps = []
                expected_total = total
            else:
                continue

        steps.append(instruction)
        if expected_total is not None and step == expected_total:
            return steps
        expected_next = step + 1

    if not steps:
        if log_text.strip() in {"built and pushed", "pending build"} or log_text.strip().startswith(
            "error:"
        ):
            raise ValueError(
                "no retained Dockerfile build log is available for this image; "
                f"the API returned only status text: {log_text.strip()!r}"
            )
        raise ValueError("no Dockerfile build steps found in image log")
    raise ValueError("build log ended before the first Dockerfile stage completed")


def dockerfile_from_steps(steps: Iterable[str]) -> str:
    return "\n".join(steps).rstrip() + "\n"


def parse_env_instruction(instruction: str) -> list[tuple[str, str]]:
    body = instruction.removeprefix("ENV").strip()
    if not body:
        return []

    first, _, rest = body.partition(" ")
    if "=" not in first:
        return [(first, rest)]

    pairs: list[tuple[str, str]] = []
    tokens = TOKEN_RE.findall(body) or body.split()

    for token in tokens:
        key, sep, value = token.partition("=")
        if sep:
            pairs.append((key, quote_env_value_if_needed(value)))
    return pairs


def quote_env_value_if_needed(value: str) -> str:
    if not any(char.isspace() for char in value):
        return value
    if value.startswith(("'", '"')) and value.endswith(("'", '"')):
        return value
    return json.dumps(value)


def split_run_command(command: str) -> list[str]:
    parts = [part.strip() for part in command.split(" && ") if part.strip()]
    return parts or [command]


def render_run_command(command: str, indent: str = "    ") -> list[str]:
    parts = split_run_command(command)
    if len(parts) == 1 and len(command) <= 120:
        return [f"{indent}.run_command({py_string(command)})"]

    lines = [f'{indent}.run_command(" && ".join([']
    for part in parts:
        lines.append(f"{indent}    {py_string(part)},")
    lines.append(f"{indent}]))")
    return lines


def render_image_builder(image: dict[str, Any], steps: list[str]) -> str:
    username = image_username(image) or "chutes"
    name = image.get("name") or "recovered-image"
    tag = image.get("tag") or "recovered"
    readme = image.get("readme") or f"{name} recovered image"

    lines = [
        "image = (",
        "    Image(",
        f"        username={py_string(username)},",
        f"        name={py_string(name)},",
        f"        tag={py_string(tag)},",
        f"        readme={py_string(readme)},",
        "    )",
    ]
    notes: list[str] = []

    for instruction in steps:
        keyword, _, body = instruction.partition(" ")
        keyword = keyword.upper()
        body = body.strip()
        if keyword == "FROM":
            lines.append(f"    .from_base({py_string(body)})")
        elif keyword == "ENV":
            for key, value in parse_env_instruction(instruction):
                lines.append(f"    .with_env({py_string(key)}, {py_string(value)})")
        elif keyword == "USER":
            lines.append(f"    .set_user({py_string(body)})")
        elif keyword == "WORKDIR":
            lines.append(f"    .set_workdir({py_string(body)})")
        elif keyword == "RUN":
            lines.extend(render_run_command(body))
        elif keyword == "ENTRYPOINT":
            lines.append(f"    .with_entrypoint({py_string(body)})")
        elif keyword == "MAINTAINER":
            lines.append(f"    .with_maintainer({py_string(body)})")
        else:
            notes.append(f"# TODO: translate unsupported Dockerfile instruction: {instruction}")

    lines.append(")")
    if notes:
        return "\n".join(notes + ["", *lines]) + "\n"
    return "\n".join(lines) + "\n"


def detect_engine(image: dict[str, Any], override: str) -> str:
    if override != "auto":
        return override
    name = str(image.get("name") or "").lower()
    if "sglang" in name:
        return "sglang"
    if "vllm" in name:
        return "vllm"
    return "unknown"


def render_chutes_python(image: dict[str, Any], steps: list[str], args: argparse.Namespace) -> str:
    engine = detect_engine(image, args.engine)
    builder = {"sglang": "build_sglang_chute", "vllm": "build_vllm_chute"}.get(engine)

    imports = ["import os", "from chutes.chute import NodeSelector", "from chutes.image import Image"]
    if builder:
        imports.append(f"from chutes.chute.template.{engine} import {builder}")

    body = [
        *imports,
        "",
        f"MODEL_NAME = os.getenv(\"CHUTES_MODEL_NAME\", {py_string(args.model_name)})",
        f"MODEL_REVISION = os.getenv(\"CHUTES_MODEL_REVISION\", {py_string(args.revision)})",
        f"ENGINE_ARGS = os.getenv(\"CHUTES_ENGINE_ARGS\", {py_string(args.engine_args)})",
        "",
        render_image_builder(image, steps).rstrip(),
    ]

    if builder:
        body.extend(
            [
                "",
                f"chute = {builder}(",
                f"    username={py_string(args.username or image_username(image) or 'chutes')},",
                f"    readme={py_string(args.chute_readme)},",
                "    model_name=MODEL_NAME,",
                "    image=image,",
                f"    concurrency={args.concurrency},",
                "    revision=MODEL_REVISION,",
                "    node_selector=NodeSelector(",
                f"        gpu_count={args.gpu_count},",
                f"        min_vram_gb_per_gpu={args.min_vram_gb_per_gpu},",
                "    ),",
                "    engine_args=ENGINE_ARGS,",
                ")",
            ]
        )
    else:
        body.extend(
            [
                "",
                "# No standard chute builder was detected for this image name.",
                "# Use `image` above with the appropriate Chute or template builder.",
            ]
        )

    return "\n".join(body).rstrip() + "\n"


def retry_delay(headers: Any, attempt: int, base_delay: float) -> float:
    retry_after = None
    if headers:
        retry_after = headers.get("Retry-After")
    if retry_after:
        try:
            return min(float(retry_after), 60.0)
        except ValueError:
            pass
    return min(base_delay * (2**attempt), 30.0)


async def fetch_images(
    name: str | None = None,
    *,
    max_retries: int = 5,
    retry_base_delay: float = 1.0,
) -> list[dict[str, Any]]:
    import aiohttp
    from loguru import logger
    from chutes.config import get_config
    from chutes.util.auth import sign_request

    logger.remove()
    config = get_config()
    headers, _ = sign_request(purpose="images")
    items: list[dict[str, Any]] = []
    page = 0
    limit = 200

    async with aiohttp.ClientSession(base_url=config.generic.api_base_url) as session:
        while True:
            params = {"include_public": "true", "limit": str(limit), "page": str(page)}
            if name:
                params["name"] = name
            for attempt in range(max_retries + 1):
                async with session.get("/images/", headers=headers, params=params) as response:
                    text = await response.text()
                    if response.status == 200:
                        data = json.loads(text)
                        break
                    if response.status in RETRYABLE_STATUSES and attempt < max_retries:
                        await asyncio.sleep(retry_delay(response.headers, attempt, retry_base_delay))
                        continue
                    raise RuntimeError(
                        retry_exhausted_message(
                            "failed to list images", response.status, text, max_retries
                        )
                    )

            batch = data.get("items") or []
            items.extend(batch)
            total = int(data.get("total") or 0)
            if not batch or len(items) >= total:
                break
            page += 1

    return items


async def fetch_image_by_ref(
    image_ref: str,
    *,
    max_retries: int = 5,
    retry_base_delay: float = 1.0,
) -> dict[str, Any]:
    import aiohttp
    from loguru import logger
    from chutes.config import get_config
    from chutes.util.auth import sign_request

    logger.remove()
    config = get_config()
    headers, _ = sign_request(purpose="images")
    path_ref = image_ref.lstrip("/")
    async with aiohttp.ClientSession(base_url=config.generic.api_base_url) as session:
        for attempt in range(max_retries + 1):
            async with session.get(f"/images/{path_ref}", headers=headers) as response:
                text = await response.text()
                if response.status == 200:
                    return json.loads(text)
                if response.status == 404:
                    raise KeyError(image_ref)
                if response.status in RETRYABLE_STATUSES and attempt < max_retries:
                    await asyncio.sleep(retry_delay(response.headers, attempt, retry_base_delay))
                    continue
                raise RuntimeError(
                    retry_exhausted_message(
                        "failed to fetch image metadata", response.status, text, max_retries
                    )
                )

    raise RuntimeError("failed to fetch image metadata")


async def resolve_image(
    ref: ImageRef,
    *,
    max_retries: int,
    retry_base_delay: float,
) -> dict[str, Any]:
    if ref.image_id or (ref.username and ref.tag):
        try:
            return await fetch_image_by_ref(
                ref.raw,
                max_retries=max_retries,
                retry_base_delay=retry_base_delay,
            )
        except KeyError:
            pass

    images = await fetch_images(
        ref.name,
        max_retries=max_retries,
        retry_base_delay=retry_base_delay,
    )
    return select_image(images, ref)


async def fetch_image_logs(
    image_id: str,
    *,
    max_retries: int = 5,
    retry_base_delay: float = 1.0,
) -> str:
    import aiohttp
    from loguru import logger
    from chutes.config import get_config
    from chutes.util.auth import sign_request

    logger.remove()
    config = get_config()
    headers, _ = sign_request(purpose="images")
    async with aiohttp.ClientSession(base_url=config.generic.api_base_url) as session:
        for attempt in range(max_retries + 1):
            async with session.get(f"/images/{image_id}/logs", headers=headers) as response:
                text = await response.text()
                if response.status == 200:
                    return text
                if response.status in RETRYABLE_STATUSES and attempt < max_retries:
                    await asyncio.sleep(retry_delay(response.headers, attempt, retry_base_delay))
                    continue
                raise RuntimeError(
                    retry_exhausted_message(
                        "failed to fetch image logs", response.status, text, max_retries
                    )
                )

    raise RuntimeError("failed to fetch image logs")


def print_section(title: str, content: str) -> None:
    print(f"## {title}")
    print()
    print("```" + ("python" if title.lower().startswith("chutes") else "dockerfile"))
    print(content.rstrip())
    print("```")
    print()


def write_outputs(output_dir: Path, image: dict[str, Any], dockerfile: str, python_code: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    name = str(image.get("name") or "image")
    tag = str(image.get("tag") or "tag")
    stem = f"{name}-{tag}".replace("/", "-")
    docker_path = output_dir / f"{stem}.Dockerfile"
    python_path = output_dir / f"{stem}.py"
    docker_path.write_text(dockerfile, encoding="utf-8")
    python_path.write_text(python_code, encoding="utf-8")
    print(f"Wrote Dockerfile: {docker_path}")
    print(f"Wrote chutes build: {python_path}")
    print()


async def recover(args: argparse.Namespace) -> int:
    if not args.image:
        raise ValueError("image is required unless --scan is used")
    ref = parse_image_ref(args.image)
    image = await resolve_image(
        ref,
        max_retries=args.max_retries,
        retry_base_delay=args.retry_base_delay,
    )
    log_text = await fetch_image_logs(
        str(image["image_id"]),
        max_retries=args.max_retries,
        retry_base_delay=args.retry_base_delay,
    )
    steps = extract_original_dockerfile_steps(log_text)
    dockerfile = dockerfile_from_steps(steps)
    python_code = render_chutes_python(image, steps, args)

    print(
        f"# Recovered {image_username(image) or 'unknown'}/{image.get('name')}:{image.get('tag')}"
        f" ({image.get('image_id')})"
    )
    print(f"# Created: {image.get('created_at')}")
    print(f"# Status: {image.get('status')}")
    print()

    if args.output_dir:
        write_outputs(Path(args.output_dir), image, dockerfile, python_code)

    if args.format in {"all", "dockerfile"}:
        print_section("Dockerfile", dockerfile)
    if args.format in {"all", "python"}:
        print_section("Chutes Build", python_code)
    return 0


async def scan(args: argparse.Namespace) -> int:
    images = await fetch_images(
        args.name,
        max_retries=args.max_retries,
        retry_base_delay=args.retry_base_delay,
    )
    built = [
        image
        for image in images
        if str(image.get("status") or "").startswith("built and pushed")
        and (not args.owner or image_username(image) == args.owner)
    ]
    if args.limit:
        built = built[: args.limit]

    semaphore = asyncio.Semaphore(args.scan_concurrency)
    start = time.time()
    ok: list[tuple[str, int]] = []
    missing_logs: list[str] = []
    failed: list[tuple[str, str]] = []
    render_args = argparse.Namespace(
        engine=args.engine,
        model_name=args.model_name,
        revision=args.revision,
        engine_args=args.engine_args,
        username=args.username,
        chute_readme=args.chute_readme,
        concurrency=args.concurrency,
        gpu_count=args.gpu_count,
        min_vram_gb_per_gpu=args.min_vram_gb_per_gpu,
    )

    async def check(image: dict[str, Any]) -> None:
        ref = f"{image_username(image) or 'unknown'}/{image.get('name')}:{image.get('tag')}"
        async with semaphore:
            try:
                log_text = await fetch_image_logs(
                    str(image["image_id"]),
                    max_retries=args.max_retries,
                    retry_base_delay=args.retry_base_delay,
                )
                steps = extract_original_dockerfile_steps(log_text)
                dockerfile_from_steps(steps)
                render_chutes_python(image, steps, render_args)
                ok.append((ref, len(steps)))
            except ValueError as exc:
                if "no Dockerfile build steps" in str(exc) or "no retained Dockerfile" in str(exc):
                    missing_logs.append(ref)
                else:
                    failed.append((ref, str(exc)))
            except Exception as exc:
                failed.append((ref, str(exc)))
            if args.scan_delay > 0:
                await asyncio.sleep(args.scan_delay)

    await asyncio.gather(*(check(image) for image in built))

    elapsed = time.time() - start
    print(f"Scanned built images: {len(built)}")
    print(f"Recoverable: {len(ok)}")
    print(f"Missing retained build logs: {len(missing_logs)}")
    print(f"Failed: {len(failed)}")
    print(f"Elapsed seconds: {elapsed:.1f}")

    if missing_logs:
        print("\nMissing logs:")
        for ref in missing_logs[: args.show_failures]:
            print(f"  {ref}")
        if len(missing_logs) > args.show_failures:
            print(f"  ... {len(missing_logs) - args.show_failures} more")

    if failed:
        print("\nFailures:")
        for ref, reason in failed[: args.show_failures]:
            print(f"  {ref}: {reason[:300]}")
        if len(failed) > args.show_failures:
            print(f"  ... {len(failed) - args.show_failures} more")

    return 1 if failed else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Recover the original Dockerfile build stage for a public Chutes image and "
            "render it as a Chutes Image/template builder."
        )
    )
    parser.add_argument(
        "image",
        nargs="?",
        help="Image name for latest nightly, image ID, name:tag, or username/name:tag",
    )
    parser.add_argument("--scan", action="store_true", help="Scan recoverability instead of printing output")
    parser.add_argument("--owner", help="Only scan images owned by this username")
    parser.add_argument("--name", help="Only scan images whose API name filter matches this value")
    parser.add_argument("--limit", type=int, help="Maximum number of images to scan")
    parser.add_argument("--scan-concurrency", type=int, default=1)
    parser.add_argument("--scan-delay", type=float, default=0.5)
    parser.add_argument("--show-failures", type=int, default=20)
    parser.add_argument("--max-retries", type=int, default=8)
    parser.add_argument("--retry-base-delay", type=float, default=2.0)
    parser.add_argument("--engine", choices=["auto", "sglang", "vllm"], default="auto")
    parser.add_argument("--format", choices=["all", "dockerfile", "python"], default="all")
    parser.add_argument("--output-dir", help="Optional directory to write .Dockerfile and .py files")
    parser.add_argument("--username", help="Username to use in the generated chute builder")
    parser.add_argument("--model-name", default="REPLACE_WITH_MODEL_NAME")
    parser.add_argument("--revision", default="REPLACE_WITH_HF_COMMIT")
    parser.add_argument("--engine-args", default="--context-length 16384")
    parser.add_argument("--chute-readme", default="Recovered LLM chute")
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--gpu-count", type=int, default=1)
    parser.add_argument("--min-vram-gb-per-gpu", type=int, default=24)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.scan:
            return asyncio.run(scan(args))
        return asyncio.run(recover(args))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
