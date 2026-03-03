# Chutes Jumpmaster

Jumpmaster is a control-plane workspace for operating in the Chutes ecosystem.

Primary jobs:

- **Track upstream changes across core Chutes repos** - Keep submodules current and inspect diffs quickly
- **Build, run, deploy, and operate chutes with `deploy.sh`** - Centralized setup and lifecycle commands
- **Wrap upstream Docker images into chutes** - Auto-discover routes and register passthrough cords

Everything here is vendor-neutral—you can reuse the exact workflow for any service that needs to run on Chutes.

---

## Quick Start

```bash
# 1. Setup environment (creates .venv, installs deps, registers with Chutes)
./setup.sh

# 2. Activate and use deploy.sh for everything else
source .venv/bin/activate
./deploy.sh
```

---

## Core Sub-Repositories

This repository is a workspace for several core Chutes repos. These are tracked as git submodules and updated via `update_all_repos.sh`.

| Repository | Purpose | URL |
|-----------|---------|-----|
| `chutes/` | Python SDK for building images and chutes | [github.com/chutesai/chutes](https://github.com/chutesai/chutes) |
| `chutes-api/` | API server and validation logic | [github.com/chutesai/chutes-api](https://github.com/chutesai/chutes-api) |
| `chutes-web/` | Web frontend and dashboard | [github.com/chutesai/chutes-web](https://github.com/chutesai/chutes-web) |
| `chutes-miner/` | GPU miner code for running chutes | [github.com/chutesai/chutes-miner](https://github.com/chutesai/chutes-miner) |
| `chutes-e2ee-transport/` | End-to-end encrypted communication | [github.com/chutesai/chutes-e2ee-transport](https://github.com/chutesai/chutes-e2ee-transport) |
| `sek8s/` | Kubernetes integration and infrastructure | [github.com/chutesai/sek8s](https://github.com/chutesai/sek8s) |

### Keeping Repos in Sync

Run `update_all_repos.sh` to fetch and pull latest changes from all sub-repositories:

```bash
./update_all_repos.sh
```

This ensures your local workspace stays current with upstream developments.

---

## Daily Ops Loop

Use this loop to stay current and operational:

1. Sync all tracked upstream repos:
   ```bash
   ./update_all_repos.sh
   ```
2. Inspect what changed in submodules (`chutes/`, `chutes-api/`, `chutes-web/`, etc.) using your IDE or git diff tools.
3. Use `deploy.sh` to build, deploy, check status, stream logs, and warm chutes as needed.

---

## Architecture & Methodology

**Strategy:** Keep the vendor image intact and inject the Chutes runtime so the exact same binaries continue to run. Only use the metadata-rebuild path (replaying steps onto the `parachutes/python` base) when you explicitly want a fresh foundation—for example, to audit each layer or to publish a clean-room replica. Even if the upstream container uses Conda or custom CUDA stacks, we still prefer to wrap *that* image so it behaves identically once deployed.

### Tooling

| Tool | Purpose |
|------|---------|
| **Auto-Discovery (`deploy.sh --discover` / `tools/discover_routes.py`)** | Boots the upstream image locally, probes common OpenAPI endpoints, and writes `deploy_*.routes.json` so passthrough cords can be generated automatically. |
| **Wrapper SDK (`tools/chute_wrappers.py`)** | Injects system Python, the `chutes` user, OpenCL libs, and helper scripts into any base image. Handles route registration, startup waits, and health checks. |
| **Image Generator (`tools/create_chute_from_image.py`)** | Replays an existing Docker image's metadata on top of the Chutes base (`deploy_*_auto.py`), giving you a reproducible python-first version that still launches the original entrypoint. |
| **Vanilla examples (`vanilla_examples/`)** | Pure-Python chutes that instantiate `Chute`/`ChuteImage` directly—useful when you want the traditional `torch.cuda` debugging loop without the wrapper layer. |

---

## Upstream Change Inspection

The Chutes Jumpmaster setup is designed for efficient local development with modern IDEs equipped with LLM support (VS Code, Cursor, etc.):

### Discovering Changes in Core Repos

When changes come down the pipeline from upstream chutes repos, use these tools to understand what's new:

1. **`update_all_repos.sh`** - Pull latest changes from all sub-repositories
2. **Explore source code** - IDE-integrated navigation through Python/TypeScript/Go code

### Running OpenAPI Discovery

The discovery tool spins up a container, probes for OpenAPI specs, and generates route definitions:

```bash
# Automatically discover routes from a chute definition
./deploy.sh --discover deploy_my_service

# Or use the tool directly
python tools/discover_routes.py --chute-file deploy_my_service.py \
    --startup-delay 300 --probe-timeout 60 --docker-gpus all
```

This generates a `deploy_my_service.routes.json` file containing all discovered endpoints, which can then be used when building the chute.

### Creating Chutes from Existing Images

The `create_chute_from_image.py` tool helps you jumpstart chute development:

```bash
# Generate a chute definition from any Docker image
python tools/create_chute_from_image.py elbios/xtts-whisper:latest \
    --name xtts-whisper --gpus all --interactive
```

This produces a `deploy_xtts_whisper_auto.py` file that you can further customize.

---

## Typical Paths

1. **Auto-Discovery + Wrapper (original image with Chutes injected).** Run discovery to capture the service's OpenAPI, then call `build_wrapper_image()` so the upstream container keeps its own stack while inheriting the Chutes runtime. This is the fastest way to deploy vendor images unchanged.
2. **Image Generator (Chutes base image with the original entrypoint).** Use `tools/create_chute_from_image.py` to rebuild the Dockerfile onto `parachutes/python`, but keep the upstream entrypoint so its services still launch exactly as before—ideal for auditing layers or when you need a reproducible base.
3. **Vanilla Rebuild (Chutes base + rewritten services).** Start from the Chutes base image and reimplement services directly in Python (see `vanilla_examples/`). This gives you explicit `torch` usage, cords, and lifecycle hooks for the tightest debugging loop.

---

## Platform Context

Chutes behaves like a less restrictive, GPU-aware AWS Lambda. Containers can stay warm, keep local caches, and expose arbitrary HTTP routes. The router expects JSON payloads for quota tracking—e.g., when adapting a legacy XTTS/Whisper workflow you'd wrap audio bytes in JSON (base64) or add a proxy to do it automatically.

- **Future Direction:** Images can return JSON-wrapped audio responses as well, opening the door to multi-part emulation in the SDK later.

---

## Workflow

### 1. Setup (`./setup.sh`)

Interactive wizard that:
- Installs `uv` and creates `.venv` (Python 3.11)
- Installs the `chutes` CLI and supporting deps
- Helps you register a new Chutes account *or* link an existing website account to a Bittensor wallet in `~/.chutes/config.ini`

### 2. Deploy (`./deploy.sh`)

Capabilities (press Enter for defaults when prompted):

| Category | Option | Capability |
|----------|--------|------------|
| Account | **1** | Show username + payment address from config |
| Account | **2** | Link existing Chutes account to local Bittensor wallet and write `~/.chutes/config.ini` |
| Build/Discovery | **3** | Build from local `deploy_*.py` (wraps `CHUTE_BASE_IMAGE`) |
| Build/Discovery | **4** | Create a chute definition from an existing Docker image |
| Local Run | **5** | Run wrapped service in Docker (GPU sanity check) |
| Local Run | **6** | Run chute in host dev mode |
| Cloud Ops | **7** | Deploy chute (upload + schedule on Chutes.ai) |
| Cloud Ops | **8** | Chute status (health + instances) |
| Cloud Ops | **9** | Warmup + stream logs via SDK watcher (`chutes warmup <chute> --stream-logs`) |
| Cloud Ops | **10** | Warmup once (manual spin-up) |
| Cloud Ops | **11** | Keep warm loop (repeated warmup) |
| Cleanup | **12** | List & delete chutes (interactive safety checks) |
| Cleanup | **13** | List & delete images |

`--logs` and option **9** intentionally trigger warmup and auto-watch for instances before streaming logs. If your installed `chutes` CLI does not support `--stream-logs` (or watcher mode fails), Jumpmaster falls back to legacy instance polling + direct `/instances/{id}/logs` streaming.

**CLI Examples**
```bash
./deploy.sh --discover deploy_xtts_whisper
./deploy.sh --build deploy_xtts_whisper --local
./deploy.sh --deploy deploy_xtts_whisper --accept-fee
./deploy.sh --logs xtts-whisper
```

### 3. Route Discovery

```bash
./deploy.sh --discover deploy_myservice
```
1. Starts the base image in Docker with GPU access
2. Waits for startup
3. Probes `/openapi.json`, `/docs.json`, `/docs/openapi.json`, `/swagger.json`
4. Writes `deploy_myservice.routes.json`

If no manifest exists when you choose "Build chute," the script now defaults the discovery prompt to **Yes** to avoid deploying an image with no cords.

---

## Deploy Script Structure

```python
from tools.chute_wrappers import build_wrapper_image, load_route_manifest, register_passthrough_routes

CHUTE_NAME = "xtts-whisper"
CHUTE_TAG = "tts-stt-v0.1.16"
CHUTE_BASE_IMAGE = "elbios/xtts-whisper:latest"
SERVICE_PORTS = [8020, 8080]
CHUTE_STATIC_ROUTES = [{"port": 8080, "method": "POST", "path": "/inference"}]

image = build_wrapper_image(USERNAME, CHUTE_NAME, CHUTE_TAG, CHUTE_BASE_IMAGE, env=CHUTE_ENV)

chute = Chute(
    username=USERNAME,
    name=CHUTE_NAME,
    image=image,
    node_selector=NodeSelector(gpu_count=1, min_vram_gb_per_gpu=16),
)

register_passthrough_routes(
    chute,
    load_route_manifest(static_routes=CHUTE_STATIC_ROUTES),
    SERVICE_PORTS[0],
)
```

---

## Vanilla Examples (traditional chutes)

Most guidance here focuses on wrapping upstream Docker images, but some services are still easier to express as straight Python modules. Those canonical "vanilla" samples live in `vanilla_examples/`:

- `vanilla_examples/deploy_example_imggen.py` – Fully managed FastAPI chute that imports `ChuteImage`, keeps models on `torch.cuda`, and exposes inference cords directly.
- `vanilla_examples/deploy_example_sglang.py` – Minimal `build_sglang_chute` example that matches the way first-party SGLang chutes are deployed.

**Why bother with the vanilla path**
- It is the original Chutes development flow: `import chutes`, allocate GPUs with `NodeSelector`, and call `torch.cuda.*` yourself, so stepping through failures is just Python debugging.
- You can run these modules locally (`python vanilla_examples/deploy_example_imggen.py`) without rebuilding a wrapper image, which shortens the iteration loop.
- Perfect when you are building the container from scratch and want explicit control over installs, caching, and warmup scripts.

---

## Troubleshooting Cheat Sheet

| Issue | Fix |
|-------|-----|
| Multipart calls return 400 | Convert to JSON + base64 payload, or add a proxy that does it |
| No routes discovered | Add `CHUTE_STATIC_ROUTES` or rerun discovery with longer delays |
| Build segfaults | Ensure `build_wrapper_image` injects system Python; Conda-only bases fail `chutes-inspecto` |
| Remote build rejected | Requires ≥ $50 balance; use `--local` during development |
| Chute never warms | Use menu option 11 (keep warm loop) and watch instance logs |

---

## Repository Layout

```
chutes-jumpmaster/
├── setup.sh                     # Environment setup (venv, deps, registration)
├── deploy.sh                    # Main CLI (interactive + flags)
├── update_all_repos.sh          # Update all chutes sub-repositories
├── requirements.txt             # Python deps
├── deploy_example_docker.py     # Wrapper template for arbitrary images
├── deploy_example_xtts_whisper.py  # Wrapper example for XTTS + Whisper
├── vanilla_examples/            # Traditional pure-Python chute modules
│   ├── deploy_example_imggen.py # Torch-based FastAPI image generator
│   └── deploy_example_sglang.py # SGLang chute template
├── tools/
│   ├── chute_wrappers.py        # Image builder, route helpers
│   ├── discover_routes.py       # OpenAPI probing and route discovery
│   ├── create_chute_from_image.py  # Generate chute from Docker image
│   └── instance_logs.py         # Watcher-first log utility (legacy fallback included)
├── chutes/                      # Chutes Python SDK (git submodule)
├── chutes-api/                  # API server (git submodule)
├── chutes-web/                  # Web frontend (git submodule)
├── chutes-miner/                # Miner code (git submodule)
├── chutes-e2ee-transport/       # E2EE transport (git submodule)
├── sek8s/                       # Kubernetes integration (git submodule)
├── DOCKER_TROUBLESHOOTING.md    # Notes on Python/inspecto issues
└── README.md
```

---

## Links
- [Chutes Documentation](https://chutes.ai/docs)
- [SDK Image Reference](https://chutes.ai/docs/sdk-reference/image)
- [Registration Token](https://rtok.chutes.ai/users/registration_token)

Let us know if you need the docs expanded to cover additional workflows (gRPC, websocket passthrough, etc.).
