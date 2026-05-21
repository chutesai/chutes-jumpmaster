import argparse
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import recover_image_build  # noqa: E402


class RecoverImageBuildTests(unittest.TestCase):
    def sample_image(self):
        return {
            "image_id": "img-1",
            "name": "sglang",
            "tag": "nightly-2026051700",
            "readme": "SGLang inference",
            "status": "built and pushed",
            "created_at": "2026-05-17T08:40:20Z",
            "user": {"username": "chutes", "user_id": "user-1"},
        }

    def test_parse_image_ref_latest_name(self):
        ref = recover_image_build.parse_image_ref("sglang")
        self.assertIsNone(ref.username)
        self.assertEqual(ref.name, "sglang")
        self.assertIsNone(ref.tag)

    def test_parse_image_ref_full_ref(self):
        ref = recover_image_build.parse_image_ref("chutes/sglang:nightly-2026051700")
        self.assertEqual(ref.username, "chutes")
        self.assertEqual(ref.name, "sglang")
        self.assertEqual(ref.tag, "nightly-2026051700")

    def test_select_image_prefers_latest_nightly(self):
        ref = recover_image_build.parse_image_ref("sglang")
        selected = recover_image_build.select_image(
            [
                {
                    **self.sample_image(),
                    "image_id": "old",
                    "tag": "nightly-2026050600",
                    "created_at": "2026-05-06T00:00:00Z",
                },
                {
                    **self.sample_image(),
                    "image_id": "new",
                    "tag": "nightly-2026051700",
                    "created_at": "2026-05-17T00:00:00Z",
                },
                {
                    **self.sample_image(),
                    "image_id": "non-nightly",
                    "tag": "custom",
                    "created_at": "2026-05-18T00:00:00Z",
                },
            ],
            ref,
        )
        self.assertEqual(selected["image_id"], "new")

    def test_extract_original_dockerfile_steps_stops_after_first_stage(self):
        log_text = "\n".join(
            [
                "noise",
                "STEP 1/3: FROM base",
                "STEP 2/3: ENV A=1",
                "STEP 3/3: RUN echo ok",
                "STEP 1/2: FROM injected",
                "STEP 2/2: RUN echo later",
            ]
        )
        self.assertEqual(
            recover_image_build.extract_original_dockerfile_steps(log_text),
            ["FROM base", "ENV A=1", "RUN echo ok"],
        )

    def test_render_image_builder(self):
        steps = [
            "FROM parachutes/python:3.12-cu13",
            "ENV SGL_KERNEL_VERSION=0.4.2.post2",
            "USER root",
            "RUN echo one && echo two",
            "USER chutes",
        ]
        output = recover_image_build.render_image_builder(self.sample_image(), steps)
        self.assertIn('name="sglang"', output)
        self.assertIn('.from_base("parachutes/python:3.12-cu13")', output)
        self.assertIn('.with_env("SGL_KERNEL_VERSION", "0.4.2.post2")', output)
        self.assertIn('"echo one",', output)
        self.assertIn('"echo two",', output)

    def test_render_chutes_python_includes_sglang_builder(self):
        args = argparse.Namespace(
            engine="auto",
            model_name="MODEL",
            revision="REV",
            engine_args="--context-length 1",
            username=None,
            chute_readme="Recovered",
            concurrency=16,
            gpu_count=1,
            min_vram_gb_per_gpu=24,
        )
        output = recover_image_build.render_chutes_python(
            self.sample_image(),
            ["FROM base"],
            args,
        )
        self.assertIn("from chutes.chute.template.sglang import build_sglang_chute", output)
        self.assertIn("chute = build_sglang_chute(", output)
        self.assertIn('MODEL_REVISION = os.getenv("CHUTES_MODEL_REVISION", "REV")', output)


if __name__ == "__main__":
    unittest.main()
