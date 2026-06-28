from __future__ import annotations

import argparse
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KERNEL_DIR = PROJECT_ROOT / "kaggle_kernel"
DEFAULT_KERNEL_ID = "muhammedtariq/ai-agent-security-attack-codex"
COMPETITION = "ai-agent-security-multi-step-tool-attacks"


def build_script(attack_source: str) -> str:
    return f'''from __future__ import annotations

import glob
import sys
from pathlib import Path


COMPETITION = "{COMPETITION}"
ATTACK_CODE = {attack_source!r}


def add_competition_data_to_path() -> None:
    for candidate in glob.glob("/kaggle/input/**/kaggle_evaluation", recursive=True):
        dataset_root = str(Path(candidate).parent)
        if dataset_root not in sys.path:
            sys.path.insert(0, dataset_root)
        print(f"Dataset root: {{dataset_root}}")
        return

    try:
        import kagglehub
    except Exception as exc:
        raise RuntimeError("Could not find mounted competition data and kagglehub is unavailable") from exc

    dataset_root = kagglehub.competition_download(COMPETITION)
    if dataset_root not in sys.path:
        sys.path.insert(0, dataset_root)
    print(f"Downloaded competition data: {{dataset_root}}")


add_competition_data_to_path()

attack_path = Path("/kaggle/working/attack.py")
attack_path.write_text(ATTACK_CODE, encoding="utf-8")
print(f"Wrote {{attack_path}}")

submission_path = Path("/kaggle/working/submission.csv")
submission_path.write_text(
    "Id,Score\\n"
    "gpt_oss_public,0.0\\n"
    "gpt_oss_private,0.0\\n"
    "gemma_public,0.0\\n"
    "gemma_private,0.0\\n",
    encoding="utf-8",
)
print(f"Wrote placeholder {{submission_path}}")

import kaggle_evaluation.jed_attack_134815.jed_attack_inference_server as inference_server

inference_server.JEDAttackInferenceServer().serve()
'''


def build_metadata(kernel_id: str) -> dict[str, object]:
    title = kernel_id.rsplit("/", 1)[-1].replace("-", " ").title()
    return {
        "id": kernel_id,
        "title": title,
        "code_file": "submission.py",
        "language": "python",
        "kernel_type": "script",
        "is_private": "true",
        "enable_gpu": "false",
        "enable_tpu": "false",
        "enable_internet": "false",
        "machine_shape": "",
        "dataset_sources": [],
        "competition_sources": [COMPETITION],
        "kernel_sources": [],
        "model_sources": [],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel-dir", type=Path, default=DEFAULT_KERNEL_DIR)
    parser.add_argument("--kernel-id", default=DEFAULT_KERNEL_ID)
    args = parser.parse_args()

    attack_source = (PROJECT_ROOT / "src" / "attack.py").read_text(encoding="utf-8")
    args.kernel_dir.mkdir(parents=True, exist_ok=True)
    (args.kernel_dir / "submission.py").write_text(build_script(attack_source), encoding="utf-8")
    (args.kernel_dir / "kernel-metadata.json").write_text(
        json.dumps(build_metadata(args.kernel_id), indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote Kaggle kernel files to {args.kernel_dir}")


if __name__ == "__main__":
    main()
