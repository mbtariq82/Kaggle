from __future__ import annotations

from pathlib import Path

import kagglehub
from kagglehub.exceptions import UnauthenticatedError


COMPETITION = "ai-agent-security-multi-step-tool-attacks"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = PROJECT_ROOT / "data" / "competition"


def main() -> None:
    if (OUTPUT_DIR / "aicomp_sdk").exists() and (OUTPUT_DIR / "kaggle_evaluation").exists():
        print(OUTPUT_DIR)
        return

    try:
        path = kagglehub.competition_download(
            COMPETITION,
            output_dir=str(OUTPUT_DIR),
        )
    except UnauthenticatedError as exc:
        raise SystemExit(
            "Kaggle is not authenticated. Add your competition token to "
            "%USERPROFILE%\\.kaggle\\access_token or set Kaggle credentials, "
            "then rerun this script."
        ) from exc
    print(path)


if __name__ == "__main__":
    main()
