from __future__ import annotations

import argparse
import shutil
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = Path("/kaggle/working/attack.py")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Where to write the attack.py file Kaggle will import.",
    )
    args = parser.parse_args()

    source = PROJECT_ROOT / "src" / "attack.py"
    output = args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, output)
    print(f"Wrote {output} from {source}")


if __name__ == "__main__":
    main()
