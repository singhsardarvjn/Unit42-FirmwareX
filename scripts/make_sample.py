"""Write the synthetic demo firmware to samples/demo-router-firmware.zip (for manual upload tests)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.samples import build_sample_firmware_zip  # noqa: E402

out = ROOT / "samples" / "demo-router-firmware.zip"
out.parent.mkdir(exist_ok=True)
out.write_bytes(build_sample_firmware_zip())
print(f"Wrote {out} ({out.stat().st_size} bytes)")
