# Build natively on Windows with the pinned requirements-build.txt.
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files

root = Path(SPECPATH).parent
helpers = root / "vendor" / "windows-amd64"
for name in ("wireproxy.exe", "wgcf.exe"):
    if not (helpers / name).is_file():
        raise SystemExit(f"Missing verified helper: {name}")

a = Analysis(
    [str(root / "src/warppocket/__main__.py")],
    pathex=[str(root / "src")],
    binaries=[(str(helpers / name), "vendor/windows-amd64")
              for name in ("wireproxy.exe", "wgcf.exe")],
    datas=[(str(root / "vendor/licenses"), "vendor/licenses"),
           *collect_data_files("certifi")],
    hiddenimports=["socks"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="WarpPocket", console=False, debug=False, strip=False, upx=False,
    uac_admin=False,
)
