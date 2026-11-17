"""Triển khai model SDC mới cho router: một lệnh từ sdc_os.onnx tới bộ file build/router.

Chạy trên Windows (cmd/PowerShell), các bước build ARM tự gọi sang WSL:
    python deploy_model.py model_origin\\20261116_093834
    python deploy_model.py <thư mục run | thư mục release | file sdc_os.onnx> [tuỳ chọn]

Tuỳ chọn:
    --parity-rows N          chỉ đối chiếu N dòng đầu trên QEMU (mặc định: tất cả, khoảng 13 phút)
    --push [USER@HOST]       build xong thì chép lên router (mặc định admin@192.168.1.1)
    --push-only [USER@HOST]  không build, chỉ chép build/router hiện có lên router

Các bước:
    1. kiểm model: sha256 theo manifest.json, file contract đi kèm
    2. tách model -> build/model (sdc_packet, sdc_tail, sdc_probe_full)
    3. chuyển sang .ort -> build/ort, sinh required_operators.config
    4. xuất nhánh hostname -> build/ort/sdc_hn.bin
    5. sinh bộ test đối chiếu, kiểm model tách -> build/ort/parity_cases.txt
    6. (WSL) build lại ORT nếu cần, link sdc_agent/sdc_infer, đối chiếu trên QEMU, chạy pcap thử,
       gom build/router (kèm model_version.txt, checksums.md5)
    7. (tuỳ chọn) chép lên router và kiểm tra trên router
"""
import argparse
import datetime as dt
import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

PROJECT = Path(__file__).resolve().parent
BUILD = PROJECT / "build"
SPLIT = PROJECT / "model_split"
MODEL_DIR = BUILD / "model"
ORT_DIR = BUILD / "ort"
ROUTER_DIR = BUILD / "router"
PARITY_INPUTS = BUILD / "test" / "parity_inputs.txt"
DEFAULT_HOST = "admin@192.168.1.1"


def step(title):
    print(f"\n=== {title}", flush=True)


def run(command, **kwargs):
    print("$", " ".join(str(c) for c in command), flush=True)
    subprocess.run([str(c) for c in command], check=True, **kwargs)


def python(script, *args):
    run([sys.executable, SPLIT / script, *args], cwd=PROJECT)


def wsl_path(path):
    path = Path(path).resolve()
    drive = path.drive.rstrip(":").lower()
    if not drive or len(drive) != 1:
        raise SystemExit(f"đường dẫn không nằm trên ổ đĩa Windows: {path}")
    return f"/mnt/{drive}/" + "/".join(path.parts[1:])


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def resolve_model(arg):
    path = Path(arg)
    if not path.is_absolute() and not path.exists():
        path = PROJECT / path
    for candidate in (path, path / "sdc_os.onnx", path / "release" / "sdc_os.onnx"):
        if candidate.is_file() and candidate.suffix == ".onnx":
            return candidate.resolve()
    raise SystemExit(f"không tìm thấy sdc_os.onnx trong {arg}")


def check_model(onnx_path):
    """Kiểm sha256 theo manifest.json (nếu có) và trả thông tin để ghi model_version.txt."""
    info = {"model": str(onnx_path), "sdc_os.onnx sha256": sha256(onnx_path)}
    manifest_path = onnx_path.with_name("manifest.json")
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        entry = manifest.get("files", {}).get(onnx_path.name, {})
        if entry.get("sha256") and entry["sha256"] != info["sdc_os.onnx sha256"]:
            raise SystemExit(f"sha256 {onnx_path.name} khác manifest.json: file hỏng hoặc không cùng bản")
        contract = entry.get("contract_file")
        if contract:
            contract_path = onnx_path.with_name(contract["file"])
            if not contract_path.is_file():
                raise SystemExit(f"thiếu {contract['file']} cạnh {onnx_path.name}")
            if sha256(contract_path) != contract["sha256"]:
                raise SystemExit(f"sha256 {contract['file']} khác manifest.json")
        info["release_id"] = manifest.get("release_id", "")
        info["source_run"] = manifest.get("sources", {}).get("run", "")
        print("manifest.json: sha256 khớp, release", info["release_id"])
    else:
        print("không có manifest.json, bỏ qua bước kiểm sha256")
    return info


def convert_to_ort():
    for name in ("sdc_packet", "sdc_tail"):
        shutil.copy2(MODEL_DIR / f"{name}.onnx", ORT_DIR / f"{name}.onnx")
        (ORT_DIR / f"{name}.ort").unlink(missing_ok=True)
    run([sys.executable, "-m", "onnxruntime.tools.convert_onnx_models_to_ort", ORT_DIR,
         "--optimization_style", "Fixed"], cwd=PROJECT)
    for name in ("sdc_packet.ort", "sdc_tail.ort", "required_operators.config"):
        if not (ORT_DIR / name).is_file():
            raise SystemExit(f"chuyển đổi không tạo ra {name}")


def write_version(info):
    lines = [f"{key}={value}" for key, value in info.items()]
    lines.append(f"built={dt.datetime.now().isoformat(timespec='seconds')}")
    (ORT_DIR / "model_version.txt").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def push(host):
    files = [line.split()[1] for line in (ROUTER_DIR / "checksums.md5").read_text().splitlines() if line.strip()]
    files.append("checksums.md5")
    print("Dừng sdc_agent đang chạy (nếu có) và tạo /tmp/sdc. Mỗi lệnh ssh/scp có thể hỏi mật khẩu.")
    run(["ssh", host, "[ -f /tmp/sdc/sdc_service.sh ] && sh /tmp/sdc/sdc_service.sh stop;"
                      " killall sdc_agent 2>/dev/null; mkdir -p /tmp/sdc"])
    run(["scp", "-O", *files, f"{host}:/tmp/sdc/"], cwd=ROUTER_DIR)
    run(["ssh", host, "cd /tmp/sdc && chmod +x sdc_agent sdc_infer && md5sum -c checksums.md5"
                      " && cat model_version.txt && ./sdc_infer /tmp/sdc parity_1000.txt"])


def main():
    parser = argparse.ArgumentParser(description="Triển khai model SDC mới cho router.")
    parser.add_argument("model", nargs="?", help="thư mục run, thư mục release hoặc file sdc_os.onnx")
    parser.add_argument("--parity-rows", type=int, default=None,
                        help="số dòng đối chiếu trên QEMU (mặc định: tất cả)")
    parser.add_argument("--push", nargs="?", const=DEFAULT_HOST, default=None, metavar="USER@HOST",
                        help=f"chép lên router sau khi build (mặc định {DEFAULT_HOST})")
    parser.add_argument("--push-only", nargs="?", const=DEFAULT_HOST, default=None, metavar="USER@HOST",
                        help="không build, chỉ chép build/router hiện có lên router")
    args = parser.parse_args()

    if args.push_only:
        if not (ROUTER_DIR / "checksums.md5").is_file():
            raise SystemExit("build/router chưa có bộ file, hãy build trước")
        print((ROUTER_DIR / "model_version.txt").read_text(encoding="utf-8")
              if (ROUTER_DIR / "model_version.txt").is_file() else "(không có model_version.txt)")
        push(args.push_only)
        return
    if not args.model:
        parser.error("cần đường dẫn model (hoặc dùng --push-only)")

    started = time.time()
    onnx_path = resolve_model(args.model)
    for folder in (MODEL_DIR, ORT_DIR, ROUTER_DIR):
        folder.mkdir(parents=True, exist_ok=True)
    if not PARITY_INPUTS.is_file():
        raise SystemExit(f"thiếu bộ input đối chiếu {PARITY_INPUTS}")

    step(f"[1/7] Kiểm model {onnx_path}")
    info = check_model(onnx_path)

    step("[2/7] Tách model -> build/model")
    python("split_model.py", onnx_path, MODEL_DIR)

    step("[3/7] Chuyển sang .ort -> build/ort")
    convert_to_ort()

    step("[4/7] Xuất nhánh hostname -> build/ort/sdc_hn.bin")
    python("export_hostname.py", onnx_path, ORT_DIR / "sdc_hn.bin")

    step("[5/7] Sinh bộ test đối chiếu và kiểm model tách")
    python("make_parity.py", MODEL_DIR, onnx_path, PARITY_INPUTS, ORT_DIR / "parity_cases.txt")
    write_version(info)

    step("[6/7] Build ARM, đối chiếu trên QEMU, gom build/router (WSL)")
    command = ["wsl", "-e", "bash", wsl_path(PROJECT / "toolchain" / "build_router.sh")]
    if args.parity_rows:
        command.append(str(args.parity_rows))
    run(command)

    if args.push:
        step(f"[7/7] Chép lên router {args.push}")
        push(args.push)
    else:
        step("[7/7] Xong. Chép lên router:")
        print("  python deploy_model.py --push-only        (chép bản vừa build), hoặc chép tay:")
        print(f"  cd /d {ROUTER_DIR}")
        print("  ssh admin@192.168.1.1 \"mkdir -p /tmp/sdc\"")
        print("  scp -O sdc_agent sdc_infer sdc_packet.ort sdc_tail.ort sdc_hn.bin run_sdc.sh sdc_service.sh sdc_monitor.sh "
              "parity_1000.txt model_version.txt checksums.md5 admin@192.168.1.1:/tmp/sdc/")
    print(f"\nTổng thời gian {(time.time() - started) / 60:.1f} phút. Bộ file router: {ROUTER_DIR}")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"\nLỖI ở lệnh: {' '.join(map(str, error.cmd))} (exit {error.returncode})")
