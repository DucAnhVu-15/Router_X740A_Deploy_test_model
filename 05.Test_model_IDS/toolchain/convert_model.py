#!/usr/bin/env python
"""Chuyển model.onnx của một run thành build/ort/ids_model.ort cho ONNX Runtime rút gọn trên router.

Bản ORT rút gọn chỉ có TreeEnsembleClassifier của ai.onnx.ml opset 3, nên đổi khai báo opset từ 1 lên 3.
Dừng lại nếu xác suất thay đổi.

Cách dùng: python convert_model.py [thư mục run]
"""
import subprocess
import sys
from pathlib import Path

import numpy as np
import onnx
import onnxruntime as ort

PROJECT = Path(__file__).resolve().parent.parent
RUN_DIR = Path(sys.argv[1]) if len(sys.argv) > 1 else PROJECT / "model" / "20261105_1550"
OUT = PROJECT / "build" / "ort"
SAMPLES = 200000


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    source = RUN_DIR / "model.onnx"
    target = OUT / "ids_model.onnx"
    model = onnx.load(source)
    kept = {}
    for item in model.opset_import:
        kept.setdefault(item.domain, item)
    del model.opset_import[:]
    for item in kept.values():
        if item.domain == "ai.onnx.ml":
            item.version = 3
        model.opset_import.append(item)
    onnx.checker.check_model(model)
    onnx.save(model, target)

    rng = np.random.default_rng(0)
    values = (rng.lognormal(1, 3, (SAMPLES, 97)) * (rng.random((SAMPLES, 97)) > 0.5)).astype(np.float32)
    outputs = [ort.InferenceSession(path, providers=["CPUExecutionProvider"]).run(["probabilities"], {"features": values})[0]
               for path in (str(source), str(target))]
    largest = float(np.abs(outputs[0] - outputs[1]).max())
    if largest != 0:
        raise SystemExit(f"xác suất thay đổi: {largest}")

    subprocess.run([sys.executable, "-m", "onnxruntime.tools.convert_onnx_models_to_ort", str(target),
                    "--optimization_style", "Fixed", "--output_dir", str(OUT)], check=True, capture_output=True)
    print(f"OK: {OUT / 'ids_model.ort'} ({(OUT / 'ids_model.ort').stat().st_size} byte), lệch xác suất {largest}")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
