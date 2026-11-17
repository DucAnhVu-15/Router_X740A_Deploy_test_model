"""Xuất dữ liệu nhánh hostname từ sdc_os.onnx sang file nhị phân cho agent C++.

Mọi trọng số lấy trực tiếp từ graph, nên bản C++ dùng đúng số của model gốc.
Hỗ trợ cả hai dạng trọng số trong graph:
  - int8  : sdc/hn/weight_<head>
  - int4  : sdc/hn/weight4_<head> (hai giá trị mỗi byte, nibble thấp trước, lệch q_offset)
Trọng số int4 được giải nén về int8 nên sdc_hn.bin và agent C++ giữ nguyên định dạng.

Contract: nếu metadata có `full_contract` (rules, masks, implied bị tách ra file riêng) thì đọc file đó,
mặc định nằm cạnh sdc_os.onnx, và kiểm sha256.
Cách dùng: python export_hostname.py <sdc_os.onnx> <sdc_hn.bin> [sdc_os_contract.json]
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

import numpy as np
import onnx
from onnx import numpy_helper

sys.stdout.reconfigure(encoding="utf-8")

HEADS = ("make", "type", "model")
UNKNOWN = "__unknown__"


class Writer:
    def __init__(self, handle):
        self.handle = handle

    def u32(self, value):
        self.handle.write(struct.pack("<I", int(value)))

    def string(self, value):
        raw = value.encode("utf-8")
        self.u32(len(raw))
        self.handle.write(raw)

    def strings(self, values):
        self.u32(len(values))
        for value in values:
            self.string(value)

    def array(self, values, dtype):
        data = np.asarray(values, dtype=dtype)
        self.u32(data.size)
        self.handle.write(data.tobytes())


def attrs(node):
    return {a.name: a for a in node.attribute}


def find_single(nodes, op_type, stem=""):
    found = [n for n in nodes if n.op_type == op_type and stem in n.name]
    if len(found) != 1:
        raise ValueError(f"cần đúng 1 node {op_type} {stem}, thấy {len(found)}")
    return found[0]


def load_contract(model, source, contract_path=None):
    """Contract đầy đủ: metadata của graph, hoặc file riêng nếu metadata đã lược bớt."""
    contract = json.loads(next(p.value for p in model.metadata_props if p.key == "sdc.contract"))
    full = contract.get("full_contract")
    if not full:
        return contract
    path = Path(contract_path) if contract_path else Path(source).with_name(full["file"])
    if not path.is_file():
        raise ValueError(f"model cần file contract {full['file']} cạnh sdc_os.onnx, không thấy {path}")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != full["sha256"]:
        raise ValueError(f"sha256 của {path.name} không khớp metadata: {digest} != {full['sha256']}")
    loaded = json.loads(raw)
    if loaded.get("run_id") != contract.get("run_id"):
        raise ValueError(f"run_id contract {loaded.get('run_id')} khác model {contract.get('run_id')}")
    print("contract", path.name, "sha256 OK")
    return loaded


def export(source, target, contract_path=None):
    model = onnx.load(source)
    if_node = find_single(model.graph.node, "If")
    branch = attrs(if_node)["then_branch"].g
    tensors = {t.name: t for t in list(model.graph.initializer) + list(branch.initializer)}
    contract = load_contract(model, source, contract_path)
    host = contract["hostname"]
    for flag in ("preserve_packet_answers", "guard_model_type", "guard_model_make", "model_implies"):
        if not host.get(flag):
            raise ValueError(f"cờ {flag} tắt: bản C++ chưa hỗ trợ")

    def find(stem):
        prefix = f"sdc/hn/{stem}_"
        return [k for k in tensors if k.startswith(prefix) and k[len(prefix):].isdigit()]

    def tensor(stem):
        names = find(stem)
        if len(names) != 1:
            raise ValueError(f"tensor {stem}: {names}")
        return numpy_helper.to_array(tensors[names[0]])

    def weights(head):
        """Ma trận int8 [feature, class] đúng như graph dùng trước khi nhân scale."""
        if find("weight_" + head):
            return tensor("weight_" + head).astype(np.int8)
        packed = tensor("weight4_" + head)
        rows, cols = (int(v) for v in tensor("q_shape_" + head))
        offset = float(tensor("q_offset_" + head))
        if int(tensor("nibble_" + head)) != 0x0F or int(tensor("shift_" + head)) != 4:
            raise ValueError(f"cách nén 4 bit của {head} không như mong đợi")
        if list(tensor("start_" + head)) != [0] or list(tensor("stop_" + head)) != [rows * cols]:
            raise ValueError(f"vùng Slice trọng số {head} không như mong đợi")
        if offset != int(offset):
            raise ValueError(f"q_offset {head} không nguyên: {offset}")
        # Graph: Concat([byte & 15, byte >> 4]) theo trục 1 rồi trải phẳng -> nibble thấp đứng trước.
        nibbles = np.stack([packed & 0x0F, packed >> 4], axis=1).reshape(-1)[: rows * cols]
        signed = nibbles.astype(np.int16).reshape(rows, cols) - int(offset)
        if signed.min() < -128 or signed.max() > 127:
            raise ValueError("trọng số vượt int8")
        return signed.astype(np.int8)

    def check_graph(name, stem, expected):
        """Đối chiếu dữ liệu contract với initializer của graph khi graph có tensor đó."""
        if find(stem) and not np.array_equal(np.asarray(tensor(stem)), np.asarray(expected)):
            raise ValueError(f"{name} trong contract khác graph ({stem})")

    encoder = find_single(branch.node, "LabelEncoder", "n_LabelEncoder_17")
    enc = attrs(encoder)
    keys = [k.decode("utf-8") for k in enc["keys_strings"].strings]
    if any(len(k) != 1 for k in keys):
        raise ValueError("bảng ký tự có khoá nhiều code point")
    alias = sorted((ord(k), int(v)) for k, v in zip(keys, enc["values_int64s"].ints))

    tfidf = attrs(find_single(branch.node, "TfIdfVectorizer"))
    pool = list(tfidf["pool_int64s"].ints)
    offsets = list(tfidf["ngram_counts"].ints) + [len(pool)]
    indexes = list(tfidf["ngram_indexes"].ints)
    base = max(v for _, v in alias) + 1
    grams, position = [], 0
    for n in range(1, 6):
        count = (offsets[n] - offsets[n - 1]) // n
        for i in range(count):
            codes = pool[offsets[n - 1] + i * n:offsets[n - 1] + (i + 1) * n]
            key = base ** n
            for k, code in enumerate(codes):
                key += code * base ** (n - k - 1)
            grams.append((key, indexes[position]))
            position += 1
    if position != len(indexes) or len({k for k, _ in grams}) != len(grams):
        raise ValueError("bảng n-gram không khớp")
    grams.sort()

    bad = [n for n in branch.node if n.op_type == "RegexFullMatch" and n.name.startswith("sdc/hn/n_")]
    bad_pattern = attrs(bad[0])["pattern"].s.decode("utf-8")
    if "__unknown__" not in bad_pattern:
        raise ValueError("regex đầu tiên không phải regex lọc hostname rỗng")

    labels = host["labels"]
    index = {h: {v: i for i, v in enumerate(labels[h])} for h in HEADS}

    masks = {name: np.asarray(host["masks"][name], dtype=np.float32) > 0 for name in ("type_guard", "make", "type")}
    check_graph("masks.type_guard", "mask_type_guard", masks["type_guard"])
    if find("mask_type_guard"):  # graph dạng mới: mask bool
        check_graph("masks.make", "mask_make", masks["make"])
        check_graph("masks.type", "mask_type", masks["type"])
    check_graph("implied.make", "implied_make_table", np.asarray(host["implied"]["make"], dtype=object))
    check_graph("implied.type", "implied_type_table", np.asarray(host["implied"]["type"], dtype=object))

    patterns = {attrs(n)["pattern"].s.decode("utf-8") for n in branch.node if n.op_type == "RegexFullMatch"}
    missing = [p for p, _, _ in host["rules"] if p not in patterns]
    if missing:
        raise ValueError(f"{len(missing)} luật trong contract không có trong graph, ví dụ {missing[:3]}")

    idf = tensor("idf")
    with open(target, "wb") as handle:
        out = Writer(handle)
        handle.write(b"SDCHN1\0\0")
        out.string(contract["run_id"])
        out.string(bad_pattern)
        out.array([a for pair in alias for a in pair], "<u4")
        out.u32(base)
        out.array([k for k, _ in grams], "<u8")
        out.array([v for _, v in grams], "<u4")
        out.array(idf, "<f4")
        for head in HEADS:
            weight = weights(head)
            out.strings([str(v) for v in tensor("labels_" + head)])
            out.u32(weight.shape[1])
            handle.write(struct.pack("<f", float(tensor("threshold_" + head))))
            out.array(tensor("scale_" + head), "<f4")
            out.array(tensor("bias_" + head), "<f4")
            out.array(weight, "i1")
            if weight.shape[0] != idf.size:
                raise ValueError("số feature không khớp idf")
        for head in HEADS:
            rules = [(p, y) for p, h, y in host["rules"] if h == head]
            out.u32(len(rules))
            for pattern, label in rules:
                out.string(pattern)
                out.string(label)
        evidence = host["expert_make_evidence"]
        out.u32(len(evidence))
        for label, pattern in evidence.items():
            out.string(label)
            out.string(pattern)
        out.strings(host["strong_mdns"])
        out.strings(host["strong_oui"])
        for head in HEADS:
            out.strings(labels[head])
        for name in ("type_guard", "make", "type"):
            out.array(masks[name].astype(np.uint8), "u1")
        for name, head in (("make", "make"), ("type", "type")):
            out.array([index[head][v] for v in host["implied"][name]], "<u2")
        pairs = [(coarse, fine) for coarse, targets in host["type_refine"].items() for fine in targets]
        out.u32(len(pairs))
        for coarse, fine in pairs:
            out.string(coarse)
            out.string(fine)

    print("run_id", contract["run_id"], "features", idf.size,
          "weights", "int4" if find("weight4_make") else "int8")
    print("alias", len(alias), "base", base, "ngrams", len(grams), "bad", bad_pattern)
    print("rules", {h: sum(1 for _, x, _ in [tuple(r) for r in host["rules"]] if x == h) for h in HEADS})
    print("labels", {h: len(labels[h]) for h in HEADS}, "evidence", len(host["expert_make_evidence"]))
    print("thresholds", {h: round(float(tensor("threshold_" + h)), 4) for h in HEADS})
    print("unknown index", {h: index[h][UNKNOWN] for h in HEADS}, "refine", host["type_refine"])
    print(f"wrote {target} {Path(target).stat().st_size / 1e6:.2f} MB")


if __name__ == "__main__":
    export(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
