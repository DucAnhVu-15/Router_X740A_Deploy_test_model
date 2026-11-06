"""Tách sdc_os.onnx thành hai đoạn quanh nhánh hostname.

  sdc_packet.onnx : input -> sdc/packet_output
  sdc_tail.onnx   : input + hn_result -> output

File gốc không bị sửa. Nhánh hostname sẽ chạy trong agent C++.
Cách dùng: python split_model.py <sdc_os.onnx> <thư mục ra>
"""
import sys
from pathlib import Path

import onnx
from onnx import TensorProto, helper

PACKET = "sdc/packet_output"
HN_RESULT = "sdc/hn/result"
HN_INPUT = "hn_result"


def slice_graph(model, output_name, stop, name):
    """Giữ các node cần để tính output_name, dừng ở các tensor trong stop."""
    nodes = list(model.graph.node)
    producer = {out: i for i, node in enumerate(nodes) for out in node.output}
    keep, stack = set(), [output_name]
    while stack:
        tensor = stack.pop()
        if tensor in stop or tensor not in producer:
            continue
        index = producer[tensor]
        if index not in keep:
            keep.add(index)
            stack.extend(i for i in nodes[index].input if i)

    kept = [nodes[i] for i in sorted(keep)]
    used = {i for node in kept for i in node.input if i}
    inits = [t for t in model.graph.initializer if t.name in used]
    init_names = {t.name for t in inits}
    inputs = [i for i in model.graph.input if i.name in used and i.name not in init_names]
    # `thresholds` vừa là input vừa là initializer: giữ để có thể ghi đè như model gốc.
    inputs += [i for i in model.graph.input if i.name in used and i.name in init_names]
    output = next((o for o in model.graph.output if o.name == output_name), None)
    if output is None:
        output = helper.make_tensor_value_info(output_name, TensorProto.STRING, [None, 3])
    graph = helper.make_graph(kept, name, inputs, [output], initializer=inits)
    return helper.make_model(graph, opset_imports=list(model.opset_import),
                             ir_version=model.ir_version, producer_name="sdc-split")


def main(source, out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    model = onnx.load(source)

    packet = slice_graph(model, PACKET, set(), "sdc_packet")
    onnx.checker.check_model(packet)
    onnx.save(packet, out / "sdc_packet.onnx")

    tail = slice_graph(model, "output", {HN_RESULT}, "sdc_tail")
    for node in tail.graph.node:
        for i, name in enumerate(node.input):
            if name == HN_RESULT:
                node.input[i] = HN_INPUT
    tail.graph.input.insert(1, helper.make_tensor_value_info(HN_INPUT, TensorProto.STRING, [None, 3]))
    onnx.checker.check_model(tail)
    onnx.save(tail, out / "sdc_tail.onnx")

    # Bản gốc có thêm output trung gian, dùng để đối chiếu từng đoạn.
    probe = onnx.ModelProto()
    probe.CopyFrom(model)
    for name in (PACKET, HN_RESULT):
        probe.graph.output.append(helper.make_tensor_value_info(name, TensorProto.STRING, [None, 3]))
    probe.ClearField("metadata_props")
    onnx.save(probe, out / "sdc_probe_full.onnx")

    for path in ("sdc_packet.onnx", "sdc_tail.onnx", "sdc_probe_full.onnx"):
        loaded = onnx.load(out / path)
        print(f"{path}: {(out / path).stat().st_size / 1e6:.2f} MB, top nodes {len(loaded.graph.node)}, "
              f"inputs {[i.name for i in loaded.graph.input]}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
