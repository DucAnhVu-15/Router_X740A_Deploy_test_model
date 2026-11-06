"""Tìm các tensor đi qua vết cắt quanh node If hostname của sdc_os.onnx."""
import collections
import sys

import onnx

sys.stdout.reconfigure(encoding="utf-8")

PACKET = "sdc/packet_output"
HN_RESULT = "sdc/hn/result"


def main(path):
    model = onnx.load(path)
    nodes = list(model.graph.node)
    producer = {out: i for i, node in enumerate(nodes) for out in node.output}
    inits = {t.name for t in model.graph.initializer}
    graph_inputs = {i.name for i in model.graph.input}

    def ancestors(target, stop=()):
        seen, stack = set(), [target]
        while stack:
            name = stack.pop()
            if name in stop or name not in producer:
                continue
            index = producer[name]
            if index in seen:
                continue
            seen.add(index)
            stack.extend(i for i in nodes[index].input if i)
        return seen

    packet = ancestors(PACKET)
    tail = ancestors("output", stop={HN_RESULT})
    only_tail = tail - packet
    print("nodes total", len(nodes), "packet", len(packet), "tail", len(tail),
          "tail only", len(only_tail), "shared", len(tail & packet))

    cross = collections.Counter()
    for index in only_tail:
        for name in nodes[index].input:
            if name in producer and producer[name] in packet:
                cross[name] += 1
            elif name in graph_inputs and name not in inits:
                cross[name] += 1
    print("cross tensors", len(cross))
    for name, uses in sorted(cross.items()):
        origin = nodes[producer[name]].op_type if name in producer else "graph input"
        print(f"  {name}  uses={uses}  from={origin}")

    ops = collections.Counter(nodes[i].op_type for i in only_tail)
    print("tail-only ops", ops.most_common(20))
    print("packet ops", collections.Counter(nodes[i].op_type for i in packet).most_common(20))
    print("hostname evidence of If:", [n.op_type for n in nodes if n.op_type == "If"])
    locales = {a.s.decode() for n in nodes if n.op_type == "StringNormalizer"
               for a in n.attribute if a.name == "locale"}
    print("StringNormalizer locales", locales)


if __name__ == "__main__":
    main(sys.argv[1])
