"""ABI preparation for public deterministic note fixtures and capsule records.

Opening preparation deliberately does not include spending or viewing keys.
"""

import copy

PALLAS_BASE = 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001
PALLAS_SCALAR = 0x40000000000000000000000000000000224698FC0994A8DD8C46EB2100000001


def limbs(value):
    return [str(value % 2**120), str((value >> 120) % 2**120), str(value >> 240)]


def opening(vector):
    note = copy.deepcopy(vector["note"])
    note["rho"] = {"limbs": note["rho"]}
    for point in note["receiver"].values():
        for axis in ["x", "y"]:
            point[axis] = {"limbs": point[axis]}
    assert set(note) == {"receiver", "value", "rho", "rseed"}
    return note


def contents_capsule(vector):
    note = vector["note"]
    fields = []
    for name in ["g_d", "pk_d"]:
        assert not note["receiver"][name]["is_infinity"]
        for axis in ["x", "y"]:
            fields.extend(note["receiver"][name][axis])
    fields += [note["value"], *note["rho"], *note["rseed"], vector["position"]]
    fields.extend(x for sibling in vector["siblings"] for x in sibling)
    assert len(fields) == 145
    return [str(int(x)) for x in fields]


def ownership(vector):
    return {
        name: {"limbs": copy.deepcopy(value)}
        for name, value in vector["ownership"].items()
    }
