from falcon.audit.log import AuditLog, verify_chain


def test_chain_valid(tmp_path):
    p = str(tmp_path / "a.jsonl")
    log = AuditLog(p, "run1")
    for i in range(5):
        log.append("step", params={"i": i})
    assert verify_chain(p) == (True, None)


def test_tamper_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(str(p), "run1")
    for i in range(5):
        log.append("step", params={"i": i})
    lines = p.read_text().splitlines()
    lines[2] = lines[2].replace('"i":2', '"i":99')
    p.write_text("\n".join(lines) + "\n")
    ok, bad = verify_chain(str(p))
    assert not ok and bad == 3


def test_deleted_line_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(str(p), "run1")
    for i in range(4):
        log.append("step", params={"i": i})
    lines = p.read_text().splitlines()
    del lines[1]
    p.write_text("\n".join(lines) + "\n")
    assert verify_chain(str(p))[0] is False


def test_chain_continues_after_reopen(tmp_path):
    p = str(tmp_path / "a.jsonl")
    AuditLog(p, "run1").append("a")
    AuditLog(p, "run1").append("b")
    assert verify_chain(p) == (True, None)
