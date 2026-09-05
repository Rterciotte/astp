from astp.execution_trace import append_trace_event, verify_execution_trace


def test_execution_trace_is_hash_linked(tmp_path):
    path = tmp_path / "trace.jsonl"
    append_trace_event(path, "session.started")
    append_trace_event(path, "session.finished")
    assert verify_execution_trace(path) is True
    text = path.read_text()
    path.write_text(text.replace("session.finished", "session.tampered"))
    assert verify_execution_trace(path) is False
