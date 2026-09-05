from astp.execution_trace import append_trace_event
from astp.session_ledger import initialize_session_ledger, record_completion, reserve_action
from astp.session_report import summarize_session_execution


def test_session_report_counts_trace_and_ledger(tmp_path):
    ledger = tmp_path / "ledger.db"
    trace = tmp_path / "trace.jsonl"
    initialize_session_ledger(ledger, "s")
    counters = reserve_action(ledger, "s", max_actions=2, max_requests=2)
    counters = record_completion(ledger, "s")
    append_trace_event(trace, "permit.issued")
    append_trace_event(trace, "evidence.recorded")
    summary = summarize_session_execution(counters, trace)
    assert summary.completed == 1
    assert summary.permits_issued == 1
    assert summary.evidence_records == 1
