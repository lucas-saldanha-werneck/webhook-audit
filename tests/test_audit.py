import json
import pytest
from webhook_audit import audit, load_events, sign
from webhook_audit.cli import main

S = "s3cret"


def mk(eid, obj, seq, ts=0, body="{}", sig=None):
    return {"event_id": eid, "object_id": obj, "sequence": seq, "ts": ts,
            "body": body, "signature": sig if sig is not None else sign(S, body), "_line": 0}


def types(events, secret=S):
    return sorted(f["type"] for f in audit(events, secret)["findings"])


def test_clean_log_has_no_findings():
    evs = [mk("a", "o", 1), mk("b", "o", 2), mk("c", "o", 3)]
    assert types(evs) == []


def test_duplicate_detected():
    assert types([mk("a", "o", 1), mk("a", "o", 1, ts=5)]) == ["duplicate"]


def test_duplicate_not_counted_as_out_of_order():
    assert "out_of_order" not in types([mk("a", "o", 1), mk("b", "o", 2), mk("a", "o", 1, ts=9)])


def test_gap_detected():
    assert types([mk("a", "o", 1), mk("b", "o", 3)]) == ["gap"]


def test_out_of_order_detected():
    assert "out_of_order" in types([mk("a", "o", 1), mk("b", "o", 3), mk("c", "o", 2)])


def test_objects_are_independent():
    assert types([mk("a", "x", 1), mk("b", "y", 1)]) == []


def test_bad_signature():
    assert types([mk("a", "o", 1, sig="00")]) == ["bad_signature"]


def test_signature_skipped_without_secret():
    assert types([mk("a", "o", 1, sig="00")], secret=None) == []


def test_tampered_body_fails_signature():
    ev = mk("a", "o", 1, body='{"amount":1}')
    ev["body"] = '{"amount":9999}'
    assert types([ev]) == ["bad_signature"]


def test_shrinking_retry_flagged():
    evs = [mk("a", "o", 1, ts=0), mk("a", "o", 1, ts=10), mk("a", "o", 1, ts=12)]
    assert "slow_retry" in types(evs)


def test_growing_retry_ok():
    evs = [mk("a", "o", 1, ts=0), mk("a", "o", 1, ts=2), mk("a", "o", 1, ts=10)]
    assert "slow_retry" not in types(evs)


def test_load_events_rejects_bad_json(tmp_path):
    f = tmp_path / "x.jsonl"
    f.write_text("{bad\n")
    with pytest.raises(ValueError, match="line 1"):
        load_events(str(f))


def test_load_events_skips_blank_lines(tmp_path):
    f = tmp_path / "x.jsonl"
    f.write_text(json.dumps({"event_id": "a"}) + "\n\n")
    assert len(load_events(str(f))) == 1


def test_cli_sample_exit_code_and_counts(capsys):
    assert main(["examples/sample.jsonl", "--secret", "example-secret", "--json"]) == 1
    counts = json.loads(capsys.readouterr().out)["counts"]
    assert counts == {"duplicate": 2, "gap": 1, "out_of_order": 1, "bad_signature": 1, "slow_retry": 1}


def test_cli_missing_file(capsys):
    assert main(["nope.jsonl"]) == 2
