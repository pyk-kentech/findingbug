from engine.io.events import load_events_jsonl


def test_load_events_jsonl_normalizes_minimal_schema(tmp_path):
    p = tmp_path / "events.jsonl"
    p.write_text('{"event_id":"e1","event_type":"read","subject":"proc:a","object":"file:x"}\n', encoding="utf-8")

    events = load_events_jsonl(p)

    assert len(events) == 1
    assert events[0].event_id == "e1"
    assert events[0].event_type == "read"
    assert events[0].subject == "proc:a"
    assert events[0].object == "file:x"
