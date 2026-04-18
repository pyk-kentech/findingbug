import json

from engine.cli.run_pipeline import run_pipeline, train_noise_model_pipeline


def _write_rules(path):
    path.write_text(
        "\n".join(
            [
                "rules:",
                "  - rule_id: R_PROC_FILE",
                "    name: proc file",
                "    source_types: [process]",
                "    target_types: [file]",
                "    prerequisites: []",
                "    event_predicate:",
                "      event_type: proc_to_file",
                "    severity: 1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _write_events_with_bytes(path, values):
    lines = []
    for i, b in enumerate(values, start=1):
        lines.append(
            json.dumps(
                {
                    "event_id": f"e{i}",
                    "event_type": "proc_to_file",
                    "subject": f"proc:{i}",
                    "object": f"file:{i}",
                    "bytes": b,
                }
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_event_no_bytes(path):
    path.write_text(
        json.dumps(
            {
                "event_id": "e1",
                "event_type": "proc_to_file",
                "subject": "proc:a",
                "object": "file:x",
            }
        )
        + "\n",
        encoding="utf-8",
    )


def test_byte_volume_training_then_detection_drop(tmp_path):
    rules = tmp_path / "rules.yaml"
    train_events = tmp_path / "train.jsonl"
    detect_events = tmp_path / "detect.jsonl"
    model = tmp_path / "noise_model.json"
    out_train = tmp_path / "out_train"
    out_detect = tmp_path / "out_detect"
    _write_rules(rules)
    _write_events_with_bytes(train_events, list(range(10, 31)))
    _write_events_with_bytes(detect_events, [15])

    train_noise_model_pipeline(
        train_events_path=str(train_events),
        rules_path=str(rules),
        output_path=str(out_train),
        save_noise_model_path=str(model),
        min_count=999,
        bytes_min_count=20,
    )
    payload = json.loads(model.read_text(encoding="utf-8"))
    assert "byte_volume" in payload
    assert "R_PROC_FILE" in payload["byte_volume"]
    assert payload["byte_volume"]["R_PROC_FILE"]["p95"] >= 15

    result = run_pipeline(
        events_path=str(detect_events),
        rules_path=str(rules),
        output_path=str(out_detect),
        noise_model_path=str(model),
        noise_bytes_threshold="p95",
    )
    trained = result["summary"]["noise_filter"]["trained_noise"]
    assert trained["by_byte_volume"] >= 1
    assert result["summary"]["noise_filter"]["after"]["matches"] < result["summary"]["noise_filter"]["before"]["matches"]


def test_byte_volume_outlier_not_dropped(tmp_path):
    rules = tmp_path / "rules.yaml"
    train_events = tmp_path / "train.jsonl"
    detect_events = tmp_path / "detect.jsonl"
    model = tmp_path / "noise_model.json"
    out_train = tmp_path / "out_train"
    out_detect = tmp_path / "out_detect"
    _write_rules(rules)
    _write_events_with_bytes(train_events, list(range(10, 31)))
    _write_events_with_bytes(detect_events, [500])

    train_noise_model_pipeline(
        train_events_path=str(train_events),
        rules_path=str(rules),
        output_path=str(out_train),
        save_noise_model_path=str(model),
        min_count=999,
        bytes_min_count=20,
    )
    result = run_pipeline(
        events_path=str(detect_events),
        rules_path=str(rules),
        output_path=str(out_detect),
        noise_model_path=str(model),
        noise_bytes_threshold="p95",
    )
    trained = result["summary"]["noise_filter"]["trained_noise"]
    assert trained["by_byte_volume"] == 0
    assert result["summary"]["noise_filter"]["after"]["matches"] == result["summary"]["noise_filter"]["before"]["matches"]


def test_byte_volume_not_applied_when_bytes_missing(tmp_path):
    rules = tmp_path / "rules.yaml"
    train_events = tmp_path / "train.jsonl"
    detect_events = tmp_path / "detect.jsonl"
    model = tmp_path / "noise_model.json"
    out_train = tmp_path / "out_train"
    out_detect = tmp_path / "out_detect"
    _write_rules(rules)
    _write_events_with_bytes(train_events, list(range(10, 31)))
    _write_event_no_bytes(detect_events)

    train_noise_model_pipeline(
        train_events_path=str(train_events),
        rules_path=str(rules),
        output_path=str(out_train),
        save_noise_model_path=str(model),
        min_count=999,
        bytes_min_count=20,
    )
    result = run_pipeline(
        events_path=str(detect_events),
        rules_path=str(rules),
        output_path=str(out_detect),
        noise_model_path=str(model),
        noise_bytes_threshold="p95",
    )
    trained = result["summary"]["noise_filter"]["trained_noise"]
    assert trained["by_byte_volume"] == 0
    assert result["summary"]["noise_filter"]["after"]["matches"] == result["summary"]["noise_filter"]["before"]["matches"]
