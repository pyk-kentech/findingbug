import json

from engine.cli.run_pipeline import _build_parser, run_pipeline


def test_cli_parser_accepts_out_as_directory_option():
    parser = _build_parser()
    args = parser.parse_args(["--events", "e.jsonl", "--rules", "r.yaml", "--out", "out"])
    assert args.out == "out"


def test_e2e_out_directory_contains_split_json_files(tmp_path):
    events_path = tmp_path / "events.jsonl"
    rules_path = tmp_path / "rules.yaml"
    out_dir = tmp_path / "out"

    events_path.write_text(
        '{"event_id":"e1","event_type":"x","subject":"a","object":"b"}\n',
        encoding="utf-8",
    )
    rules_path.write_text("rules: []\n", encoding="utf-8")

    run_pipeline(str(events_path), str(rules_path), str(out_dir))

    expected = ["result.json", "summary.json", "matches.json", "hsg.json"]
    for name in expected:
        assert (out_dir / name).exists()

    payload = json.loads((out_dir / "result.json").read_text(encoding="utf-8"))
    assert payload["summary"]["matches"] == 0
