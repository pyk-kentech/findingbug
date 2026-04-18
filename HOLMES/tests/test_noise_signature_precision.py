from engine.core.matcher import TTPMatch
from engine.noise.model import get_benign_drop_ids, train_noise_model
from engine.rules.schema import Rule


def _match(match_id: str, rule_id: str, subject: str, object_: str, event_type: str = "proc_to_file") -> TTPMatch:
    return TTPMatch(
        match_id=match_id,
        rule_id=rule_id,
        event_ids=[f"e-{match_id}"],
        entities=[subject, object_],
        bindings={"subject": subject, "object": object_},
        metadata={"event_type": event_type},
    )


def test_signature_precision_drops_high_frequency_benign_pattern():
    rule = Rule(rule_id="R1", name="r1", stage=3, event_predicate={"event_type": "proc_to_file"})
    train_matches = [_match(f"m{i}", "R1", "proc:a", "file:/tmp/a.txt") for i in range(20)]
    model = train_noise_model(
        train_matches,
        rule_by_id={"R1": rule},
        min_count=1,
        signature_min_ratio=0.1,
    )

    detect_match = _match("d1", "R1", "proc:a", "file:/tmp/a.txt")
    drop_ids, stats = get_benign_drop_ids([detect_match], {"R1": rule}, model, signature_min_ratio=0.1)

    assert detect_match.match_id in drop_ids
    assert stats["by_signature"] == 1
    assert stats["signature_precision"]["dropped_by_ratio"] == 1


def test_signature_precision_keeps_rare_benign_pattern():
    rule = Rule(rule_id="R1", name="r1", stage=3, event_predicate={"event_type": "proc_to_file"})
    train_matches = [_match(f"m{i}", "R1", "proc:a", "file:/tmp/a.txt") for i in range(19)]
    train_matches.append(_match("m_rare", "R1", "proc:a", "file:/home/a.txt"))
    model = train_noise_model(
        train_matches,
        rule_by_id={"R1": rule},
        min_count=1,
        signature_min_ratio=0.1,
    )

    detect_match = _match("d1", "R1", "proc:a", "file:/home/a.txt")
    drop_ids, stats = get_benign_drop_ids([detect_match], {"R1": rule}, model, signature_min_ratio=0.1)

    assert detect_match.match_id not in drop_ids
    assert stats["by_signature"] == 0


def test_signature_is_stage_aware():
    rule_stage3 = Rule(rule_id="R_STAGE", name="r", stage=3, event_predicate={"event_type": "proc_to_file"})
    train_matches = [_match(f"m{i}", "R_STAGE", "proc:a", "file:/tmp/a.txt") for i in range(10)]
    model = train_noise_model(
        train_matches,
        rule_by_id={"R_STAGE": rule_stage3},
        min_count=1,
        signature_min_ratio=0.1,
    )

    rule_stage5 = Rule(rule_id="R_STAGE", name="r", stage=5, event_predicate={"event_type": "proc_to_file"})
    detect_match = _match("d1", "R_STAGE", "proc:a", "file:/tmp/a.txt")
    drop_ids, stats = get_benign_drop_ids([detect_match], {"R_STAGE": rule_stage5}, model, signature_min_ratio=0.1)

    assert detect_match.match_id not in drop_ids
    assert stats["by_signature"] == 0


def test_file_shape_differentiates_tmp_and_home():
    rule = Rule(rule_id="R_FILE", name="r", stage=3, event_predicate={"event_type": "proc_to_file"})
    model = train_noise_model(
        [_match(f"m{i}", "R_FILE", "proc:a", "file:/tmp/a.txt") for i in range(20)],
        rule_by_id={"R_FILE": rule},
        min_count=1,
        signature_min_ratio=0.1,
    )

    detect_match = _match("d1", "R_FILE", "proc:a", "file:/home/a.txt")
    drop_ids, stats = get_benign_drop_ids([detect_match], {"R_FILE": rule}, model, signature_min_ratio=0.1)

    assert detect_match.match_id not in drop_ids
    assert stats["by_signature"] == 0
