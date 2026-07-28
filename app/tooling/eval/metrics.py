"""Pure metric computation for RedactLens's calibration and holdout corpora."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class Plant:
    file: str
    start: int
    end: int
    category: str
    is_positive: bool
    detector_id: str = "unknown"
    case_id: str = "unlabeled"


@dataclass(frozen=True)
class FindingLike:
    """The public evaluation subset of a canonical core Finding."""

    file: str
    start: int
    end: int
    tier: str
    confidence: float
    detector_id: str = "unknown"
    category: str = "unknown"
    supporting_detector_ids: tuple[str, ...] = ()


def _finding_overlaps_plant(finding: FindingLike, plant: Plant) -> bool:
    """Apply the evaluation contract for a semantically correct span.

    A finding and plant are compatible only when they name the same relative
    file and category and the finding fully contains the planted value.  Full
    containment rejects partial-secret detections while allowing a detector to
    include meaningful syntax or description context around the value.
    Category agreement is deliberately part of correctness: locating an SSN
    but reporting it as a credential is not a correct personal-ID finding.
    """
    return (
        finding.file == plant.file
        and finding.category == plant.category
        and finding.start >= 0
        and plant.start >= 0
        and finding.end > finding.start
        and plant.end > plant.start
        and finding.start <= plant.start
        and finding.end >= plant.end
    )


def _finding_sort_key(item: tuple[int, FindingLike]) -> tuple:
    index, finding = item
    return (
        finding.file,
        finding.start,
        finding.end,
        finding.category,
        finding.detector_id,
        finding.tier,
        finding.confidence,
        finding.supporting_detector_ids,
        index,
    )


def _plant_sort_key(item: tuple[int, Plant]) -> tuple:
    index, plant = item
    return (
        plant.file,
        plant.start,
        plant.end,
        plant.category,
        plant.detector_id,
        plant.case_id,
        index,
    )


def _semantic_prediction_key(finding: FindingLike) -> tuple[str, int, int, str]:
    """Identify predictions that represent the same visible detection.

    Detector identity, confidence, and tier are evidence about one prediction,
    not separate sensitive values.  Equivalent predictions therefore share one
    unit of matching capacity while remaining separate observations for metric
    denominators and confidence calibration.
    """
    return (
        finding.file,
        finding.start,
        finding.end,
        finding.category,
    )


@dataclass
class _FlowEdge:
    to: int
    reverse: int
    capacity: int
    cost: int


def _add_flow_edge(
    graph: list[list[_FlowEdge]],
    source: int,
    target: int,
    cost: int,
) -> _FlowEdge:
    forward = _FlowEdge(target, len(graph[target]), 1, cost)
    backward = _FlowEdge(source, len(graph[source]), 0, -cost)
    graph[source].append(forward)
    graph[target].append(backward)
    return forward


def _augment_shortest_path(
    graph: list[list[_FlowEdge]],
    source: int,
    sink: int,
) -> bool:
    """Augment one minimum-cost residual path using deterministic Bellman-Ford."""
    node_count = len(graph)
    distances: list[int | None] = [None] * node_count
    predecessors: list[tuple[int, int] | None] = [None] * node_count
    distances[source] = 0

    for _ in range(node_count - 1):
        changed = False
        for node, edges in enumerate(graph):
            distance = distances[node]
            if distance is None:
                continue
            for edge_index, edge in enumerate(edges):
                if edge.capacity == 0:
                    continue
                candidate = distance + edge.cost
                current = distances[edge.to]
                if current is None or candidate < current:
                    distances[edge.to] = candidate
                    predecessors[edge.to] = (node, edge_index)
                    changed = True
        if not changed:
            break

    if distances[sink] is None:
        return False

    node = sink
    while node != source:
        predecessor = predecessors[node]
        if predecessor is None:  # pragma: no cover - guarded by reachability above
            raise RuntimeError("incomplete minimum-cost matching path")
        previous, edge_index = predecessor
        edge = graph[previous][edge_index]
        edge.capacity = 0
        graph[node][edge.reverse].capacity = 1
        node = previous
    return True


def _one_to_one_matches(
    findings: list[FindingLike],
    positives: list[Plant],
    require_tier: str | None = None,
) -> list[tuple[int, int]]:
    """Return the deterministic lexicographically optimal one-to-one matching.

    Successive minimum-cost augmenting paths first maximize cardinality.  For
    that cardinality, integer cost bands minimize total span overhang, then
    total finding length, then detector disagreement, then maximize total
    matched confidence. Equivalent file/span/category predictions share one
    unit of flow capacity, so duplicates cannot recall additional plants.
    Canonical node/edge order provides a stable final tie-break independent of
    input order for distinguishable records.
    """
    eligible_findings = sorted(
        [
            item
            for item in enumerate(findings)
            if require_tier is None or item[1].tier == require_tier
        ],
        key=_finding_sort_key,
    )
    positive_items = sorted(enumerate(positives), key=_plant_sort_key)
    if not eligible_findings or not positive_items:
        return []

    semantic_groups: dict[tuple[str, int, int, str], list[int]] = {}
    for finding_rank, (_, finding) in enumerate(eligible_findings):
        semantic_groups.setdefault(_semantic_prediction_key(finding), []).append(finding_rank)
    ordered_groups = sorted(semantic_groups.items(), key=lambda item: item[0])

    compatible_pairs = [
        (finding_rank, finding_index, finding, plant_rank, plant_index, plant)
        for finding_rank, (finding_index, finding) in enumerate(eligible_findings)
        for plant_rank, (plant_index, plant) in enumerate(positive_items)
        if _finding_overlaps_plant(finding, plant)
    ]
    if not compatible_pairs:
        return []

    # One unit in a higher-order cost band outweighs every possible lower-order
    # cost across the entire matching, giving a true lexicographic optimum.
    maximum_matches = min(len(ordered_groups), len(positive_items))
    maximum_pair_rank = len(compatible_pairs) - 1
    maximum_stable_cost = maximum_matches * maximum_pair_rank
    confidence_ratios = {
        finding_rank: float(finding.confidence).as_integer_ratio()
        for finding_rank, _, finding, _, _, _ in compatible_pairs
    }
    # Binary-float denominators are powers of two, so the largest denominator
    # is an exact common scale. This compares summed confidences without a
    # decimal rounding policy becoming part of the matching result.
    common_confidence_denominator = max(
        denominator for _, denominator in confidence_ratios.values()
    )
    confidence_scores = {
        finding_rank: numerator * (common_confidence_denominator // denominator)
        for finding_rank, (numerator, denominator) in confidence_ratios.items()
    }
    maximum_confidence_score = max(confidence_scores.values())
    confidence_penalties = {
        finding_rank: maximum_confidence_score - score
        for finding_rank, score in confidence_scores.items()
    }
    maximum_confidence_penalty = max(confidence_penalties.values())
    confidence_unit = maximum_stable_cost + 1
    maximum_confidence_cost = (
        maximum_matches * maximum_confidence_penalty * confidence_unit + maximum_stable_cost
    )
    detector_unit = maximum_confidence_cost + 1
    maximum_detector_cost = maximum_matches * detector_unit + maximum_confidence_cost
    length_unit = maximum_detector_cost + 1
    maximum_length = max(finding.end - finding.start for _, _, finding, _, _, _ in compatible_pairs)
    maximum_length_cost = maximum_matches * maximum_length * length_unit + maximum_detector_cost
    overhang_unit = maximum_length_cost + 1

    source = 0
    group_offset = 1
    finding_offset = group_offset + len(ordered_groups)
    plant_offset = finding_offset + len(eligible_findings)
    sink = plant_offset + len(positive_items)
    graph: list[list[_FlowEdge]] = [[] for _ in range(sink + 1)]
    for group_rank, (_, finding_ranks) in enumerate(ordered_groups):
        group_node = group_offset + group_rank
        _add_flow_edge(graph, source, group_node, 0)
        for finding_rank in finding_ranks:
            _add_flow_edge(graph, group_node, finding_offset + finding_rank, 0)
    for plant_rank in range(len(positive_items)):
        _add_flow_edge(graph, plant_offset + plant_rank, sink, 0)

    pair_edges: list[tuple[int, int, _FlowEdge]] = []
    for stable_rank, pair in enumerate(compatible_pairs):
        finding_rank, finding_index, finding, plant_rank, plant_index, plant = pair
        overhang = (plant.start - finding.start) + (finding.end - plant.end)
        length = finding.end - finding.start
        detector_penalty = int(finding.detector_id != plant.detector_id)
        confidence_penalty = confidence_penalties[finding_rank]
        cost = (
            overhang * overhang_unit
            + length * length_unit
            + detector_penalty * detector_unit
            + confidence_penalty * confidence_unit
            + stable_rank
        )
        edge = _add_flow_edge(
            graph,
            finding_offset + finding_rank,
            plant_offset + plant_rank,
            cost,
        )
        pair_edges.append((finding_index, plant_index, edge))

    while _augment_shortest_path(graph, source, sink):
        pass

    return sorted(
        (
            (finding_index, plant_index)
            for finding_index, plant_index, edge in pair_edges
            if edge.capacity == 0
        ),
        key=lambda pair: (_finding_sort_key((pair[0], findings[pair[0]])), pair[1]),
    )


def finding_is_true_positive(finding: FindingLike, positives: list[Plant]) -> bool:
    return any(_finding_overlaps_plant(finding, plant) for plant in positives)


def plant_is_recalled(
    plant: Plant,
    findings: list[FindingLike],
    require_tier: str | None = None,
) -> bool:
    return any(
        _finding_overlaps_plant(finding, plant)
        and (require_tier is None or finding.tier == require_tier)
        for finding in findings
    )


def finding_precision(findings: list[FindingLike], positives: list[Plant]) -> float:
    """Return one-to-one precision; an empty prediction set has no support."""
    if not findings:
        return 0.0
    return len(_one_to_one_matches(findings, positives)) / len(findings)


def plant_recall(
    positives: list[Plant],
    findings: list[FindingLike],
    require_tier: str | None = None,
) -> float:
    if not positives:
        return 1.0
    return len(_one_to_one_matches(findings, positives, require_tier)) / len(positives)


def f1_score(precision: float, recall: float) -> float:
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def evaluate(findings: list[FindingLike], plants: list[Plant]) -> dict:
    positives = [plant for plant in plants if plant.is_positive]
    tier_a = [finding for finding in findings if finding.tier == "A"]
    overall_matches = _one_to_one_matches(findings, positives)
    tier_a_matches = _one_to_one_matches(tier_a, positives)
    true_positive_findings = len(overall_matches)
    tier_a_true_positive_findings = len(tier_a_matches)
    recalled_plants = true_positive_findings
    overall_precision = true_positive_findings / len(findings) if findings else 0.0
    overall_recall = recalled_plants / len(positives) if positives else 1.0
    tier_a_precision = tier_a_true_positive_findings / len(tier_a) if tier_a else 0.0
    tier_a_recall = tier_a_true_positive_findings / len(positives) if positives else 1.0

    return {
        "num_findings": len(findings),
        "num_positive_plants": len(positives),
        "num_decoy_plants": len(plants) - len(positives),
        "tier_a_findings": len(tier_a),
        "tier_a_true_positive_findings": tier_a_true_positive_findings,
        "true_positive_findings": true_positive_findings,
        "false_positive_findings": len(findings) - true_positive_findings,
        "recalled_plants": recalled_plants,
        "false_negative_plants": len(positives) - recalled_plants,
        "overall_precision": overall_precision,
        "overall_recall": overall_recall,
        "overall_f1": f1_score(overall_precision, overall_recall),
        "tier_a_precision": tier_a_precision,
        "tier_a_recall": tier_a_recall,
        "any_tier_recall": overall_recall,
        "tier_b_rescue_recall": overall_recall - tier_a_recall,
    }


def threshold_sweep(
    findings: list[FindingLike],
    plants: list[Plant],
    thresholds: list[float],
) -> list[dict]:
    positives = [plant for plant in plants if plant.is_positive]
    rows = []
    for threshold in thresholds:
        selected = [finding for finding in findings if finding.confidence >= threshold]
        matches = _one_to_one_matches(selected, positives)
        true_positives = len(matches)
        precision = true_positives / len(selected) if selected else 0.0
        recall = true_positives / len(positives) if positives else 1.0
        rows.append(
            {
                "threshold": threshold,
                "precision": precision,
                "recall": recall,
                "f1": f1_score(precision, recall),
                "num_findings_at_or_above": len(selected),
                "true_positive_findings": true_positives,
                "false_positive_findings": len(selected) - true_positives,
            }
        )
    return rows


def select_threshold(
    rows: list[dict],
    minimum_precision: float,
    preferred_threshold: float | None = None,
) -> float:
    """Select with calibration data only: maximize recall while meeting trust."""
    if not rows:
        raise ValueError("cannot select a threshold from an empty calibration sweep")
    eligible = [row for row in rows if row["precision"] >= minimum_precision]
    if not eligible:
        best_precision = max(row["precision"] for row in rows)
        raise ValueError(
            "no calibration threshold meets the minimum precision "
            f"{minimum_precision:.3f}; best observed precision was {best_precision:.3f}"
        )
    best = max(
        eligible,
        key=lambda row: (
            row["recall"],
            row["precision"],
            (
                -abs(row["threshold"] - preferred_threshold)
                if preferred_threshold is not None
                else -row["threshold"]
            ),
        ),
    )
    return best["threshold"]


def detector_breakdown(
    findings: list[FindingLike],
    plants: list[Plant],
    raw_opinion_counts: Mapping[str, int] | None = None,
    *,
    raw_opinions: list[FindingLike] | None = None,
    detector_ids: Iterable[str] = (),
) -> dict[str, dict]:
    """Report true detector quality alongside canonical consolidation.

    A detector contributes to a canonical finding when it is either primary or
    retained as supporting evidence. Precision, recall, false positives, and
    false negatives use the detector's own pre-consolidation span/category when
    ``raw_opinions`` is supplied. Canonical contribution quality remains
    available separately, and the fallback is explicitly marked incomplete.
    """
    positives = [plant for plant in plants if plant.is_positive]
    if raw_opinion_counts is not None:
        invalid_counts = {
            detector_id: count
            for detector_id, count in raw_opinion_counts.items()
            if not isinstance(count, int) or isinstance(count, bool) or count < 0
        }
        if invalid_counts:
            raise ValueError("raw detector opinion counts must be non-negative integers")

    observed_raw_counts = Counter(opinion.detector_id for opinion in raw_opinions or [])
    if raw_opinions is not None and raw_opinion_counts is not None:
        nonzero_counts = {
            detector_id: count for detector_id, count in raw_opinion_counts.items() if count
        }
        if nonzero_counts != dict(observed_raw_counts):
            raise ValueError("raw detector opinion geometry does not match raw counts")

    detector_ids = sorted(
        {finding.detector_id for finding in findings}
        | {detector_id for finding in findings for detector_id in finding.supporting_detector_ids}
        | {plant.detector_id for plant in positives}
        | (set(raw_opinion_counts) if raw_opinion_counts is not None else set())
        | set(observed_raw_counts)
        | set(detector_ids)
    )
    result: dict[str, dict] = {}
    for detector_id in detector_ids:
        emitted = [finding for finding in findings if finding.detector_id == detector_id]
        contributions = [
            finding
            for finding in findings
            if finding.detector_id == detector_id or detector_id in finding.supporting_detector_ids
        ]
        expected = [plant for plant in positives if plant.detector_id == detector_id]
        detector_opinions = (
            [opinion for opinion in raw_opinions if opinion.detector_id == detector_id]
            if raw_opinions is not None
            else contributions
        )
        # Precision asks whether this detector's own opinion was correct at
        # all. Recall remains detector-specific: plants assigned to this
        # detector must be covered by one of that detector's actual opinions.
        precision_matches = _one_to_one_matches(detector_opinions, positives)
        recall_matches = _one_to_one_matches(detector_opinions, expected)
        true_opinions = len(precision_matches)
        recalled = len(recall_matches)
        canonical_precision_matches = _one_to_one_matches(contributions, positives)
        canonical_recall_matches = _one_to_one_matches(contributions, expected)
        canonical_true = len(canonical_precision_matches)
        canonical_recalled = len(canonical_recall_matches)
        observable_raw_opinions = sum(
            int(finding.detector_id == detector_id)
            + finding.supporting_detector_ids.count(detector_id)
            for finding in findings
        )
        raw_opinion_count = (
            raw_opinion_counts.get(detector_id, 0)
            if raw_opinion_counts is not None
            else (len(detector_opinions) if raw_opinions is not None else observable_raw_opinions)
        )
        if raw_opinion_count < observable_raw_opinions:
            raise ValueError(
                f"raw count for detector {detector_id!r} is below its observable opinions"
            )
        if raw_opinions is not None and raw_opinion_count != len(detector_opinions):
            raise ValueError(f"raw geometry count for detector {detector_id!r} is inconsistent")
        canonical_contributions = len(contributions)
        # Each canonical finding has exactly one primary detector. Attribute
        # every absorbed raw opinion to its originating detector so these
        # counts partition the scanner's global raw-minus-canonical total.
        # Supporting contributions remain visible separately.
        consolidated_opinions = raw_opinion_count - len(emitted)
        unrepresented_raw_opinions = raw_opinion_count - canonical_contributions
        result[detector_id] = {
            "precision": true_opinions / len(detector_opinions) if detector_opinions else 0.0,
            "recall": recalled / len(expected) if expected else 1.0,
            "false_positives": len(detector_opinions) - true_opinions,
            "false_negatives": len(expected) - recalled,
            "emitted_findings": len(emitted),
            "canonical_contributions": canonical_contributions,
            "canonical_precision": (
                canonical_true / canonical_contributions if canonical_contributions else 0.0
            ),
            "canonical_recall": canonical_recalled / len(expected) if expected else 1.0,
            "canonical_false_positives": canonical_contributions - canonical_true,
            "canonical_false_negatives": len(expected) - canonical_recalled,
            "expected_plants": len(expected),
            "raw_opinions": raw_opinion_count,
            "raw_opinions_complete": raw_opinions is not None,
            "consolidated_opinions": consolidated_opinions,
            "unrepresented_raw_opinions": unrepresented_raw_opinions,
            "consolidation_rate": (
                consolidated_opinions / raw_opinion_count if raw_opinion_count else 0.0
            ),
        }
    return result


def category_breakdown(findings: list[FindingLike], plants: list[Plant]) -> dict[str, dict]:
    positives = [plant for plant in plants if plant.is_positive]
    categories = sorted(
        {finding.category for finding in findings} | {plant.category for plant in positives}
    )
    result: dict[str, dict] = {}
    for category in categories:
        category_findings = [finding for finding in findings if finding.category == category]
        category_plants = [plant for plant in positives if plant.category == category]
        matches = _one_to_one_matches(category_findings, category_plants)
        true_findings = len(matches)
        recalled = true_findings
        precision = true_findings / len(category_findings) if category_findings else 0.0
        recall = recalled / len(category_plants) if category_plants else 1.0
        result[category] = {
            "precision": precision,
            "recall": recall,
            "f1": f1_score(precision, recall),
            "false_positives": len(category_findings) - true_findings,
            "false_negatives": len(category_plants) - recalled,
            "emitted_findings": len(category_findings),
            "expected_plants": len(category_plants),
        }
    return result


def confidence_calibration(
    findings: list[FindingLike],
    plants: list[Plant],
    bucket_width: float = 0.1,
) -> dict:
    positives = [plant for plant in plants if plant.is_positive]
    matched_finding_indices = {
        finding_index for finding_index, _ in _one_to_one_matches(findings, positives)
    }
    outcomes = [
        (finding.confidence, float(index in matched_finding_indices))
        for index, finding in enumerate(findings)
    ]
    if not outcomes:
        return {"brier_score": 0.0, "expected_calibration_error": 0.0, "buckets": []}

    bucket_count = round(1 / bucket_width)
    buckets = []
    weighted_error = 0.0
    for index in range(bucket_count):
        lower = index * bucket_width
        upper = 1.0 if index == bucket_count - 1 else (index + 1) * bucket_width
        members = [
            item
            for item in outcomes
            if lower <= item[0] <= upper
            if index == bucket_count - 1 or item[0] < upper
        ]
        if not members:
            continue
        average_confidence = sum(item[0] for item in members) / len(members)
        accuracy = sum(item[1] for item in members) / len(members)
        weighted_error += len(members) / len(outcomes) * abs(average_confidence - accuracy)
        buckets.append(
            {
                "lower": lower,
                "upper": upper,
                "count": len(members),
                "average_confidence": average_confidence,
                "accuracy": accuracy,
            }
        )

    brier = sum((confidence - outcome) ** 2 for confidence, outcome in outcomes) / len(outcomes)
    return {
        "brier_score": brier,
        "expected_calibration_error": weighted_error,
        "buckets": buckets,
    }


def user_impact_metrics(
    findings: list[FindingLike],
    plants: list[Plant],
    num_files: int,
) -> dict:
    metrics = evaluate(findings, plants)
    positives = metrics["num_positive_plants"]
    return {
        "false_positives_per_1000_files": (
            metrics["false_positive_findings"] / num_files * 1000 if num_files else 0.0
        ),
        "canonical_findings_per_planted_value": (len(findings) / positives if positives else 0.0),
    }
