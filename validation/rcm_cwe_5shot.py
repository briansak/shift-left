"""5-shot RCM CWE prompts (technical report B.3.1 / model-card raw-completion style)."""

from __future__ import annotations

from typing import Sequence

from rcm_cwe_inputs import RcmInstance, normalize_block_text

SHOT_COUNT = 5
SHOT_EXAMPLE_SEPARATOR = "\n###\n"
FIVE_SHOT_COMPLETION_STOP = [SHOT_EXAMPLE_SEPARATOR]
FIVE_SHOT_MAX_TOKENS = 128


def defect_context(instance: RcmInstance) -> str:
    """Single-line handler defect signal for 5-shot exemplars (no CWE label)."""
    return (
        f"Configuration block: {normalize_block_text(instance.config_block)}. "
        f"Resolved values: {normalize_block_text(instance.resolved_values) or '(none)'}. "
        f"Handler match summary: {normalize_block_text(instance.match_description)}"
    )


def _shot_line(instance: RcmInstance) -> str:
    return f"{defect_context(instance)}. The CWE is {instance.expected_cwe}."


def select_shot_examples(
    instances: Sequence[RcmInstance],
    target_index: int,
    *,
    shot_count: int = SHOT_COUNT,
) -> list[RcmInstance]:
    """Pick rotated in-context examples excluding the scored instance."""
    if shot_count >= len(instances):
        raise ValueError("shot_count must be smaller than instance population")
    examples: list[RcmInstance] = []
    offset = 1
    while len(examples) < shot_count:
        idx = (target_index + offset) % len(instances)
        if idx != target_index:
            examples.append(instances[idx])
        offset += 1
    return examples


def build_5shot_rcm_prompt(
    target: RcmInstance,
    examples: Sequence[RcmInstance],
) -> str:
    """Raw-completion prompt: five completed shots, delimiter-separated, then target."""
    if not examples:
        raise ValueError("examples required")
    if target in examples:
        raise ValueError("target must not appear in shot examples")
    parts = [_shot_line(example) for example in examples]
    parts.append(f"{defect_context(target)}. The CWE is")
    return SHOT_EXAMPLE_SEPARATOR.join(parts)


def build_5shot_prompts(instances: list[RcmInstance]) -> list[tuple[RcmInstance, str, list[str]]]:
    """Return (instance, prompt, example_instance_ids) for each scored row."""
    prompts: list[tuple[RcmInstance, str, list[str]]] = []
    for index, instance in enumerate(instances):
        examples = select_shot_examples(instances, index)
        prompts.append(
            (
                instance,
                build_5shot_rcm_prompt(instance, examples),
                [item.instance_id for item in examples],
            )
        )
    return prompts
