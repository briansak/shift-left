"""Deterministic structural chunking."""

from __future__ import annotations

from foundation_sec_server.chunking import HeuristicTokenCounter, chunk_hunk_content
from foundation_sec_server.handlers.registry import TERRAFORM


TERRAFORM_HUNK = """\
resource "aws_security_group_rule" "a" {
  type        = "ingress"
  cidr_blocks = ["10.0.0.0/8"]
}

resource "aws_security_group_rule" "b" {
  type        = "ingress"
  cidr_blocks = ["0.0.0.0/0"]
}
"""


def test_chunking_is_deterministic_across_repeated_runs() -> None:
    counter = HeuristicTokenCounter()
    first = chunk_hunk_content(
        TERRAFORM_HUNK,
        handler=TERRAFORM,
        line_start=1,
        max_tokens=256,
        token_counter=counter,
        overlap_lines=0,
    )
    second = chunk_hunk_content(
        TERRAFORM_HUNK,
        handler=TERRAFORM,
        line_start=1,
        max_tokens=256,
        token_counter=counter,
        overlap_lines=0,
    )
    assert [(c.content, c.line_start, c.line_end, c.chunk_index) for c in first] == [
        (c.content, c.line_start, c.line_end, c.chunk_index) for c in second
    ]
