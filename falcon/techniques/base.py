"""Technique contract. A technique is DATA + a safe simulate() function.
`destructive` can never be True: constructing such a technique raises."""
from dataclasses import dataclass, field
from typing import Callable


class ContractError(Exception):
    pass


@dataclass(frozen=True)
class Technique:
    id: str                      # e.g. "privesc.role_chain"
    attack_id: str               # MITRE ATT&CK ID, e.g. "T1098"
    name: str
    tactic: str
    preconditions: list
    action: str                  # what is emulated (plain words)
    expected_iocs: list          # signals defenders should see
    teardown: str                # how it's reverted
    param_spec: dict             # name -> (type, min, max)  (min/max for numbers)
    simulate: Callable = field(repr=False, default=None)
    destructive: bool = False

    def __post_init__(self):
        if self.destructive:
            raise ContractError(f"{self.id}: destructive techniques are not allowed")
        if not self.teardown:
            raise ContractError(f"{self.id}: a teardown description is required")
