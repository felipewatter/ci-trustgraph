"""Constrained YAML loader. Input files are data, never executed."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
import yaml
from yaml.nodes import MappingNode
from .model import Workflow

MAX_BYTES = 512 * 1024
MAX_FILES = 200
MAX_NODES = 40000


class InputError(ValueError):
    """Malformed, excessive, or unsafe workflow input."""


class WorkflowLoader(yaml.SafeLoader):
    """YAML 1.2-style boolean resolver and duplicate-key protection."""


WorkflowLoader.yaml_implicit_resolvers = {
    key: [(tag, rex) for tag, rex in resolvers if tag != 'tag:yaml.org,2002:bool']
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def _construct_mapping(loader: WorkflowLoader, node: MappingNode, deep: bool = False) -> dict:
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            if key in result:
                raise InputError(f'duplicate key: {key!r}')
        except TypeError as e:
            raise InputError('mapping key must be hashable') from e
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


WorkflowLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def _count_nodes(node: Any, visited: set[int]) -> int:
    # Reject aliases as well as recursive alias cycles; preserve bounded memory use.
    if id(node) in visited:
        raise InputError('YAML aliases are not supported')
    visited.add(id(node))
    if isinstance(node, yaml.MappingNode):
        children = [part for pair in node.value for part in pair]
    elif isinstance(node, yaml.SequenceNode):
        children = list(node.value)
    else:
        children = []
    return 1 + sum(_count_nodes(child, visited) for child in children)


def _read_yaml(data: bytes, path: str) -> dict:
    try:
        text = data.decode('utf-8-sig')
    except UnicodeDecodeError as exc:
        raise InputError(f'{path}: input must be UTF-8') from exc
    try:
        tree = yaml.compose(text, Loader=WorkflowLoader)
        if tree is None or _count_nodes(tree, set()) > MAX_NODES:
            raise InputError(f'{path}: empty or overly complex YAML document')
        obj = yaml.load(text, Loader=WorkflowLoader)
    except (yaml.YAMLError, RecursionError) as exc:
        raise InputError(f'{path}: YAML parsing error: {str(exc)[:200]}') from exc
    if not isinstance(obj, dict):
        raise InputError(f'{path}: top level must be an object')
    if not isinstance(obj.get('jobs'), dict):
        raise InputError(f'{path}: jobs must be an object')
    if not isinstance(obj.get('on', {}), (dict, list, str)):
        raise InputError(f'{path}: on must be string, list or mapping')
    return obj


def get_events(obj: dict) -> frozenset[str]:
    event = obj.get('on', {})
    if isinstance(event, str):
        return frozenset([event])
    if isinstance(event, list):
        return frozenset(str(v) for v in event)
    return frozenset(str(k) for k in event)


def load_workflows(root: Path) -> list[Workflow]:
    if root.is_symlink():
        raise InputError('repository root must not be a symlink')
    if not root.is_dir():
        raise InputError(f'not a directory: {root}')
    paths = sorted([*root.glob('.github/workflows/*.yml'), *root.glob('.github/workflows/*.yaml')])
    if len(paths) > MAX_FILES:
        raise InputError(f'too many workflows (max {MAX_FILES})')
    flows = []
    for p in paths:
        if p.is_symlink() or not p.is_file():
            raise InputError(f'symlink or non-file not supported: {p}')
        if p.stat().st_size > MAX_BYTES:
            raise InputError(f'{p}: workflow exceeds {MAX_BYTES} bytes')
        rel = p.relative_to(root).as_posix()
        obj = _read_yaml(p.read_bytes(), rel)
        name = obj.get('name', p.stem)
        if not isinstance(name, str) or len(name) > 256:
            raise InputError(f'{rel}: invalid workflow name')
        flows.append(Workflow(rel, name, get_events(obj), obj))
    return sorted(flows, key=lambda x: x.path)


def load_policy(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise InputError('invalid or oversized policy file')
    try:
        obj = json.loads(path.read_text(encoding='utf-8'))
    except (ValueError, UnicodeError) as e:
        raise InputError(f'invalid policy JSON: {e}') from e
    if not isinstance(obj, dict):
        raise InputError('policy must be object')
    return obj
