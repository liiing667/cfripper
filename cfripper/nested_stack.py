"""
Discovery and traversal of locally packaged nested CloudFormation stacks.

A nested stack is a resource of type ``AWS::CloudFormation::Stack`` whose
``Properties.TemplateURL`` points at another template. When a whole stack
package is handed to CFRipper as local files, every nested template has to be
scanned too: a root template can be clean while a child carries a wildcard
principal, a wildcard resource or a cross-account trust.

Only references that resolve to a local file inside the package are followed.
Remote references (``http(s)://``, ``s3://``) and intrinsic functions that
cannot be resolved to a path without deployment-time context are skipped with
a warning, because CFRipper has no local file to analyse for them. Missing
local files and reference cycles fail closed by raising an exception so a
broken package can never pass the scan silently.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set
from urllib.parse import urlparse

from pycfmodel.model.cf_model import CFModel

logger = logging.getLogger(__file__)

NESTED_STACK_RESOURCE_TYPE = "AWS::CloudFormation::Stack"
REMOTE_TEMPLATE_URL_SCHEMES = {"http", "https", "s3"}


class NestedStackException(Exception):
    """Base class for failures while walking a local nested stack package."""


class MissingNestedTemplateException(NestedStackException):
    """Raised when a local ``TemplateURL`` does not point at an existing file."""


class NestedTemplateCycleException(NestedStackException):
    """Raised when nested template references form a cycle."""


@dataclass
class NestedTemplate:
    """One template in a nested stack package.

    There is one node per unique file path: a template legitimately referenced
    by several stacks is parsed and scanned only once. ``parents`` holds the
    logical ids of the ``AWS::CloudFormation::Stack`` resources along the first
    root-to-node path discovered, so the nesting chain can be reported, and
    ``children`` keeps the graph inspectable. The same child node can be
    attached to several parents.
    """

    path: Path
    logical_id: Optional[str] = None
    parents: List[str] = field(default_factory=list)
    children: List["NestedTemplate"] = field(default_factory=list)
    cfmodel: Optional[CFModel] = None

    @property
    def is_root(self) -> bool:
        return not self.parents

    def nesting_chain(self, root_path) -> str:
        """Render the root-to-node chain, e.g. ``root.yaml > ChildStack/child.yaml``."""
        root_name = root_path.name if isinstance(root_path, Path) else str(root_path)
        labels = [root_name]
        if self.parents:
            labels.append(f"{'/'.join(self.parents)}/{self.path.name}")
        return " > ".join(labels)


def get_nested_stack_template_urls(cfmodel: CFModel) -> Dict[str, str]:
    """Return ``{logical_id: TemplateURL}`` for the nested stacks in ``cfmodel``.

    Only plain-string ``TemplateURL`` values can identify a local file;
    intrinsic functions such as ``Ref``/``Fn::Sub`` cannot be turned into a
    filesystem path without deployment-time context and are therefore ignored.
    """
    template_urls: Dict[str, str] = {}
    for logical_id, resource in cfmodel.Resources.items():
        if resource.Type != NESTED_STACK_RESOURCE_TYPE:
            continue
        properties = getattr(resource, "Properties", None)
        template_url = getattr(properties, "TemplateURL", None) if properties is not None else None
        if isinstance(template_url, str):
            template_urls[logical_id] = template_url
    return template_urls


def is_remote_template_url(template_url: str) -> bool:
    return urlparse(template_url).scheme.lower() in REMOTE_TEMPLATE_URL_SCHEMES


def resolve_local_template_path(template_url: str, parent_path: Path) -> Optional[Path]:
    """Resolve a child ``TemplateURL`` against its parent template's directory.

    Returns ``None`` for references that are not local files (remote URLs).
    Intrinsic-function values never reach this function because they are not
    strings.
    """
    if is_remote_template_url(template_url):
        return None
    return (parent_path.parent / template_url).resolve()


class NestedTemplateWalker:
    """Walk a local nested stack package depth-first, failing closed.

    The walker loads each template through ``load_cfmodel``, a callable taking
    a ``Path`` and returning a parsed, optionally resolved ``CFModel``, which
    keeps filesystem and parsing concerns out of the traversal itself. Each
    unique file is loaded at most once.
    """

    def __init__(self, load_cfmodel: Callable[[Path], CFModel]):
        self.load_cfmodel = load_cfmodel
        self._models: Dict[Path, CFModel] = {}

    def walk(self, root_path: Path, root_cfmodel: Optional[CFModel] = None) -> NestedTemplate:
        root_path = root_path.resolve()
        root_model = root_cfmodel or self._get_model(root_path)
        root_node = NestedTemplate(path=root_path, cfmodel=root_model)
        self._models[root_path] = root_model
        visited: Dict[Path, NestedTemplate] = {root_path: root_node}
        self._visit(node=root_node, active={root_path}, visited=visited)
        return root_node

    def _get_model(self, path: Path) -> CFModel:
        if path not in self._models:
            self._models[path] = self.load_cfmodel(path)
        return self._models[path]

    def _visit(self, node: NestedTemplate, active: Set[Path], visited: Dict[Path, NestedTemplate]) -> None:
        node.cfmodel = self._get_model(node.path)
        for logical_id, template_url in get_nested_stack_template_urls(node.cfmodel).items():
            child_path = resolve_local_template_path(template_url, node.path)
            if child_path is None:
                logger.warning(
                    f"Skipping nested stack {logical_id} in {node.path}: remote TemplateURL {template_url!r} "
                    "cannot be analysed as a local template."
                )
                continue

            if child_path in active:
                raise NestedTemplateCycleException(
                    f"Nested template cycle detected: {child_path} is reachable from itself through {node.path} "
                    f"(resource {logical_id})."
                )
            if not child_path.is_file():
                raise MissingNestedTemplateException(
                    f"Nested template {child_path} referenced by resource {logical_id} in {node.path} does not exist."
                )

            existing = visited.get(child_path)
            if existing is not None:
                # The same file can legitimately be referenced from several
                # stacks. Attach the existing node so the graph stays complete,
                # but do not parse or walk it again.
                node.children.append(existing)
                continue

            child_node = NestedTemplate(
                path=child_path,
                logical_id=logical_id,
                parents=node.parents + [logical_id],
                cfmodel=self._get_model(child_path),
            )
            node.children.append(child_node)
            visited[child_path] = child_node
            self._visit(node=child_node, active=active | {child_path}, visited=visited)


def iter_nested_templates(node: NestedTemplate) -> List[NestedTemplate]:
    """Flatten a nesting graph depth-first, root first, one entry per unique file."""
    nodes: List[NestedTemplate] = []
    seen: Set[Path] = set()

    def _collect(current: NestedTemplate) -> None:
        if current.path in seen:
            return
        seen.add(current.path)
        nodes.append(current)
        for child in current.children:
            _collect(child)

    _collect(node)
    return nodes
