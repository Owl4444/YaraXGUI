"""Deterministic layered CFG layout without recursion or GUI dependencies."""

from collections import defaultdict, deque


def layered_layout(sizes, edges, horizontal_gap=64, vertical_gap=64):
    """Lay out disconnected regions separately so they cannot form one huge row."""
    adjacent = {node: set() for node in sizes}
    for source, target, _ in edges:
        if source in sizes and target in sizes:
            adjacent[source].add(target)
            adjacent[target].add(source)
    components = []
    component_of = {}
    for root in sizes:
        if root in component_of:
            continue
        number = len(components)
        component = []
        queue = [root]
        component_of[root] = number
        while queue:
            node = queue.pop()
            component.append(node)
            for target in sorted(adjacent[node], reverse=True):
                if target not in component_of:
                    component_of[target] = number
                    queue.append(target)
        components.append(component)
    grouped_edges = defaultdict(list)
    for edge in edges:
        if edge[0] in component_of and edge[1] in component_of:
            grouped_edges[component_of[edge[0]]].append(edge)
    positions, ranks = {}, {}
    y_offset = rank_offset = 0
    for number, component in enumerate(components):
        component_sizes = {node: sizes[node] for node in component}
        local_positions, local_ranks = _layout_connected(
            component_sizes, grouped_edges[number], horizontal_gap, vertical_gap)
        for node in component:
            x, y = local_positions[node]
            positions[node] = (x, y + y_offset)
            ranks[node] = local_ranks[node] + rank_offset
        y_offset += max(y + sizes[n][1] for n, (_, y) in local_positions.items()) + vertical_gap * 2
        rank_offset += max(local_ranks.values()) + 2
    return positions, ranks


def _layout_connected(sizes, edges, horizontal_gap, vertical_gap):
    """Return node positions and ranks; remove DFS back edges before ranking.

    Longest-path ranks keep joins below every forward predecessor. Alternating
    barycenter sweeps order each layer to reduce crossings without allocating a
    permanent column for every branch.
    """
    outgoing = {node: [] for node in sizes}
    for source, target, kind in edges:
        if source in sizes and target in sizes:
            outgoing[source].append((target, kind))
    for successors in outgoing.values():
        successors.sort(key=lambda edge: (edge[1] != "fallthrough", edge[0]))

    state = {}
    back_edges = set()
    for root in sizes:
        if root in state:
            continue
        state[root] = 1
        stack = [(root, iter(outgoing[root]))]
        while stack:
            node, children = stack[-1]
            child = next(children, None)
            if child is None:
                state[node] = 2
                stack.pop()
                continue
            target, _ = child
            if state.get(target) == 1:
                back_edges.add((node, target))
            elif target not in state:
                state[target] = 1
                stack.append((target, iter(outgoing[target])))

    predecessors = defaultdict(list)
    forward = defaultdict(list)
    for source, targets in outgoing.items():
        for target, _ in targets:
            if (source, target) not in back_edges:
                forward[source].append(target)
                predecessors[target].append(source)
    indegree = {node: len(predecessors[node]) for node in sizes}
    queue = deque(node for node in sizes if not indegree[node])
    ranks = dict.fromkeys(sizes, 0)
    while queue:
        node = queue.popleft()
        for target in forward[node]:
            ranks[target] = max(ranks[target], ranks[node] + 1)
            indegree[target] -= 1
            if not indegree[target]:
                queue.append(target)

    layers = defaultdict(list)
    for node in sizes:
        layers[ranks[node]].append(node)
    order = {node: index for layer in layers.values() for index, node in enumerate(layer)}
    for sweep in range(4):
        downward = sweep % 2 == 0
        for rank in sorted(layers, reverse=not downward):
            neighbors = predecessors if downward else forward

            def barycenter(node):
                related = neighbors[node]
                return sum(order[n] for n in related) / len(related) if related else order[node]

            layers[rank].sort(key=barycenter)
            order.update((node, index) for index, node in enumerate(layers[rank]))

    positions = {}
    y = 0
    for rank in sorted(layers):
        layer = layers[rank]
        width = sum(sizes[n][0] for n in layer) + horizontal_gap * (len(layer) - 1)
        x = -width / 2
        for node in layer:
            positions[node] = (x, y)
            x += sizes[node][0] + horizontal_gap
        y += max(sizes[n][1] for n in layer) + vertical_gap
    return positions, ranks
