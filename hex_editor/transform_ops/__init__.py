# -*- coding: utf-8 -*-
"""Built-in transform operation plugins for the hex editor.

Each module in this package registers one or more operations by calling
:func:`hex_editor.transforms.register_transform` (typically as a decorator).
At startup :func:`hex_editor.transforms.load_builtin_plugins` imports every
module here and the :data:`hex_editor.transforms.REGISTRY` is populated as
a side-effect.

To add a new operation:

1. Create a new ``.py`` file in this directory (or extend an existing one).
2. Import the decorator and helpers::

        from ..transforms import register_transform, TransformError, TransformParam, parse_bytes_input

3. Define a function ``(data: bytes, params: dict) -> bytes`` decorated with
   ``@register_transform(name=..., category=..., params=[...], length_preserving=...)``.
4. Restart the hex editor — the new op appears in the Transform dialog.

External plugin directories can be loaded at runtime via
:func:`hex_editor.transforms.load_plugin_file` /
:func:`hex_editor.transforms.load_plugin_directory`.
"""
