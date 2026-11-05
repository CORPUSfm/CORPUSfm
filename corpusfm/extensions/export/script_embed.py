"""One encoding policy for captured data embedded in an inline <script> (packet 1450)."""

from __future__ import annotations

import json


def script_json(value: object) -> str:
    """JSON that can't change how the HTML parser reads the surrounding <script>.

    Escaping only `</` isn't enough: `<!--<script` puts the parser in a state where the page's real
    `</script>` no longer closes the element, and the application's code never runs. JSON only has `<`
    inside strings, so a Unicode escape covers every such sequence and decodes to exactly the source
    text. U+2028 and U+2029 are escaped as well, for JavaScript engines older than ES2019.
    `_savePage` in explorer.html applies the same policy in the browser.
    """
    return (json.dumps(value, ensure_ascii=False)
            .replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))
