"""Serialize report data safely inside the HTML template's script element."""
import json
import re


def _script_json(value):
    # JSON quoting alone does not stop the HTML parser from closing <script>.
    # Escape HTML metacharacters and JS line separators without changing data.
    blob = json.dumps(value, ensure_ascii=False)
    for char, escaped in (("<", "\\u003c"), (">", "\\u003e"),
                          ("&", "\\u0026"), ("\u2028", "\\u2028"),
                          ("\u2029", "\\u2029")):
        blob = blob.replace(char, escaped)
    return blob


def render_report(template, data, delete_config=None):
    values = {"__REPORT_DATA__": _script_json(data),
              "__DELETE_CONFIG__": _script_json(delete_config)}
    # Substitute only template markers, never marker-like text in user data.
    return re.sub(r"__REPORT_DATA__|__DELETE_CONFIG__",
                  lambda match: values[match.group()], template)
