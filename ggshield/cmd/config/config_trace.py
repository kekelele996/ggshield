import json
from typing import Any, Dict, List, Optional

import click

from ggshield.cmd.utils.common_options import (
    add_common_options,
    json_option,
    text_json_format_option,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.config.provenance import (
    STATUS_INVALID,
    STATUS_MERGED,
    TRACEABLE_KEYS,
    ConfigKeyTrace,
    LayerName,
    LayerValue,
    trace_config,
)


def _root_cli_params(ctx: click.Context) -> Dict[str, Any]:
    """Parameters passed on the command line, looking both at the root group
    (`ggshield --insecure config trace`) and at this command."""
    root_params = dict(ctx.find_root().params)
    for name in ("config_path", "insecure", "allow_self_signed", "verbose", "debug"):
        value = ctx.params.get(name)
        if value is not None:
            root_params[name] = value
    return root_params


def _format_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) if value else "(empty)"
    if value is None:
        return "not set"
    if value == "":
        return "(empty)"
    return str(value)


def _layer_label(layer_value: LayerValue) -> str:
    return (
        f"{layer_value.layer.value} ({layer_value.detail})"
        if layer_value.detail
        else layer_value.layer.value
    )


def _render_text(traces: List[ConfigKeyTrace]) -> str:
    lines: List[str] = []
    for trace in traces:
        lines.append(trace.key)

        if trace.merge:
            contributors = [
                layer for layer in trace.layers if layer.status == STATUS_MERGED
            ]
            lines.append(
                f"  final value:  {_format_value(trace.value)}"
                f" (combined from {len(contributors)} config file(s))"
            )
        else:
            lines.append(f"  final value:  {_format_value(trace.value)}")
            source = trace.source
            if source is not None:
                source_label = (
                    f"{source.layer.value} ({source.detail})"
                    if source.detail
                    else source.layer.value
                )
                lines.append(f"  source:       {source_label}")

        if trace.layers:
            width = max(len(_layer_label(layer)) for layer in trace.layers)
            lines.append("  layers:       (low to high precedence)")
            for layer in trace.layers:
                label = _layer_label(layer).ljust(width)
                lines.append(
                    f"    {label}  {_format_value(layer.value)} [{layer.status}]"
                )

        if trace.conflict:
            overridden = [
                layer
                for layer in trace.layers
                if layer.status == "overridden" and layer.layer != LayerName.DEFAULT
            ]
            invalid = [
                layer for layer in trace.layers if layer.status == STATUS_INVALID
            ]
            problems = []
            if overridden:
                problems.append(f"{len(overridden)} lower value(s) overridden")
            if invalid:
                problems.append(f"{len(invalid)} invalid value(s) ignored")
            lines.append(f"  conflict:     {', '.join(problems)}")

        lines.append(f"  tip:          {trace.write_advice}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


@click.command(
    name="trace",
    help="""
Trace where each effective configuration value comes from.

For every configuration key, show the value provided by each layer (default,
global/local config file, .env file, environment variable, command line
option), which layer wins, which lower values are overridden and which layers
conflict. Sensitive values (API keys) are masked.

The tip line tells you which layer a change should be written to, scoped to
the single key so unrelated settings are not copied over.
""",
)
@click.argument(
    "field_name",
    nargs=1,
    type=click.Choice(TRACEABLE_KEYS),
    required=False,
    metavar="KEY",
)
@json_option
@text_json_format_option
@add_common_options()
@click.pass_context
def config_trace_cmd(
    ctx: click.Context, field_name: Optional[str], **kwargs: Any
) -> int:
    ctx_obj = ContextObj.get(ctx)
    traces = trace_config(ctx_obj.config, _root_cli_params(ctx))

    if field_name is not None:
        traces = [trace for trace in traces if trace.key == field_name]

    if ctx_obj.use_json:
        payload = [trace.as_dict() for trace in traces]
        click.echo(json.dumps(payload if field_name is None else payload[0]))
    else:
        click.echo(_render_text(traces), nl=False)

    return 0
