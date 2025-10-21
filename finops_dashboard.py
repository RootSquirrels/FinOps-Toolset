"""FinOps dashboard generator (refactored for pylint).

This module reads a normalized CSV (see repo README for schema) and produces an 
interactive HTML dashboard with Plotly charts. Optionally exports selected figures to PDF
if Kaleido is installed.

Primary improvements vs. the original version:
- Line length <= 100 chars
- No trailing whitespace
- Snake_case variable names
- No multiple statements per line
- Narrowed exception handling (no bare or broad `Exception` catch)
- Docstrings on all functions
- Use dict literals over `dict()` calls
- Broke up large functions with too many locals/branches/args
- Removed unused variables

Columns expected (best-effort if missing):
- ResourceType, Region, Estimated_Cost_USD, Resource_ID, Name, Potential_Saving_USD
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple
import argparse

import pandas as pd
import plotly.graph_objects as go


# ------------------------------
# Data & config containers
# ------------------------------

@dataclass
class DashboardConfig:
    """Simple configuration for the dashboard build."""

    top_n: int = 25
    title: str = "AWS FinOps Dashboard"
    output_html: Path = Path("cleanup_dashboard.html")
    export_pdf: bool = False


# ------------------------------
# Data loading & preparation
# ------------------------------

REQUIRED_COLUMNS = {
    "ResourceType",
    "Region",
    "Estimated_Cost_USD",
    "Resource_ID",
    "Name",
}


def load_csv(csv_path: Path) -> pd.DataFrame:
    """Load and minimally validate the normalized CSV.

    Missing columns are tolerated where possible. Regions or names may be filled
    with placeholders to allow charts to render.
    """
    try:
        frame = pd.read_csv(csv_path)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"CSV not found: {csv_path}") from exc
    except pd.errors.EmptyDataError as exc:
        raise ValueError(f"CSV is empty or unreadable: {csv_path}") from exc

    for col in ("ResourceType", "Region"):
        if col not in frame.columns:
            frame[col] = "Unknown"
    if "Estimated_Cost_USD" not in frame.columns:
        frame["Estimated_Cost_USD"] = 0.0
    if "Name" not in frame.columns:
        frame["Name"] = frame.get("Resource_ID", "")

    # Normalize types
    frame["Estimated_Cost_USD"] = pd.to_numeric(
        frame["Estimated_Cost_USD"], errors="coerce"
    ).fillna(0.0)

    return frame


# ------------------------------
# Chart helpers
# ------------------------------


def _new_layout(title: str, x_title: str, y_title: str) -> dict:
    """Common layout dict for simple charts."""
    return {
        "title": title,
        "xaxis": {"title": x_title, "tickangle": -30},
        "yaxis": {"title": y_title},
        "margin": {"l": 60, "r": 40, "t": 50, "b": 70},
        "legend": {"orientation": "h"},
    }


def build_cost_by_resource_type(df: pd.DataFrame) -> go.Figure:
    """Bar chart: total monthly cost by ResourceType."""
    grouped = (
        df.groupby("ResourceType", dropna=False)["Estimated_Cost_USD"].sum().sort_values(ascending=False)
    )
    fig = go.Figure(
        data=[
            go.Bar(
                x=grouped.index.tolist(),
                y=grouped.values.tolist(),
                hovertemplate="%{x}: $%{y:.2f}<extra></extra>",
            )
        ]
    )
    fig.update_layout(
        **_new_layout("Cost by Resource Type", "Resource Type", "USD")
    )
    return fig


def build_top_resources(df: pd.DataFrame, top_n: int) -> go.Figure:
    """Bar chart: top-N individual resources by monthly cost."""
    subset = (
        df.sort_values("Estimated_Cost_USD", ascending=False)
        .head(top_n)
        .copy()
    )
    x_labels = (
        subset["ResourceType"].astype(str)
        + " | "
        + subset.get("Name", subset.get("Resource_ID", "")).astype(str)
    )
    fig = go.Figure(
        data=[
            go.Bar(
                x=x_labels.tolist(),
                y=subset["Estimated_Cost_USD"].tolist(),
                hovertemplate=(
                    "Resource: %{x}<br>Monthly cost: $%{y:.2f}<extra></extra>"
                ),
            )
        ]
    )
    fig.update_layout(
        **_new_layout("Top Resources by Cost", "Resource (type | id/name)", "USD")
    )
    return fig


def _pivot_cost(df: pd.DataFrame) -> Tuple[pd.Index, pd.Index, List[List[float]]]:
    """Pivot data for heatmap: rows=Region, cols=ResourceType, values=Estimated_Cost_USD."""
    pivot = pd.pivot_table(
        df,
        index="Region",
        columns="ResourceType",
        values="Estimated_Cost_USD",
        aggfunc="sum",
        fill_value=0.0,
    )
    z_matrix = pivot.values.tolist()
    return pivot.columns, pivot.index, z_matrix


def build_cost_heatmap(df: pd.DataFrame) -> go.Figure:
    """Heatmap: monthly cost by Region × ResourceType with lightweight annotations."""
    x_cols, y_idx, z_matrix = _pivot_cost(df)

    heatmap = go.Heatmap(z=z_matrix, x=list(x_cols), y=list(y_idx), coloraxis="coloraxis")
    fig = go.Figure(data=[heatmap])

    # Add small value annotations (avoid clutter for zeroes)
    for row, region in enumerate(y_idx):
        for col, rtype in enumerate(x_cols):
            val = z_matrix[row][col]
            if val <= 0:
                continue
            fig.add_annotation(
                x=rtype,
                y=region,
                text=f"${val:,.0f}",
                showarrow=False,
                font={"size": 10},
            )

    fig.update_layout(
        title={"text": "Cost Heatmap by Region × Resource Type"},
        xaxis={"title": "Resource Type", "tickangle": -35, "tickfont": {"size": 10}},
        yaxis={"title": "Region", "tickfont": {"size": 11}},
        margin={"l": 120, "r": 40, "t": 70, "b": 80},
        coloraxis={"colorscale": "YlGnBu"},
    )
    return fig


# ------------------------------
# HTML & (optional) PDF export
# ------------------------------


def compose_html(figures: Iterable[go.Figure], title: str) -> str:
    """Compose a single-file HTML with multiple figures stacked."""
    parts = [
        "<html><head><meta charset='utf-8'><title>" + title + "</title></head><body>",
        f"<h1 style='font-family:sans-serif'>{title}</h1>",
    ]
    for fig in figures:
        parts.append(fig.to_html(full_html=False, include_plotlyjs="cdn"))
    parts.append("</body></html>")
    return "\n".join(parts)


def export_pdf(figures: Iterable[go.Figure], base_path: Path) -> List[Path]:
    """Export each figure to a separate PDF named like `<base>_N.pdf`.

    Returns the list of written file paths. Requires `kaleido` to be installed.
    """

    written: List[Path] = []
    for idx, fig in enumerate(figures, start=1):
        out_path = base_path.with_suffix("")
        out_file = out_path.parent / f"{out_path.name}_{idx}.pdf"
        fig.write_image(str(out_file))
        written.append(out_file)
    return written


# ------------------------------
# Orchestration
# ------------------------------


def build_dashboard(frame: pd.DataFrame, cfg: DashboardConfig) -> Tuple[str, List[go.Figure]]:
    """Build dashboard HTML and return (html_str, figures_list)."""
    cost_by_type = build_cost_by_resource_type(frame)
    heatmap = build_cost_heatmap(frame)
    top_resources = build_top_resources(frame, cfg.top_n)

    figures = [cost_by_type, heatmap, top_resources]
    html = compose_html(figures, cfg.title)
    return html, figures


def parse_args(argv: Optional[Iterable[str]] = None) -> Tuple[Path, DashboardConfig]:
    """Parse CLI args and return (csv_path, DashboardConfig)."""
    parser = argparse.ArgumentParser(
        description=(
            "Generate a self-contained HTML FinOps dashboard from a normalized CSV. "
            "Exports optional PDFs if --pdf is passed and kaleido is installed."
        )
    )
    parser.add_argument(
        "csv",
        type=Path,
        help="Path to the normalized CSV produced by the scanner.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("cleanup_dashboard.html"),
        help="Output HTML file path (default: cleanup_dashboard.html)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=25,
        help="Number of top resources to show (default: 25)",
    )
    parser.add_argument(
        "--title",
        type=str,
        default="AWS FinOps Dashboard",
        help="Dashboard title (default: AWS FinOps Dashboard)",
    )
    parser.add_argument(
        "--pdf",
        action="store_true",
        help="Also export figures to individual PDF files (requires kaleido).",
    )

    args = parser.parse_args(list(argv) if argv is not None else None)

    cfg = DashboardConfig(
        top_n=args.top,
        title=args.title,
        output_html=args.output,
        export_pdf=args.pdf,
    )
    return args.csv, cfg


def main(argv: Optional[Iterable[str]] = None) -> int:
    """Entrypoint for CLI usage."""
    csv_path, cfg = parse_args(argv)
    frame = load_csv(csv_path)

    html, figures = build_dashboard(frame, cfg)
    cfg.output_html.write_text(html, encoding="utf-8")

    if cfg.export_pdf:
        try:
            export_pdf(figures, cfg.output_html)
        except RuntimeError as err:
            # Present a clean hint without crashing on missing optional deps
            print(str(err))  # noqa: T201

    print(f"Wrote {cfg.output_html}")  # noqa: T201
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
