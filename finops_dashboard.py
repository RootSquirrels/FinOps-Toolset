#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FinOps HTML Dashboard generator for cleanup_estimates.csv
Usage:
  python finops_dashboard.py cleanup_estimates.csv -o cleanup_dashboard.html --top 25

This tool:
- Reads your ';' delimited CSV (as produced by write_resource_to_csv(...)).
- Computes aggregates (cost, potential savings) by ResourceType and Region (from Signals).
- Renders Plotly charts + summary KPIs + top findings table into one self-contained HTML file.
"""

import argparse
import os
import sys
import math
import pandas as pd
import numpy as np
import plotly.graph_objects as go #type: ignore
import plotly.io as pio #type: ignore
from datetime import datetime
from typing import Optional

# ---------- CSV schema helpers ----------
REQUIRED_COLS = [
    "Resource_ID","Name","ResourceType","OwnerId","State","Creation_Date",
    "Storage_GB","Object_Count","Estimated_Cost_USD","Potential_Saving_USD",
    "ApplicationID","Application","Environment","ReferencedIn",
    "FlaggedForReview","Confidence","Signals"
]

def _read_csv_csv(path: str) -> pd.DataFrame:
    """
    Robust CSV reader for the FinOps export:
    - Accepts leading 'sep=;' or 'sep=,' Excel hint lines.
    - Handles UTF-8 with BOM.
    - Auto-detects delimiter if needed.
    - Falls back to skip bad lines instead of failing.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"CSV not found: {path}")

    # Read the first non-empty line to detect 'sep=' (Excel hint)
    first_line = ""
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        for line in f:
            if line.strip():  # non-empty
                first_line = line.strip()
                break

    skiprows = 0
    sep_arg = None  # let us choose dynamically

    if first_line.lower().startswith("sep=") and len(first_line) >= 5:
        # Excel hint e.g., "sep=;" or "sep=,"
        sep_arg = first_line[4]
        skiprows = 1  # skip the hint line

    # Try a few strategies in order
    tried = []
    def normalize(df: pd.DataFrame) -> pd.DataFrame:
        # Canonicalize columns
        def canon(c): return c.strip().replace(" ", "_")
        df.columns = [canon(c) for c in df.columns]
        for c in [
            "Resource_ID","Name","ResourceType","OwnerId","State","Creation_Date",
            "Storage_GB","Object_Count","Estimated_Cost_USD","Potential_Saving_USD",
            "ApplicationID","Application","Environment","ReferencedIn",
            "FlaggedForReview","Confidence","Signals"
        ]:
            if c not in df.columns:
                df[c] = ""  # backfill missing
        # Numeric casts
        for c in ("Estimated_Cost_USD","Potential_Saving_USD","Storage_GB","Object_Count","Confidence"):
            if c in df.columns:
                df[c] = pd.to_numeric(df[c].replace({"": np.nan}), errors="coerce").fillna(0.0)
        if "Confidence" in df.columns:
            df["Confidence"] = df["Confidence"].round(0).astype(int)
        return df

    # 1) If we saw sep=… use that delimiter
    if sep_arg:
        try:
            tried.append(f"sep='{sep_arg}', skiprows=1, engine='python'")
            df = pd.read_csv(path, sep=sep_arg, skiprows=skiprows, engine="python",
                             encoding="utf-8-sig", dtype=str, keep_default_na=False)
            return normalize(df)
        except Exception as e:
            # fall through
            pass

    # 2) Automatic sniffing
    try:
        tried.append("sep=None (sniff), engine='python'")
        df = pd.read_csv(path, sep=None, engine="python", encoding="utf-8-sig",
                         dtype=str, keep_default_na=False)
        return normalize(df)
    except Exception:
        pass

    # 3) Hard try with semicolon
    try:
        tried.append("sep=';' (C engine)")
        df = pd.read_csv(path, sep=';', encoding="utf-8-sig", dtype=str, keep_default_na=False)
        return normalize(df)
    except Exception:
        pass
    # 4) Hard try with comma
    try:
        tried.append("sep=',' (C engine)")
        df = pd.read_csv(path, sep=',', encoding="utf-8-sig", dtype=str, keep_default_na=False)
        return normalize(df)
    except Exception:
        pass

    # 5) Last resort: skip bad lines with semicolon, Python engine
    try:
        tried.append("sep=';' (python engine, skip bad lines)")
        df = pd.read_csv(path, sep=';', engine="python", encoding="utf-8-sig",
                         dtype=str, keep_default_na=False, on_bad_lines="skip")
        return normalize(df)
    except Exception as e:
        raise ValueError(f"Could not parse CSV after attempts: {tried}") from e

def _signals_to_dict(sig: str) -> dict:
    """
    Convert the Signals cell to a dict.
    Accepts strings like "k=v\nk2=v2" OR "k=v; k2=v2" OR arbitrary.
    """
    out = {}
    if not sig:
        return out
    # Split by line breaks first; then by ';'
    parts = []
    for line in str(sig).splitlines():
        line = line.strip()
        if not line:
            continue
        # If line contains multiple pairs separated by ';'
        if ';' in line and '=' in line:
            parts += [p.strip() for p in line.split(';') if p.strip()]
        else:
            parts.append(line)
    # Parse k=v
    for p in parts:
        if '=' in p:
            k,v = p.split('=', 1)
            out[str(k).strip()] = str(v).strip()
    return out

def _extract_region(df: pd.DataFrame) -> pd.Series:
    """
    Try to extract 'Region' from Signals into a new column. If absent, empty string.
    """
    if "Signals" not in df.columns:
        return pd.Series([""]*len(df), name="Region")
    regions = []
    for s in df["Signals"].tolist():
        d = _signals_to_dict(s)
        regions.append(d.get("Region",""))
    return pd.Series(regions, name="Region")


# ---------- Aggregations ----------
def _agg_by_resource_type(df: pd.DataFrame) -> pd.DataFrame:
    ag = df.groupby("ResourceType", dropna=False).agg(
        Count=("Resource_ID", "count"),
        EstCost=("Estimated_Cost_USD", "sum"),
        Potential=("Potential_Saving_USD", "sum")
    ).reset_index().sort_values(["Potential","EstCost"], ascending=[False, False])
    return ag

def _agg_by_region(df: pd.DataFrame) -> pd.DataFrame:
    if "Region" not in df.columns:
        df["Region"] = _extract_region(df)
    ag = df.groupby(["Region","ResourceType"], dropna=False).agg(
        Count=("Resource_ID", "count"),
        Potential=("Potential_Saving_USD", "sum")
    ).reset_index()
    return ag

def _top_findings(df: pd.DataFrame, top_n: int = 25) -> pd.DataFrame:
    cols = ["Resource_ID","Name","ResourceType","Estimated_Cost_USD","Potential_Saving_USD","FlaggedForReview","Confidence","Signals"]
    existing = [c for c in cols if c in df.columns]
    d = df.copy()
    d["Potential_Saving_USD"] = pd.to_numeric(d["Potential_Saving_USD"], errors="coerce").fillna(0.0)
    d = d.sort_values("Potential_Saving_USD", ascending=False)
    return d[existing].head(top_n)


# ---------- Plotly Figures ----------
def _fmt_usd(x: float) -> str:
    try:
        return f"${x:,.2f}"
    except Exception:
        return "$0.00"

def fig_cost_by_type(ag: pd.DataFrame) -> go.Figure:
    return go.Figure(
        data=[go.Bar(x=ag["ResourceType"], y=ag["EstCost"], marker_color="#1f77b4", name="Estimated cost")],
        layout=go.Layout(
            title="Estimated Monthly Cost by Resource Type",
            xaxis=dict(title="Resource Type", tickangle=-30),
            yaxis=dict(title="USD"),
            bargap=0.2,
            height=420
        )
    )

def fig_savings_by_type(ag: pd.DataFrame) -> go.Figure:
    return go.Figure(
        data=[go.Bar(x=ag["ResourceType"], y=ag["Potential"], marker_color="#2ca02c", name="Potential savings")],
        layout=go.Layout(
            title="Potential Savings by Resource Type",
            xaxis=dict(title="Resource Type", tickangle=-30),
            yaxis=dict(title="USD"),
            bargap=0.2,
            height=420
        )
    )

def fig_top_findings(topdf: pd.DataFrame) -> go.Figure:

    # Guard: nothing to plot
    if topdf is None or getattr(topdf, "empty", True):
        return go.Figure()

    toPdf = topdf.copy()
    # Build a readable label (ResourceType | Name or ID)
    label_src = toPdf["Name"].astype(str)
    # Use Resource_ID when Name is empty
    label_src = label_src.where(label_src.str.len() > 0, toPdf["Resource_ID"].astype(str))
    toPdf["Label"] = toPdf["ResourceType"].astype(str) + " | " + label_src
    fig = go.Figure(
        data=[go.Bar(
            x=toPdf["Potential_Saving_USD"],
            y=toPdf["Label"],
            orientation="h",
            marker_color="#d62728",
            name="Potential saving"
        )],
        layout=go.Layout(
            title="Top Potential Savings (resources)",
            xaxis=dict(title="USD"),
            yaxis=dict(title="Resource (type | id/name)", automargin=True),
            height=max(400, 22 * len(toPdf) + 120)
        )
    )
    return fig


def fig_heatmap_enhanced(
    ag_reg: pd.DataFrame,
    metric: str = "Potential",        # "Potential" (USD) or "Count"
    top_types: int = 12,
    top_regions: int = 18,
    normalize: Optional[str] = None, 
    colorscale: str = "YlOrRd",
    robust: bool = True               # clip color range to 2nd–98th percentiles
) -> go.Figure:
    """
    A clearer, prioritized heatmap with sorting, Top-N selection, optional normalization,
    robust color range, and readable labels/hover.

    ag_reg columns expected: Region, ResourceType, Count, Potential
    """

    if ag_reg is None or ag_reg.empty:
        return go.Figure()

    df = ag_reg.copy()

    # ---- Choose metric and guard ----
    metric = "Potential" if str(metric).lower().startswith("pot") else "Count"
    if metric not in df.columns:
        # fallback if missing column
        metric = "Count"

    # ---- Pick Top resource types by chosen metric (global) ----
    type_tot = df.groupby("ResourceType", as_index=False)[metric].sum()
    type_tot = type_tot.sort_values(metric, ascending=False)
    keep_types = type_tot["ResourceType"].head(top_types).tolist()
    df = df[df["ResourceType"].isin(keep_types)]

    # ---- Pick Top regions by chosen metric (after filtering types) ----
    reg_tot = df.groupby("Region", as_index=False)[metric].sum()
    reg_tot = reg_tot.sort_values(metric, ascending=False)
    keep_regions = reg_tot["Region"].head(top_regions).tolist()
    df = df[df["Region"].isin(keep_regions)]

    # ---- Pivot to matrix ----
    pivot = df.pivot_table(
        index="Region", columns="ResourceType", values=metric, aggfunc="sum", fill_value=0.0
    )

    # Sort axes by totals for consistent visual priority
    col_order = pivot.sum(axis=0).sort_values(ascending=False).index.tolist()
    row_order = pivot.sum(axis=1).sort_values(ascending=False).index.tolist()
    pivot = pivot.loc[row_order, col_order]

    # Keep a reference matrix for hover (both metrics if available)
    # (Optional: include Count for hover even when plotting Potential)
    hover_map = {
        "Count": df.pivot_table(index="Region", columns="ResourceType", values="Count", aggfunc="sum", fill_value=0.0)
        if "Count" in df.columns else None,
        "Potential": df.pivot_table(index="Region", columns="ResourceType", values="Potential", aggfunc="sum", fill_value=0.0)
        if "Potential" in df.columns else None
    }
    # Reindex hovers to match pivot shape
    for k in list(hover_map.keys()):
        if hover_map[k] is not None:
            hover_map[k] = hover_map[k].reindex(index=row_order, columns=col_order, fill_value=0.0)

    # ---- Optional normalization (percent mix) ----
    Z = pivot.values.astype(float)
    z_title = metric
    suffix = ""
    if normalize == "row":
        row_sums = Z.sum(axis=1, keepdims=True)
        row_sums[row_sums == 0] = 1.0
        Z = (Z / row_sums) * 100.0
        z_title = f"{metric} share per Region"
        suffix = "%"
    elif normalize == "col":
        col_sums = Z.sum(axis=0, keepdims=True)
        col_sums[col_sums == 0] = 1.0
        Z = (Z / col_sums) * 100.0
        z_title = f"{metric} share per Type"
        suffix = "%"

    # ---- Robust color range to reveal mid-range variation ----
    zmin, zmax = (None, None)
    if robust and Z.size:
        q_low = np.nanquantile(Z, 0.02)
        q_hi  = np.nanquantile(Z, 0.98)
        if np.isfinite(q_low) and np.isfinite(q_hi) and q_hi > q_low:
            zmin, zmax = float(q_low), float(q_hi)

    # ---- Annotations: only show for the top cells to avoid clutter ----
    # Define a threshold as top 10% values (post-normalization if used)
    annot = []
    if Z.size:
        flat = Z.flatten()
        thr = np.nanquantile(flat, 0.90) if np.isfinite(np.nanquantile(flat, 0.90)) else None
        for i, r in enumerate(row_order):
            for j, c in enumerate(col_order):
                val = Z[i, j]
                if thr is not None and val >= thr and val > 0:
                    text = f"{val:,.0f}{suffix}" if suffix else (f"${val:,.0f}" if metric == "Potential" and normalize is None else f"{val:,.0f}")
                    annot.append(dict(x=c, y=r, text=text, showarrow=False, font=dict(color="black", size=10)))

    # ---- Hovertemplate: show both Count & Potential if we have them ----
    def fmt_usd(x: float) -> str:
        try: return f"${x:,.2f}"
        except: return "$0.00"

    # Create 2D arrays for richer hover
    hv_count = hover_map["Count"].values if hover_map["Count"] is not None else None
    hv_pot   = hover_map["Potential"].values if hover_map["Potential"] is not None else None

    hovertext = []
    for i, r in enumerate(row_order):
        row_ht = []
        for j, c in enumerate(col_order):
            lines = [f"<b>Region:</b> {r}", f"<b>Type:</b> {c}"]
            if hv_count is not None:
                lines.append(f"<b>Count:</b> {int(hv_count[i,j])}")
            if hv_pot is not None:
                lines.append(f"<b>Potential:</b> {fmt_usd(float(hv_pot[i,j]))}")
            if normalize in ("row","col"):
                lines.append(f"<b>Share:</b> {Z[i,j]:.1f}%")
            row_ht.append("<br>".join(lines))
        hovertext.append(row_ht)

    # ---- Build figure ----
    fig = go.Figure(
        data=go.Heatmap(
            z=Z,
            x=col_order,
            y=row_order,
            colorscale=colorscale,
            colorbar=dict(title=z_title),
            zmin=zmin, zmax=zmax,
            hoverinfo="text",
            text=hovertext
        )
    )
    fig.update_layout(
        title=f"Heatmap — {('Normalized ' if normalize else '')}{metric} by Region × ResourceType",
        xaxis=dict(title="Resource Type", tickangle=-35, tickfont=dict(size=10)),
        yaxis=dict(title="Region", tickfont=dict(size=11)),
        height=max(420, 24 * len(row_order) + 180),
        margin=dict(l=180, r=40, t=70, b=80)
    )
    # Gridlines can help orient dense matrices
    fig.update_xaxes(showgrid=False)
    fig.update_yaxes(showgrid=False)
    # Add annotations (top cells only)
    if annot:
        fig.update_layout(annotations=annot)
    return fig


def _df_embed_payload(df: pd.DataFrame, max_rows: int = 5000) -> str:
    """
    Reduce to the columns we need in the browser and emit a JSON string.
    To keep HTML small, cap to max_rows (keep largest potential savings first).
    """
    use_cols = [
        "Resource_ID", "Name", "ResourceType", "Estimated_Cost_USD", "Potential_Saving_USD",
        "FlaggedForReview", "Confidence", "Signals", "Region"
    ]
    exists = [c for c in use_cols if c in df.columns]
    d = df.copy()
    # Pre-sort by potential saving, descending; then cap to max_rows
    d["Potential_Saving_USD"] = pd.to_numeric(d["Potential_Saving_USD"], errors="coerce").fillna(0.0)
    d = d.sort_values("Potential_Saving_USD", ascending=False)
    if max_rows and len(d) > max_rows:
        d = d.head(max_rows)
    # Ensure Region column present
    if "Region" not in d.columns or d["Region"].eq("").all():
        d["Region"] = _extract_region(d)
    # Convert to JSON records
    return d[exists].to_json(orient="records")


def build_html(df: pd.DataFrame, out_html: str, title: str = "AWS FinOps Cleanup Dashboard",
               top_n: int = 25, embed_js: bool = True) -> str:
    # KPIs
    total_rows = len(df)
    total_cost = float(df["Estimated_Cost_USD"].sum())
    total_potential = float(df["Potential_Saving_USD"].sum())
    types = sorted(df["ResourceType"].unique().tolist())

    ag_type = _agg_by_resource_type(df)
    ag_region = _agg_by_region(df)
    top_df   = _top_findings(df, top_n=top_n)

    # Figures
    f1 = fig_cost_by_type(ag_type)
    f2 = fig_savings_by_type(ag_type)      # we’ll attach click → filter by ResourceType
    f3 = fig_top_findings(top_df)          # optional click wiring (by type)
    
    f4 = fig_heatmap_enhanced(
        ag_region,
        metric="Potential",        
        top_types=12,              
        top_regions=18,            
        normalize="row",           # None | "row" | "col"
        colorscale="YlOrRd",       # "YlGnBu", "Viridis", "Plasma", ...
        robust=True
    )

    include_js = 'embed' if embed_js else 'cdn'
    f1_html = pio.to_html(f1, full_html=False, include_plotlyjs=include_js)
    f2_html = pio.to_html(f2, full_html=False, include_plotlyjs=False)
    f3_html = pio.to_html(f3, full_html=False, include_plotlyjs=False)
    f4_html = pio.to_html(f4, full_html=False, include_plotlyjs=False)

    # Detail table HTML placeholder
    top_tbl = top_df.copy()
    if not top_tbl.empty:
        top_tbl["Estimated_Cost_USD"] = top_tbl["Estimated_Cost_USD"].map(_fmt_usd)
        top_tbl["Potential_Saving_USD"] = top_tbl["Potential_Saving_USD"].map(_fmt_usd)
        table_html = top_tbl.to_html(index=False, escape=False)
    else:
        table_html = "<p>No findings with potential savings.</p>"

    # Embed the reduced dataset for drilldown (cap to keep HTML light)
    embedded_json = _df_embed_payload(df, max_rows=5000)

    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; margin: 0; padding: 0; background: #f7f7f9; }}
.container {{ max-width: 1320px; margin: 0 auto; padding: 24px; }}
.kpis {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 16px; }}
.card {{ background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.08); padding: 14px 16px; }}
.card .h {{ font-size: 12px; color: #666; text-transform: uppercase; letter-spacing: .06em; }}
.card .v {{ font-size: 24px; font-weight: 700; margin-top: 4px; }}
.grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
.section {{ margin-top: 18px; }}
h1 {{ margin: 0 0 8px 0; font-weight: 800; }}
h2 {{ margin: 12px 0; font-weight: 700; font-size: 18px; }}
table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
th, td {{ border: 1px solid #ddd; padding: 8px 10px; }}
th {{ background: #fafafa; text-align: left; }}
.footer {{ text-align: right; color: #777; font-size: 12px; margin-top: 12px; }}
.badge {{ background: #eef5ff; color: #0a58ca; font-weight: 600; padding: 2px 6px; border-radius: 6px; font-size: 12px; }}
.pill  {{ background: #f1f3f5; color: #333; padding: 2px 8px; border-radius: 999px; font-size: 12px; }}
.btn  {{ border: 1px solid #ccc; background: #fff; border-radius: 6px; padding: 6px 12px; cursor: pointer; }}
.btn:hover {{ background: #f8f9fa; }}
#drill_table_container {{ overflow:auto; max-height:540px; }}
</style>
</head>
<body>
<div class="container">
  <h1>{title}</h1>
  <div style="margin-bottom:8px;">
    <span class="badge">Generated: {generated_at}</span>
    <span class="badge">Types: {len(types)}</span>
    <span class="badge">Findings: {total_rows}</span>
  </div>

  <div class="kpis">
    <div class="card"><div class="h">Total Estimated Monthly Cost</div><div class="v">{_fmt_usd(total_cost)}</div></div>
    <div class="card"><div class="h">Total Potential Savings</div><div class="v">{_fmt_usd(total_potential)}</div></div>
    <div class="card"><div class="h">Distinct Resource Types</div><div class="v">{len(types):,}</div></div>
    <div class="card"><div class="h">Top N Listed</div><div class="v">{top_df.shape[0]}</div></div>
  </div>

  <div class="grid2 section">
    <div class="card" id="fig_cost_by_type_wrap">{f1_html}</div>
    <div class="card" id="fig_savings_by_type_wrap">{f2_html}</div>
  </div>

  <div class="grid2 section">
    <div class="card" id="fig_top_findings_wrap">{f3_html}</div>
    <div class="card" id="fig_heatmap_wrap">{f4_html}</div>
  </div>

  <!-- Drill-down panel -->
  <div class="section">
    <h2>Drill‑down</h2>
    <div class="card" style="margin-bottom:10px;">
      <div id="active_filters">
        <span class="pill">ResourceType: <span id="flt_type">(any)</span></span>
        <span class="pill">Region: <span id="flt_region">(any)</span></span>
        <button class="btn" id="btn_reset" style="margin-left:10px;">Clear filters</button>
      </div>
    </div>
    <div class="grid2">
      <div class="card">
        <div id="drill_chart"></div>
      </div>
      <div class="card" id="drill_table_container">
        <!-- dynamic table injected here -->
        <table id="drill_table"></table>
      </div>
    </div>
    <div class="footer">
      Source CSV: <code>{os.path.basename(out_html).replace('_dashboard.html','') or 'cleanup_estimates.csv'}</code>
    </div>
  </div>
</div>

<!-- Embedded dataset for drill-down -->
<script id="__EMBED_DATA__" type="application/json">{embedded_json}</script>

<script>
(function() {{
  // Utilities
  const fmtUSD = (x) => {{
    if (x === null || x === undefined || isNaN(x)) return "$0.00";
    return "$" + Number(x).toLocaleString(undefined, {{minimumFractionDigits:2, maximumFractionDigits:2}});
  }};
  const el = (id) => document.getElementById(id);

  // Load dataset
  let DATA = [];
  try {{
    DATA = JSON.parse(document.getElementById("__EMBED_DATA__").textContent || "[]");
  }} catch (e) {{ DATA = []; }}

  // Current filters
  const FILTER = {{ type: null, region: null }};

  // Render drill-down table
  function renderTable(rows) {{
    const tbl = el("drill_table");
    if (!rows || rows.length === 0) {{
      tbl.innerHTML = "<thead><tr><th>No rows</th></tr></thead>";
      return;
    }}
    // columns
    const cols = ["ResourceType", "Name", "Resource_ID", "Region", "Estimated_Cost_USD", "Potential_Saving_USD", "Confidence", "FlaggedForReview"];
    const head = "<thead><tr>" + cols.map(c => "<th>"+c+"</th>").join("") + "</tr></thead>";
    const body = "<tbody>" + rows.map(r => {{
      return "<tr>" + cols.map(c => {{
        let v = (r[c] ?? "");
        if (c === "Estimated_Cost_USD" || c === "Potential_Saving_USD") v = fmtUSD(Number(v||0));
        return "<td>"+ String(v) +"</td>";
      }}).join("") + "</tr>";
    }}).join("") + "</tbody>";
    tbl.innerHTML = head + body;
  }}

  // Render Top-N bar for current slice
  function renderDrillChart(rows) {{
    if (!rows) rows = [];
    // Sort by Potential_Saving_USD desc and take top 20
    rows = rows.slice().sort((a,b) => (Number(b.Potential_Saving_USD||0) - Number(a.Potential_Saving_USD||0))).slice(0, 20);
    const y = rows.map(r => (r.ResourceType || "") + " | " + ((r.Name && String(r.Name).trim().length>0) ? r.Name : r.Resource_ID));
    const x = rows.map(r => Number(r.Potential_Saving_USD||0));
    const trace = {{
      type: "bar", orientation: "h",
      x: x, y: y,
      marker: {{color: "#d62728"}},
      name: "Potential saving"
    }};
    const layout = {{
      title: "Top resources in current filter",
      xaxis: {{ title: "USD" }},
      yaxis: {{ automargin: true }},
      height: Math.max(400, 22 * y.length + 120),
      margin: {{l: 220, r: 30, t: 60, b: 60}}
    }};
    Plotly.react("drill_chart", [trace], layout, {{displayModeBar: false}});
  }}

  // Apply filters to DATA
  function currentSlice() {{
    return DATA.filter(r => {{
      let ok = true;
      if (FILTER.type)   ok = ok && String(r.ResourceType||"") === FILTER.type;
      if (FILTER.region) ok = ok && String(r.Region||"") === FILTER.region;
      return ok;
    }});
  }}

  function refresh() {{
    el("flt_type").textContent   = FILTER.type   || "(any)";
    el("flt_region").textContent = FILTER.region || "(any)";
    const slice = currentSlice();
    // Default sort in table: highest potential first
    slice.sort((a,b) => (Number(b.Potential_Saving_USD||0) - Number(a.Potential_Saving_USD||0)));
    renderTable(slice);
    renderDrillChart(slice);
  }}

  function resetFilters() {{
    FILTER.type = null; FILTER.region = null;
    refresh();
  }}

  // Attach to charts
  function wirePlotClicks() {{
    // Savings by Type bar: container → inner .js-plotly-plot
    const wrapSav  = el("fig_savings_by_type_wrap");
    const plotSav  = wrapSav ? wrapSav.querySelector(".js-plotly-plot") : null;
    if (plotSav && plotSav.on) {{
      plotSav.on("plotly_click", (ev) => {{
        try {{
          const p = ev.points && ev.points[0];
          const typeClicked = p && (p.x || p.label || p.data?.x?.[p.pointIndex]);
          if (typeClicked) {{
            FILTER.type = String(typeClicked);
            refresh();
          }}
        }} catch (e) {{}}
      }});
    }}

    // Heatmap (Region × Type): y=Region, x=ResourceType
    const wrapHeat = el("fig_heatmap_wrap");
    const plotHeat = wrapHeat ? wrapHeat.querySelector(".js-plotly-plot") : null;
    if (plotHeat && plotHeat.on) {{
      plotHeat.on("plotly_click", (ev) => {{
        try {{
          const p = ev.points && ev.points[0];
          const region = p && p.y;
          const rtype  = p && p.x;
          FILTER.region = region ? String(region) : FILTER.region;
          FILTER.type   = rtype  ? String(rtype)  : FILTER.type;
          refresh();
        }} catch (e) {{}}
      }});
    }}

    // Optional: top findings bar click — filter by its ResourceType (left label "Type | Name")
    const wrapTop  = el("fig_top_findings_wrap");
    const plotTop  = wrapTop ? wrapTop.querySelector(".js-plotly-plot") : null;
    if (plotTop && plotTop.on) {{
      plotTop.on("plotly_click", (ev) => {{
        try {{
          const p = ev.points && ev.points[0];
          const label = p && p.y ? String(p.y) : "";
          const typeFromLabel = label.includes(" | ") ? label.split(" | ")[0] : "";
          if (typeFromLabel) {{
            FILTER.type = typeFromLabel;
            refresh();
          }}
        }} catch (e) {{}}
      }});
    }}
  }}

  // Init
  document.addEventListener("DOMContentLoaded", () => {{
    el("btn_reset").addEventListener("click", resetFilters);
    resetFilters();       // initial render (no filters)
    wirePlotClicks();     // make charts interactive
  }});
}})();
</script>
</body>
</html>
"""
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(html)
    return out_html


def generate_dashboard(csv_path: str, out_html: str = "cleanup_dashboard.html", top_n: int = 25, embed_js: bool = True) -> str:
    df = _read_csv_csv(csv_path)
    # Ensure 'Region' exists via Signals extraction
    if "Region" not in df.columns or df["Region"].eq("").all():
        df["Region"] = _extract_region(df)
    return build_html(df, out_html=out_html, top_n=top_n, embed_js=embed_js)


def main():
    ap = argparse.ArgumentParser(description="Generate FinOps cleanup HTML dashboard from CSV.")
    ap.add_argument("csv", help="Path to cleanup_estimates.csv")
    ap.add_argument("-o", "--out", default="cleanup_dashboard.html", help="Output HTML file")
    ap.add_argument("--top", type=int, default=25, help="Top N resources by potential saving")
    ap.add_argument("--cdn", action="store_true", help="Use CDN for plotly.js instead of embedding (smaller HTML, requires Internet)")
    args = ap.parse_args()

    try:
        out = generate_dashboard(args.csv, out_html=args.out, top_n=args.top, embed_js=not args.cdn)
        print(f"Dashboard written to {out}")
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()