"""Mithridate CLI.

Commands:
  mithridate ingest     — pull sources → RawDocument → store
  mithridate run        — screen + extract + store (requires ANTHROPIC_API_KEY)
  mithridate eval       — run the red-team eval harness
  mithridate export     — emit STIX 2.1 bundle
  mithridate status     — show store statistics
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

# Load .env from the project root (or cwd) before any env var is read
load_dotenv()

if TYPE_CHECKING:
    from mithridate.store.db import Store

# Absolute path to the project root (two levels up from mithridate/cli/)
_PROJECT_ROOT = Path(__file__).parent.parent.parent

app = typer.Typer(
    name="mithridate",
    help="Hardened threat-intelligence agent — treats all ingested intel as hostile input.",
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)

_DEFAULT_DB = _PROJECT_ROOT / "mithridate.db"


def _get_store(db: Path) -> "Store":
    from mithridate.store.db import Store
    return Store(db_path=db)


# ---------------------------------------------------------------------------
# ingest
# ---------------------------------------------------------------------------


@app.command()
def ingest(
    source: str = typer.Option("cisa_kev", "--source", "-s", help="Source to fetch (cisa_kev)"),
    db: Path = typer.Option(_DEFAULT_DB, "--db", help="Path to SQLite database"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Fetch raw intel from OSINT sources and store raw documents."""
    _setup_logging(verbose)
    store = _get_store(db)

    if source == "cisa_kev":
        from mithridate.ingest.cisa_kev import CisaKevSource
        src = CisaKevSource()
    else:
        err_console.print(f"[red]Unknown source: {source}. Available: cisa_kev[/red]")
        raise typer.Exit(1)

    console.print(f"[cyan]Fetching from {source}…[/cyan]")
    documents = src.fetch()
    console.print(f"[green]Fetched {len(documents)} documents[/green]")

    new_count = 0
    for doc in documents:
        if not store.document_exists(doc.id):
            store.save_document(doc)
            new_count += 1

    console.print(f"[green]Stored {new_count} new documents ({len(documents) - new_count} duplicates skipped)[/green]")
    store.close()


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


@app.command()
def run(
    db: Path = typer.Option(_DEFAULT_DB, "--db", help="Path to SQLite database"),
    model: str = typer.Option("claude-haiku-4-5-20251001", "--model", "-m", help="Model for extraction (default: Haiku for cost efficiency)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Screen only, skip LLM extraction"),
    limit: int = typer.Option(0, "--limit", "-n", help="Max documents to process (0 = all)"),
    workers: int = typer.Option(5, "--workers", "-w", help="Concurrent API calls (default 5; reduce if hitting rate limits)"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Screen and extract intel from stored raw documents."""
    _setup_logging(verbose)

    store = _get_store(db)

    if dry_run:
        _run_dry(store, limit)
        store.close()
        return

    from datetime import datetime

    from mithridate.agent.planner import Planner
    from mithridate.agent.providers.anthropic import AnthropicProvider
    from mithridate.models import Provenance, RawDocument

    provider = AnthropicProvider(model=model)
    planner = Planner(provider=provider, store=store)

    # Load unprocessed documents from the store
    conn = store._conn
    rows = conn.execute(
        """
        SELECT id, text, source_id, url, fetched_at, trust_tier
        FROM raw_documents
        WHERE id NOT IN (SELECT doc_id FROM intel_records)
        AND id NOT IN (SELECT doc_id FROM quarantined_docs)
        ORDER BY fetched_at ASC
        """
        + (f" LIMIT {limit}" if limit else "")
    ).fetchall()

    if not rows:
        console.print("[yellow]No unprocessed documents found. Run 'mithridate ingest' first.[/yellow]")
        store.close()
        return

    documents = []
    for row in rows:
        doc = RawDocument(
            id=row["id"],
            text=row["text"],
            provenance=Provenance(
                source_id=row["source_id"],
                url=row["url"],
                fetched_at=datetime.fromisoformat(row["fetched_at"]),
                trust_tier=row["trust_tier"],  # type: ignore[arg-type]
            ),
        )
        documents.append(doc)

    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
        TimeRemainingColumn,
    )

    total = len(documents)
    console.print(f"[cyan]Processing {total} documents (gate → {workers}× parallel batch-extract)…[/cyan]")

    # Live counters shared across callbacks
    live: dict[str, int] = {"iocs": 0, "techs": 0, "quarantined": 0}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    ) as progress:
        gate_task = progress.add_task("[cyan]Gate", total=total)
        extract_task = progress.add_task("[green]Extract", total=total)

        def on_gate_done() -> None:
            progress.advance(gate_task)
            q = live["quarantined"]
            progress.update(
                gate_task,
                description=f"[cyan]Gate  [dim](quarantined: {q})[/dim]",
            )

        def on_extract_done(n: int, iocs: int, techs: int) -> None:
            live["iocs"] += iocs
            live["techs"] += techs
            progress.advance(extract_task, n)
            progress.update(
                extract_task,
                description=f"[green]Extract  [dim](IOCs: {live['iocs']}  techs: {live['techs']})[/dim]",
            )

        # Patch quarantine counter into on_gate_done via the run_batch callback chain
        _orig_on_gate = on_gate_done

        def on_gate_done_with_q() -> None:  # type: ignore[misc]
            _orig_on_gate()

        run_meta = planner.run_batch(
            documents,
            on_gate_done=on_gate_done,
            on_extract_done=on_extract_done,
            max_workers=workers,
        )
        live["quarantined"] = run_meta.docs_quarantined
        progress.update(gate_task, description=f"[cyan]Gate  [dim](quarantined: {live['quarantined']})[/dim]")

    console.print("\n[bold green]Run complete[/bold green]")
    console.print(f"  Processed  : {run_meta.docs_processed}")
    console.print(f"  Quarantined: {run_meta.docs_quarantined}")
    console.print(f"  IOCs extracted : {run_meta.iocs_extracted}")
    console.print(f"  Techniques mapped: {run_meta.techniques_mapped}")
    store.close()


def _run_dry(store: "Store", limit: int) -> None:
    """Screen-only run — no LLM calls, just gate verdicts."""
    from datetime import datetime

    from mithridate.gate.screener import screen
    from mithridate.models import Provenance, RawDocument

    conn = store._conn
    rows = conn.execute(
        "SELECT id, text, source_id, url, fetched_at, trust_tier FROM raw_documents"
        + (f" LIMIT {limit}" if limit else "")
    ).fetchall()

    if not rows:
        console.print("[yellow]No documents in store.[/yellow]")
        return

    stats: dict[str, int] = {"clean": 0, "suspect": 0, "quarantine": 0}
    for row in rows:
        doc = RawDocument(
            id=row["id"],
            text=row["text"],
            provenance=Provenance(
                source_id=row["source_id"],
                url=row["url"],
                fetched_at=datetime.fromisoformat(row["fetched_at"]),
                trust_tier=row["trust_tier"],  # type: ignore[arg-type]
            ),
        )
        _, result = screen(doc)
        stats[result.verdict] += 1
        store.save_screening_result(result)
        if result.verdict == "quarantine":
            store.quarantine_document(doc.id, result.signals)

    console.print("[bold]Dry-run screening results:[/bold]")
    for verdict, count in stats.items():
        colour = {"clean": "green", "suspect": "yellow", "quarantine": "red"}[verdict]
        console.print(f"  [{colour}]{verdict}: {count}[/{colour}]")


# ---------------------------------------------------------------------------
# eval
# ---------------------------------------------------------------------------


@app.command(name="eval")
def eval_cmd(
    corpus_dir: Path = typer.Option(_PROJECT_ROOT / "eval/corpora", "--corpus", "-c"),
    output_dir: Path = typer.Option(_PROJECT_ROOT / "eval/results", "--output", "-o"),
    model: str = typer.Option("claude-sonnet-4-6", "--model", "-m"),
    gate_only: bool = typer.Option(False, "--gate-only", help="Measure gate metrics only, no LLM"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Run the red-team evaluation harness and write the metrics table."""
    _setup_logging(verbose)

    # Import here to keep startup fast
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from eval.harness import EvalHarness

    harness = EvalHarness(
        corpus_dir=corpus_dir,
        output_dir=output_dir,
        model=model,
        gate_only=gate_only,
    )
    results = harness.run()
    harness.print_table(results)
    harness.save_results(results)


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------


@app.command()
def export(
    db: Path = typer.Option(_DEFAULT_DB, "--db"),
    output: Path = typer.Option(Path("stix_bundle.json"), "--output", "-o"),
    stix: bool = typer.Option(False, "--stix", is_flag=True, help="Emit STIX 2.1 bundle (default format)"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Export the intel store as a STIX 2.1 bundle."""
    _setup_logging(verbose)
    from datetime import datetime

    from mithridate.models import IOC, IntelRecord, ScreeningResult, TechniqueMapping
    from mithridate.store.db import Store
    from mithridate.store.stix_export import export_to_file

    store = Store(db_path=db)

    # Reconstruct IntelRecord objects from the store for export
    records: list[IntelRecord] = []
    ioc_rows = store.get_recent_iocs(limit=10000)
    tech_rows = store.get_recent_techniques(limit=10000)

    if not ioc_rows and not tech_rows:
        console.print("[yellow]No intel records found. Run 'mithridate run' first.[/yellow]")
        store.close()
        return

    iocs = []
    for row in ioc_rows:
        try:
            iocs.append(IOC(
                type=row["type"],  # type: ignore[arg-type]
                value=row["value"],  # type: ignore[arg-type]
                confidence=float(row["confidence"]),  # type: ignore[arg-type]
                source_doc=row["source_doc"],  # type: ignore[arg-type]
                first_seen=datetime.fromisoformat(row["first_seen"]),  # type: ignore[arg-type]
            ))
        except Exception:
            pass

    techs = []
    for row in tech_rows:
        try:
            techs.append(TechniqueMapping(
                technique_id=row["technique_id"],  # type: ignore[arg-type]
                technique_name=row["technique_name"],  # type: ignore[arg-type]
                confidence=float(row["confidence"]),  # type: ignore[arg-type]
                rationale=row["rationale"],  # type: ignore[arg-type]
            ))
        except Exception:
            pass

    dummy_screening = ScreeningResult(doc_id="export", verdict="clean", signals=[], score=0.0)
    record = IntelRecord(
        doc_id="export",
        run_id="export",
        iocs=iocs,
        techniques=techs,
        screening=dummy_screening,
    )
    records = [record]

    export_to_file(records, output)
    console.print(f"[green]Exported {len(iocs)} IOCs and {len(techs)} techniques to {output}[/green]")
    store.close()


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


@app.command()
def status(
    db: Path = typer.Option(_DEFAULT_DB, "--db"),
) -> None:
    """Show intel store statistics."""
    store = _get_store(db)
    stats = store.get_stats()
    store.close()

    table = Table(title="Mithridate Store")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", justify="right", style="green")
    for key, val in stats.items():
        table.add_row(key.replace("_", " ").title(), str(val))
    console.print(table)

    quarantined = _get_store(db).get_quarantined_docs()
    if quarantined:
        console.print(f"\n[yellow]Quarantined documents ({len(quarantined)}):[/yellow]")
        for q in quarantined[:5]:
            console.print(f"  {q['doc_id'][:12]}… — {q['reason'][:80]}")
        if len(quarantined) > 5:
            console.print(f"  … and {len(quarantined) - 5} more")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


if __name__ == "__main__":
    app()
