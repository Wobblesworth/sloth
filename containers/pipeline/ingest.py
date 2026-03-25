"""
Ingest module — loads parsed JSONL into Elasticsearch using bulk API.
"""

import json
import logging
from pathlib import Path

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

log = logging.getLogger("sloth.ingest")


def load_index_template(es, template_path, template_name):
    """Load an index template from a JSON file if not already present."""
    with open(template_path) as f:
        template = json.load(f)
    es.indices.put_index_template(name=template_name, body=template)
    log.info(f"Index template '{template_name}' loaded")


def _deep_merge(base, override):
    """Merge override dict into base dict recursively."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def ingest_jsonl(es, jsonl_path, index_name, transform_fn, batch_size=500,
                 extra_fields=None):
    """
    Read a JSONL file, transform each line with transform_fn, and bulk ingest.

    Args:
        es: Elasticsearch client
        jsonl_path: path to the JSONL file
        index_name: target index (e.g. sloth-hayabusa-case01)
        transform_fn: function(raw_line, parsed_dict) -> ECS dict
        batch_size: number of docs per bulk request
        extra_fields: dict of additional fields to inject into every document
    """
    actions = []
    total = 0
    errors_total = 0
    error_samples = []

    def _flush(actions):
        nonlocal total, errors_total
        success, errors = bulk(es, actions, raise_on_error=False)
        total += success
        errors_total += len(errors)
        # Log first few error details for diagnostics
        for err in errors:
            if len(error_samples) < 10:
                error_samples.append(err)

    with open(jsonl_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            evt = json.loads(line)
            doc = transform_fn(line, evt)
            if extra_fields:
                _deep_merge(doc, extra_fields)
            actions.append({"_index": index_name, "_source": doc})

            if len(actions) >= batch_size:
                _flush(actions)
                actions = []

    # Flush remaining
    if actions:
        _flush(actions)

    log.info(f"Ingested {total} docs into '{index_name}', {errors_total} errors")

    if error_samples:
        log.warning(f"First {len(error_samples)} error(s) from Elasticsearch:")
        for err in error_samples:
            # err is a dict like {"index": {"_id": ..., "error": {"type": ..., "reason": ...}}}
            if isinstance(err, dict):
                for action, detail in err.items():
                    error_info = detail.get("error", {})
                    log.warning(
                        f"  {error_info.get('type', '?')}: {error_info.get('reason', '?')}"
                    )

    return total, errors_total
