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


def ingest_jsonl(es, jsonl_path, index_name, transform_fn, batch_size=500):
    """
    Read a JSONL file, transform each line with transform_fn, and bulk ingest.

    Args:
        es: Elasticsearch client
        jsonl_path: path to the JSONL file
        index_name: target index (e.g. sloth-hayabusa-case01)
        transform_fn: function(raw_line, parsed_dict) -> ECS dict
        batch_size: number of docs per bulk request
    """
    actions = []
    total = 0
    errors_total = 0

    with open(jsonl_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            evt = json.loads(line)
            doc = transform_fn(line, evt)
            actions.append({"_index": index_name, "_source": doc})

            if len(actions) >= batch_size:
                success, errors = bulk(es, actions, raise_on_error=False)
                total += success
                errors_total += len(errors)
                actions = []

    # Flush remaining
    if actions:
        success, errors = bulk(es, actions, raise_on_error=False)
        total += success
        errors_total += len(errors)

    log.info(f"Ingested {total} docs into '{index_name}', {errors_total} errors")
    return total, errors_total
