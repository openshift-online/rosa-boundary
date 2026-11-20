"""Compare one quiescent attempt's current S3 workspace to a private cutoff manifest.

Evidence indexes refer to the original manifest array (zero based). This is a
reader comparison of observed versions, not an atomic snapshot or close receipt.

The comparator itself lives in ``lambda/reap-investigations/workspace_verification.py``
so this operator script and the investigation reaper verify identically. This
script keeps the task-attempt escrow assumptions; the reaper owns its own
close-attempt prefix.
"""

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lambda' / 'reap-investigations'))

from workspace_verification import (  # noqa: E402  (path set above)
    DEST,
    UUID,
    ComparisonError,
    Reason,
    compare,
    parse_manifest,
    unique_fields,
)

__all__ = ['DEST', 'UUID', 'ComparisonError', 'Reason', 'compare', 'parse_manifest',
           'unique_fields', 'save', 'main']


def save(evidence, path):
    # Publish complete evidence only, mode 0600, never replace an existing file.
    with tempfile.NamedTemporaryFile(dir=path.parent, mode='w', encoding='utf-8') as out:
        json.dump(evidence, out)
        out.write('\n')
        out.flush()
        os.link(out.name, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace-uri', required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    try:
        import boto3

        evidence = compare(boto3.client('s3'), args.workspace_uri, args.manifest.read_bytes())
        save(evidence, args.evidence)
    except ComparisonError as exc:
        code = exc.reason.value
    except Exception:
        # Neither third-party exception names nor their messages are public.
        code = 'verification_error'
    else:
        return 0
    print(f'Workspace comparison unsuccessful ({code}).', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
