#!/usr/bin/env python3
"""Seed credential-free Bedrock defaults as sre, preserving user configuration."""

import json
import os
import sys
from pathlib import Path
import tempfile


def seed(path, defaults):
    """Create missing defaults atomically; never replace existing user settings."""
    # JSONC is user-owned too. Do not shadow it with a new JSON configuration.
    if path.exists() or path.with_suffix('.jsonc').exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    # Link an already-complete file without overwriting a concurrent writer.
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            output.write(defaults if isinstance(defaults, str)
                         else json.dumps(defaults, indent=2))
            output.write('\n')
        try:
            os.link(temporary, path)
        except FileExistsError:
            pass
    finally:
        os.unlink(temporary)


def main():
    """Use the deployment's approved model and ambient ECS task-role credentials."""
    if os.environ.get('BOUNDARY_AI_USE_BEDROCK',
                      os.environ.get('CLAUDE_CODE_USE_BEDROCK', '1')) != '1':
        return
    home = Path.home()
    region = (os.environ.get('AWS_REGION')
              or os.environ.get('AWS_DEFAULT_REGION') or 'us-east-1')
    codex = Path(os.environ.get('CODEX_HOME', str(home / '.codex')))
    # Codex's native Runtime provider signs Responses requests using the AWS
    # SDK chain. Claude model IDs are not compatible with that API.
    codex_config = 'model_provider = "amazon-bedrock-runtime"\n'
    codex_model = os.environ.get('BOUNDARY_CODEX_BEDROCK_MODEL', '').strip()
    if codex_model:
        codex_config += 'model = ' + json.dumps(codex_model) + '\n'
    codex_config += ('\n[model_providers.amazon-bedrock-runtime.aws]\nregion = '
                     + json.dumps(region) + '\n')
    seed(codex / 'config.toml', codex_config)
    model = os.environ.get('ANTHROPIC_MODEL', '').strip()
    if not model:
        print('Warning: ANTHROPIC_MODEL is unset; pi/OpenCode defaults not initialized',
              file=sys.stderr)
        return
    agent = Path(os.environ.get('PI_CODING_AGENT_DIR', str(home / '.pi/agent')))
    config = Path(os.environ.get('XDG_CONFIG_HOME', str(home / '.config')))
    seed(agent / 'settings.json', {
        'defaultProvider': 'amazon-bedrock',
        'defaultModel': model,
    })
    seed(config / 'opencode/opencode.json', {
        '$schema': 'https://opencode.ai/config.json',
        'model': 'amazon-bedrock/' + model,
        'providers': {'amazon-bedrock': {'settings': {
            'region': region,
        }}},
    })


if __name__ == '__main__':
    main()
