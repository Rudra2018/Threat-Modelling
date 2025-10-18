#!/usr/bin/env python3
"""
Threat Modeling Analysis Runner
Runs the enhanced threat modeling tool on all projects in the directory
"""

import asyncio
import sys
import os
from pathlib import Path
import yaml
from enhanced_threat_modelling import main as run_threat_analysis

def load_config(config_path: str = "config.yaml"):
    """Load configuration from YAML file."""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        print(f"Error loading config: {e}")
        return None

def get_claude_api_key():
    """Get Claude API key from environment or config."""
    # First try environment variable
    api_key = os.getenv('CLAUDE_API_KEY')
    if api_key:
        return api_key

    # Then try config file
    config = load_config()
    if config and 'claude_api_key' in config:
        api_key = config['claude_api_key']
        if api_key != "YOUR_CLAUDE_API_KEY_HERE":
            return api_key

    # Ask user for API key
    print("Claude API key not found in environment or config.")
    print("Please get your API key from: https://console.anthropic.com/")
    api_key = input("Enter your Claude API key: ").strip()

    if not api_key:
        print("Error: No API key provided")
        sys.exit(1)

    return api_key

async def run_analysis():
    """Run threat modeling analysis on all projects."""
    current_dir = Path.cwd()

    # Get API key
    claude_api_key = get_claude_api_key()

    # Find all project directories
    project_dirs = [
        d for d in current_dir.iterdir()
        if d.is_dir() and not d.name.startswith('.') and d.name != 'threat_reports'
        and any(f.suffix in ['.py', '.js', '.java', '.php', '.go'] for f in d.rglob('*') if f.is_file())
    ]

    if not project_dirs:
        print("No project directories found with code files")
        return

    print(f"Found {len(project_dirs)} project directories:")
    for proj in project_dirs:
        print(f"  - {proj.name}")

    # Override sys.argv for the threat modeling script
    original_argv = sys.argv.copy()

    try:
        for project_dir in project_dirs:
            print(f"\n{'='*60}")
            print(f"Running threat analysis on: {project_dir.name}")
            print(f"{'='*60}")

            # Set up arguments for the threat modeling script
            sys.argv = [
                'enhanced_threat_modelling.py',
                '--project-path', str(project_dir),
                '--claude-api-key', claude_api_key,
                '--output-dir', str(current_dir / 'threat_reports')
            ]

            # Run the analysis
            await run_threat_analysis()

    finally:
        # Restore original argv
        sys.argv = original_argv

    print(f"\n{'='*60}")
    print("All analyses complete!")
    print(f"Reports saved to: {current_dir / 'threat_reports'}")
    print(f"{'='*60}")

if __name__ == "__main__":
    try:
        asyncio.run(run_analysis())
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
    except Exception as e:
        print(f"Error during analysis: {e}")
        import traceback
        traceback.print_exc()