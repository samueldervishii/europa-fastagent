"""
Centralized console configuration for MCP Agent.

This module provides shared console instances for consistent output handling:
- console: Main console for general output
- error_console: Error console for application errors (writes to stderr)
- server_console: Special console for MCP server output
"""

import os

from rich.console import Console

# Determine color system based on environment
# If TERM=dumb, force color support anyway (user likely has a capable terminal)
force_colors = os.getenv("TERM") == "dumb" or os.getenv("FORCE_COLOR") == "1"

# Main console for general output
console = Console(
    color_system="truecolor" if force_colors else "auto",
    force_terminal=True,  # Force terminal features even if not detected
    force_interactive=True,  # Enable interactive features
    legacy_windows=False,  # Disable legacy Windows mode
)

# Error console for application errors
error_console = Console(
    stderr=True,
    style="bold red",
)

# Special console for MCP server output
# This could have custom styling to distinguish server messages
server_console = Console(
    # Not stderr since we want to maintain output ordering with other messages
    style="dim blue",  # Or whatever style makes server output distinct
)
