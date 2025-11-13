import os
from pathlib import Path

import typer
from rich.console import Console
from rich.prompt import Confirm

from ..setup_wizard import run_setup_wizard

app = typer.Typer()
console = Console()

FASTAGENT_CONFIG_TEMPLATE = """
# FastAgent Configuration File

# Default Model Configuration:
# 
# Takes format:
#   <provider>.<model_string>.<reasoning_effort?> (e.g. anthropic.claude-3-5-sonnet-20241022 or openai.o3-mini.low)
# Accepts aliases for Anthropic Models: haiku, haiku3, sonnet, sonnet35, opus, opus3
# and OpenAI Models: gpt-4.1, gpt-4.1-mini, o1, o1-mini, o3-mini
#
# If not specified, defaults to "haiku". 
# Can be overriden with a command line switch --model=<model>, or within the Agent constructor.

default_model: haiku

# Logging and Console Configuration:
logger:
    # level: "debug" | "info" | "warning" | "error"
    # type: "none" | "console" | "file" | "http"
    # path: "/path/to/logfile.jsonl"

    
    # Switch the progress display on or off
    progress_display: true

    # Show chat User/Assistant messages on the console
    show_chat: true
    # Show tool calls on the console
    show_tools: true
    # Truncate long tool responses on the console 
    truncate_tools: true

# MCP Servers
mcp:
    servers:
        fetch:
            command: "uvx"
            args: ["mcp-server-fetch"]
        filesystem:
            command: "npx"
            args: ["-y", "@modelcontextprotocol/server-filesystem", "."]

"""

FASTAGENT_SECRETS_TEMPLATE = """
# FastAgent Secrets Configuration
# WARNING: Keep this file secure and never commit to version control

# Alternatively set OPENAI_API_KEY, ANTHROPIC_API_KEY or other environment variables. 
# Keys in the configuration file override environment variables.

openai:
    api_key: <your-api-key-here>
anthropic:
    api_key: <your-api-key-here>
deepseek:
    api_key: <your-api-key-here>
openrouter:
    api_key: <your-api-key-here>


# Example of setting MCP Server environment variables
mcp:
    servers:
        brave:
            env:
                BRAVE_API_KEY: <your_api_key_here>
        tavily:
            env:
                TAVILY_API_KEY: <your_tavily_api_key_here>

"""

GITIGNORE_TEMPLATE = """
# FastAgent secrets file
fastagent.secrets.yaml

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual Environment
.env
.venv
env/
venv/
ENV/

# IDE
.idea/
.vscode/
*.swp
*.swo
"""

AGENT_EXAMPLE_TEMPLATE = """
import asyncio
from mcp_agent.core.fastagent import FastAgent

# Create the application
fast = FastAgent("fast-agent example")


# Define the agent
@fast.agent(instruction="You are a helpful AI Agent")
async def main():
    # use the --model command line switch or agent arguments to change model
    async with fast.run() as agent:
        await agent.interactive()


if __name__ == "__main__":
    asyncio.run(main())

"""


def find_gitignore(path: Path) -> bool:
    """Check if a .gitignore file exists in this directory or any parent."""
    current = path
    while current != current.parent:  # Stop at root directory
        if (current / ".gitignore").exists():
            return True
        current = current.parent
    return False


def _validate_template_content(content: str, filename: str) -> None:
    """Validate that content is a template with placeholders, not actual secrets.

    Security: This function ensures we never write actual secrets to files.
    Templates must contain placeholder patterns like '<your-api-key-here>'.

    Raises:
        ValueError: If content appears to contain actual secrets instead of placeholders
    """
    # Check if this is a sensitive file that should only contain templates
    is_sensitive_filename = any(keyword in filename.lower() for keyword in ["secret", "key", "credential", "password", "token"])

    if not is_sensitive_filename:
        return  # Non-sensitive files don't need validation

    # Sensitive files MUST contain placeholder patterns
    has_placeholder_pattern = (
        "<your" in content.lower()
        or "<api" in content.lower()
        or "your-api-key-here" in content.lower()
        or "your_api_key_here" in content.lower()
    )

    if not has_placeholder_pattern:
        # This might contain actual secrets - reject it
        raise ValueError(
            f"Refusing to write {filename}: Content appears to contain actual secrets. "
            f"This function only writes templates with placeholders like '<your-api-key-here>'."
        )


def create_file(path: Path, content: str, force: bool = False) -> bool:
    """Create a file with given content if it doesn't exist or force is True.

    Security Note: This function ONLY writes configuration templates containing
    placeholder values (e.g., '<your-api-key-here>'), never actual secrets.
    Content is validated before writing to ensure it's a template.
    Files are protected with restrictive permissions (0o600) for sensitive content.

    Args:
        path: Path to the file to create
        content: Template content (must contain placeholders for sensitive files)
        force: If True, overwrite existing files without asking

    Returns:
        True if file was created/written, False if skipped

    Raises:
        ValueError: If attempting to write actual secrets instead of templates
    """
    if path.exists() and not force:
        should_overwrite = Confirm.ask(
            f"[yellow]Warning:[/yellow] {path} already exists. Overwrite?",
            default=False,
        )
        if not should_overwrite:
            console.print(f"Skipping {path}")
            return False

    # Security: Validate that we're only writing templates, not actual secrets
    # This protects against accidentally storing real credentials
    try:
        _validate_template_content(content, path.name)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        return False

    # Set restrictive permissions for sensitive files BEFORE writing
    # This ensures the file is created with secure permissions from the start
    is_sensitive = any(keyword in path.name.lower() for keyword in ["secret", "key", "credential", "password", "token"])

    # For sensitive files, create with restrictive permissions first
    if is_sensitive:
        # Create or truncate file with secure permissions
        path.touch(mode=0o600, exist_ok=True)

    # Write template content (already validated to contain only placeholders)
    # codeql[py/clear-text-storage-sensitive-data]: False positive - this writes
    # configuration templates with placeholder values like '<your-api-key-here>',
    # never actual secrets. Content is validated by _validate_template_content().
    path.write_text(content.strip() + "\n")

    if is_sensitive:
        try:
            # Ensure permissions are still correct after write
            os.chmod(path, 0o600)  # Read/write for owner only
            console.print(f"[green]Created[/green] {path} [dim](permissions: 600)[/dim]")
        except Exception:
            # If chmod fails (e.g., on Windows), just warn but don't fail
            console.print(f"[green]Created[/green] {path} [yellow](warning: could not set permissions)[/yellow]")
    else:
        console.print(f"[green]Created[/green] {path}")

    return True


@app.callback(invoke_without_command=True)
def init(
    config_dir: str = typer.Option(
        ".",
        "--config-dir",
        "-c",
        help="Directory where configuration files will be created",
    ),
    force: bool = typer.Option(False, "--force", "-f", help="Force overwrite existing files"),
) -> None:
    """Initialize a new FastAgent project with configuration files and example agent."""

    config_path = Path(config_dir).resolve()
    if not config_path.exists():
        should_create = Confirm.ask(f"Directory {config_path} does not exist. Create it?", default=True)
        if should_create:
            config_path.mkdir(parents=True)
        else:
            raise typer.Abort()

    # Check for existing .gitignore
    needs_gitignore = not find_gitignore(config_path)

    console.print("\n[bold]fast-agent setup[/bold]\n")
    console.print("This will create the following files:")
    console.print(f"  - {config_path}/fastagent.config.yaml")
    console.print(f"  - {config_path}/fastagent.secrets.yaml")
    console.print(f"  - {config_path}/agent.py")
    if needs_gitignore:
        console.print(f"  - {config_path}/.gitignore")

    if not Confirm.ask("\nContinue?", default=True):
        raise typer.Abort()

    # Create configuration files
    created = []
    if create_file(config_path / "fastagent.config.yaml", FASTAGENT_CONFIG_TEMPLATE, force):
        created.append("fastagent.yaml")

    if create_file(config_path / "fastagent.secrets.yaml", FASTAGENT_SECRETS_TEMPLATE, force):
        created.append("fastagent.secrets.yaml")

    if create_file(config_path / "agent.py", AGENT_EXAMPLE_TEMPLATE, force):
        created.append("agent.py")

    # Only create .gitignore if none exists in parent directories
    if needs_gitignore and create_file(config_path / ".gitignore", GITIGNORE_TEMPLATE, force):
        created.append(".gitignore")

    if created:
        console.print("\n[green]Setup completed successfully![/green]")
        if "fastagent.secrets.yaml" in created:
            console.print("\n[yellow]Important:[/yellow] Remember to:")
            console.print(
                "1. Add your API keys to fastagent.secrets.yaml, or set environment variables. Use [cyan]fast-agent check[/cyan] to verify."
            )
            console.print("2. Keep fastagent.secrets.yaml secure and never commit it to version control")
            console.print("3. Update fastagent.config.yaml to set a default model (currently system default is 'haiku')")
        console.print("\nTo get started, run:")
        console.print("  uv run agent.py")
    else:
        console.print("\n[yellow]No files were created or modified.[/yellow]")


@app.command("keys")
def keys():
    """Interactive setup wizard for API keys (Gemini, Tavily)."""
    run_setup_wizard()
