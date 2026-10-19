from setuptools import setup, find_packages
from pathlib import Path

# Lee el contenido del README.md para la página oficial de PyPI
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8") if (this_directory / "README.md").exists() else ""

setup(
    name="odoo-safe-mcp",
    version="2.0.0",
    author="Odoo Safe MCP",
    author_email="soporte@odoosafemcp.stream",
    description="Firewall y Servidor MCP seguro para conectar Agentes de IA a Odoo ERP con aprobación humana (Human-in-the-Loop).",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://odoosafemcp.stream",
    project_urls={
        "Bug Tracker": "https://github.com/makelele29/odoo-safe-mcp/issues",
        "Documentation": "https://odoosafemcp.stream/#how",
        "Get Pro API Key": "https://odoosafemcp.stream/#pricing",
    },
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.10",
    install_requires=[
        "mcp>=1.2.0",          # SDK oficial de Model Context Protocol
        "httpx>=0.27.0",       # Cliente HTTP asíncrono para JSON-RPC y Cloud Proxy
        "pydantic>=2.6.0",     # Validación estricta de payloads de Odoo
        "python-dotenv>=1.0.0" # Carga de variables de entorno locales
    ],
    entry_points={
        "console_scripts": [
            # Permite ejecutar el servidor escribiendo 'odoo-safe-mcp' en terminal
            "odoo-safe-mcp=odoo_safe_mcp.server:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Office/Business :: Financial :: Accounting",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords="odoo, erp, mcp, model-context-protocol, ai-agents, claude, security, human-in-the-loop",
)
