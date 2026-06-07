# Bug Bounty Framework

Automated reconnaissance and vulnerability hunting framework with AI-assisted reporting.

## Pipeline

`
target → recon → hunt → api_hack → secrets → report
`

## Quick Start

`ash
python main.py example.com --authorized
`

## Requirements

- Python 3.12+
- Go tools: subfinder, httpx, assetfinder (others optional)
- Ollama (optional, for AI report drafting)
