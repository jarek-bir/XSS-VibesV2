#!/usr/bin/env python3
"""
XSS Vibes - CLI Integration for New AI Tools
Adds the AI context extractor, DOM fuzzer, and report generator to the main CLI
"""

import click
from colorama import Fore, Style

# Import the new AI tools
from .ai_domfuzz import AIDOMFuzzer
from ..scripts.ai_context_extractor import AIContextExtractor
from ..scripts.report_gen import ReportGenerator, TestResult, ScanSession


@click.command("ai-context")
@click.argument("target")
@click.option("--output", "-o", help="Output report file")
@click.option(
    "--format", "-f", choices=["text", "json"], default="text", help="Output format"
)
@click.option(
    "--extensions",
    "-e",
    multiple=True,
    default=[".js", ".jsx", ".ts", ".tsx", ".vue", ".html"],
    help="File extensions to analyze",
)
def ai_context(target, output, format, extensions):
    """🧠 AI Context Extractor - analyzes .js files and suggests templates + context"""

    click.echo(f"{Fore.CYAN}🧠 XSS Vibes - AI Context Extractor{Style.RESET_ALL}")
    click.echo("=" * 50)

    extractor = AIContextExtractor()

    from pathlib import Path

    target_path = Path(target)

    if target_path.is_file():
        click.echo(f"📄 Analyzing file: {target}")
        result = extractor.analyze_file(target)
    elif target_path.is_dir():
        click.echo(f"📁 Analyzing directory: {target}")
        result = extractor.analyze_directory(target, list(extensions))
    else:
        click.echo(f"{Fore.RED}❌ Target not found: {target}{Style.RESET_ALL}")
        return

    if format == "json":
        import json

        output_content = json.dumps(result, indent=2, ensure_ascii=False)
    else:
        output_content = extractor.generate_report(result, output)

    if output and format == "json":
        with open(output, "w", encoding="utf-8") as f:
            f.write(output_content)
        click.echo(f"📄 Report saved to: {output}")
    elif not output:
        click.echo("\n" + output_content)

    # Show quick summary
    if isinstance(result, dict) and "summary" in result:
        # Directory analysis
        click.echo(f"\n{Fore.CYAN}🎯 Quick Summary:{Style.RESET_ALL}")
        click.echo(f"   Files analyzed: {result['analyzed_files']}")
        click.echo(f"   High risk files: {len(result['summary']['high_risk_files'])}")
        top_template = (
            max(result["summary"]["templates_suggested"].items(), key=lambda x: x[1])
            if result["summary"]["templates_suggested"]
            else None
        )
        if top_template:
            click.echo(f"   Top template: {top_template[0]} ({top_template[1]} files)")
    elif isinstance(result, dict) and "risk_score" in result:
        # Single file analysis
        click.echo(f"\n{Fore.CYAN}🎯 Quick Summary:{Style.RESET_ALL}")
        click.echo(
            f"   Risk score: {result['risk_score']['score']}/100 ({result['risk_score']['level']})"
        )
        if result["suggested_templates"]:
            click.echo(
                f"   Best template: {result['suggested_templates'][0]['template']}"
            )


@click.command("ai-domfuzz")
@click.option("--input", "-i", help="JavaScript file to analyze")
@click.option("--content", "-c", help="Content string to analyze")
@click.option("--max-payloads", "-m", default=50, help="Maximum payloads to generate")
@click.option(
    "--format",
    "-f",
    default="json",
    type=click.Choice(["json", "txt", "burp", "curl"]),
    help="Output format",
)
@click.option("--output", "-o", help="Output file")
@click.option("--data-dir", "-d", help="Payload data directory")
def ai_domfuzz_cmd(input, content, max_payloads, format, output, data_dir):
    """🧠 AI DOM Fuzzer - automatically selects optimal payloads for useEffect, shadowRoot, eval, etc."""

    click.echo(f"{Fore.CYAN}🧠 XSS Vibes - AI DOM Fuzzer{Style.RESET_ALL}")
    click.echo("=" * 50)

    if input:
        with open(input, "r", encoding="utf-8") as f:
            analyze_content = f.read()
    elif content:
        analyze_content = content
    else:
        click.echo(
            f"{Fore.RED}❌ No input provided. Use --input or --content{Style.RESET_ALL}"
        )
        return

    fuzzer = AIDOMFuzzer(data_dir)
    result = fuzzer.fuzz_content(analyze_content, max_payloads)

    # Show summary
    click.echo(f"{Fore.CYAN}📊 Analysis Results:{Style.RESET_ALL}")
    click.echo(f"   Detected contexts: {len(result['detected_contexts'])}")
    click.echo(f"   Selected payloads: {result['payload_count']}")
    click.echo(f"   Coverage score: {result['coverage_score']:.1f}%")

    # Show top contexts
    if result["detected_contexts"]:
        click.echo(f"\n{Fore.CYAN}🎯 Top Contexts:{Style.RESET_ALL}")
        for ctx in result["detected_contexts"][:5]:
            click.echo(
                f"   {ctx['context']} (priority: {ctx['priority']}, matches: {ctx['matches']})"
            )

    # Show recommendations
    click.echo(f"\n{Fore.CYAN}💡 Recommendations:{Style.RESET_ALL}")
    for rec in result["recommendations"]:
        click.echo(f"   {rec}")

    # Export results
    output_content = fuzzer.export_payloads(result, format, output)

    if output:
        click.echo(f"\n{Fore.GREEN}📄 Results saved to: {output}{Style.RESET_ALL}")
    else:
        click.echo(f"\n{Fore.CYAN}📋 Generated Payloads ({format}):{Style.RESET_ALL}")
        click.echo("=" * 50)
        if len(output_content) > 1000:  # Truncate long output
            click.echo(output_content[:1000] + "\n... (truncated)")
        else:
            click.echo(output_content)


@click.command("report-gen")
@click.option("--results-file", "-r", required=True, help="JSON file with test results")
@click.option("--output-dir", "-o", default="reports", help="Output directory")
@click.option(
    "--report-type",
    "-t",
    type=click.Choice(["comprehensive", "template", "payload"]),
    default="comprehensive",
    help="Type of report to generate",
)
@click.option("--template", help="Template name for template-specific report")
@click.option("--payload", help="Payload for payload-specific report")
def report_gen_cmd(results_file, output_dir, report_type, template, payload):
    """📊 Advanced Report Generator - generates HTML reports per template, per payload, per result"""

    click.echo(f"{Fore.CYAN}📊 XSS Vibes - Advanced Report Generator{Style.RESET_ALL}")
    click.echo("=" * 50)

    # Load results
    import json

    try:
        with open(results_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        click.echo(f"{Fore.RED}❌ Cannot load results file: {e}{Style.RESET_ALL}")
        return

    # Convert to TestResult objects
    results = []
    try:
        for result_data in data.get("results", []):
            result = TestResult(**result_data)
            results.append(result)
    except Exception as e:
        click.echo(f"{Fore.RED}❌ Invalid results format: {e}{Style.RESET_ALL}")
        return

    # Create session object
    session_data = data.get("session", {})
    try:
        session = ScanSession(**session_data)
    except Exception as e:
        click.echo(
            f"{Fore.YELLOW}⚠️ Invalid session data, using defaults: {e}{Style.RESET_ALL}"
        )
        session = ScanSession(
            session_id="unknown",
            start_time="2025-01-01T00:00:00",
            end_time=None,
            target_urls=[],
            total_tests=len(results),
            successful_tests=len([r for r in results if r.executed]),
            failed_tests=len([r for r in results if not r.executed]),
            vulnerabilities_found=len([r for r in results if r.executed]),
            templates_used=list(set(r.template for r in results)),
            payload_categories=[],
        )

    # Generate report
    generator = ReportGenerator(output_dir)

    try:
        if report_type == "comprehensive":
            output_path = generator.generate_comprehensive_report(results, session)
            click.echo(
                f"{Fore.GREEN}📊 Comprehensive report generated: {output_path}{Style.RESET_ALL}"
            )

        elif report_type == "template":
            if not template:
                click.echo(
                    f"{Fore.RED}❌ Template name required for template report{Style.RESET_ALL}"
                )
                return
            output_path = generator.generate_template_report(results, template)
            click.echo(
                f"{Fore.GREEN}🎯 Template report generated: {output_path}{Style.RESET_ALL}"
            )

        elif report_type == "payload":
            if not payload:
                click.echo(
                    f"{Fore.RED}❌ Payload required for payload report{Style.RESET_ALL}"
                )
                return
            output_path = generator.generate_payload_report(results, payload)
            click.echo(
                f"{Fore.GREEN}💥 Payload report generated: {output_path}{Style.RESET_ALL}"
            )

    except Exception as e:
        click.echo(f"{Fore.RED}❌ Report generation failed: {e}{Style.RESET_ALL}")


# Register commands with main CLI
def register_ai_commands(cli_group):
    """Register AI commands with the main CLI group"""
    cli_group.add_command(ai_context)
    cli_group.add_command(ai_domfuzz_cmd)
    cli_group.add_command(report_gen_cmd)
