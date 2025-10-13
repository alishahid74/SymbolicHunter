"""
SymbolicHunter Reporting Module
Generates beautiful HTML/PDF reports with interactive visualizations
"""

import json
from datetime import datetime
from collections import defaultdict
import os

class ReportGenerator:
    def __init__(self, analysis_results):
        """
        Initialize report generator with analysis results
        
        Args:
            analysis_results: Dictionary containing all analysis data
        """
        self.results = analysis_results
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def generate_html_report(self, output_path):
        """Generate interactive HTML report"""
        html = self._generate_html()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return output_path
    
    def _generate_html(self):
        """Generate complete HTML report"""
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SymbolicHunter Analysis Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 3em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .header p {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }}
        
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 15px rgba(0,0,0,0.2);
        }}
        
        .stat-card h3 {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }}
        
        .stat-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #2a5298;
        }}
        
        .stat-card.critical .value {{
            color: #dc3545;
        }}
        
        .stat-card.warning .value {{
            color: #ffc107;
        }}
        
        .stat-card.success .value {{
            color: #28a745;
        }}
        
        .section {{
            padding: 40px;
            border-bottom: 1px solid #eee;
        }}
        
        .section h2 {{
            color: #2a5298;
            margin-bottom: 25px;
            font-size: 2em;
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        
        .risk-badge {{
            display: inline-block;
            padding: 8px 20px;
            border-radius: 25px;
            font-weight: bold;
            font-size: 0.9em;
        }}
        
        .risk-critical {{
            background: #dc3545;
            color: white;
        }}
        
        .risk-high {{
            background: #fd7e14;
            color: white;
        }}
        
        .risk-medium {{
            background: #ffc107;
            color: #000;
        }}
        
        .risk-low {{
            background: #28a745;
            color: white;
        }}
        
        .vuln-list {{
            list-style: none;
        }}
        
        .vuln-item {{
            background: #f8f9fa;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 10px;
            border-left: 4px solid #2a5298;
            transition: all 0.3s ease;
        }}
        
        .vuln-item:hover {{
            background: #e9ecef;
            border-left-width: 8px;
        }}
        
        .vuln-item.critical {{
            border-left-color: #dc3545;
        }}
        
        .vuln-item h4 {{
            color: #2a5298;
            margin-bottom: 10px;
            font-size: 1.2em;
        }}
        
        .vuln-detail {{
            color: #666;
            margin: 5px 0;
            font-size: 0.95em;
        }}
        
        .code-block {{
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 10px 0;
        }}
        
        .exploit-input {{
            background: #fff3cd;
            border: 2px solid #ffc107;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
            font-family: monospace;
            word-break: break-all;
        }}
        
        .progress-bar {{
            background: #e9ecef;
            border-radius: 10px;
            height: 30px;
            overflow: hidden;
            margin: 10px 0;
        }}
        
        .progress-fill {{
            background: linear-gradient(90deg, #2a5298, #667eea);
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            transition: width 1s ease;
        }}
        
        .api-category {{
            display: inline-block;
            padding: 5px 12px;
            background: #e9ecef;
            border-radius: 15px;
            margin: 3px;
            font-size: 0.85em;
            font-weight: 500;
        }}
        
        .api-category.memory {{ background: #ffc107; color: #000; }}
        .api-category.process {{ background: #dc3545; color: white; }}
        .api-category.network {{ background: #17a2b8; color: white; }}
        .api-category.anti_debug {{ background: #6f42c1; color: white; }}
        
        .taint-flow {{
            background: linear-gradient(90deg, #ff6b6b 0%, #feca57 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin: 15px 0;
        }}
        
        .taint-flow h4 {{
            margin-bottom: 10px;
        }}
        
        .footer {{
            background: #2a5298;
            color: white;
            text-align: center;
            padding: 30px;
        }}
        
        @media print {{
            body {{ background: white; }}
            .container {{ box-shadow: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 SymbolicHunter</h1>
            <p>Binary Analysis Report</p>
            <p style="font-size: 0.9em; opacity: 0.8;">Generated: {self.timestamp}</p>
        </div>
        
        {self._generate_summary_section()}
        {self._generate_risk_assessment()}
        {self._generate_taint_analysis_section()}
        {self._generate_vulnerabilities_section()}
        {self._generate_dangerous_apis_section()}
        {self._generate_recommendations()}
        
        <div class="footer">
            <p>SymbolicHunter - Powered by angr</p>
            <p style="margin-top: 10px; font-size: 0.9em;">Advanced Binary Analysis & Vulnerability Detection</p>
        </div>
    </div>
    
    <script>
        // Animate progress bars
        window.addEventListener('load', () => {{
            document.querySelectorAll('.progress-fill').forEach(bar => {{
                const width = bar.style.width;
                bar.style.width = '0%';
                setTimeout(() => bar.style.width = width, 100);
            }});
        }});
    </script>
</body>
</html>
"""
    
    def _generate_summary_section(self):
        """Generate summary statistics cards"""
        stats = self.results.get('statistics', {})
        vulns = sum(len(v) for v in self.results.get('vulnerabilities', {}).values())
        taint_sinks = len(self.results.get('taint_analysis', {}).get('tainted_sinks', []))
        
        coverage = stats.get('code_coverage', 0)
        coverage_class = 'success' if coverage > 50 else 'warning' if coverage > 20 else 'critical'
        
        return f"""
        <div class="summary">
            <div class="stat-card critical">
                <h3>Total Vulnerabilities</h3>
                <div class="value">{vulns}</div>
            </div>
            <div class="stat-card warning">
                <h3>Taint Sinks Found</h3>
                <div class="value">{taint_sinks}</div>
            </div>
            <div class="stat-card">
                <h3>Functions Discovered</h3>
                <div class="value">{stats.get('functions_discovered', 0)}</div>
            </div>
            <div class="stat-card">
                <h3>Paths Explored</h3>
                <div class="value">{stats.get('paths_explored', 0)}</div>
            </div>
            <div class="stat-card {coverage_class}">
                <h3>Code Coverage</h3>
                <div class="value">{coverage:.1f}%</div>
            </div>
            <div class="stat-card">
                <h3>Analysis Time</h3>
                <div class="value">{stats.get('time_elapsed', 0):.1f}s</div>
            </div>
        </div>
        """
    
    def _generate_risk_assessment(self):
        """Generate risk assessment section"""
        taint_sinks = len(self.results.get('taint_analysis', {}).get('tainted_sinks', []))
        anti_analysis = len(self.results.get('anti_analysis', []))
        total_vulns = sum(len(v) for v in self.results.get('vulnerabilities', {}).values())
        
        if taint_sinks > 0 or anti_analysis > 0:
            risk = 'CRITICAL'
            risk_class = 'risk-critical'
        elif total_vulns > 100:
            risk = 'HIGH'
            risk_class = 'risk-high'
        elif total_vulns > 10:
            risk = 'MEDIUM'
            risk_class = 'risk-medium'
        else:
            risk = 'LOW'
            risk_class = 'risk-low'
        
        return f"""
        <div class="section">
            <h2>⚠️ Risk Assessment</h2>
            <div style="text-align: center; padding: 30px;">
                <div class="risk-badge {risk_class}" style="font-size: 2em; padding: 20px 40px;">
                    {risk} RISK
                </div>
                <p style="margin-top: 20px; color: #666; font-size: 1.1em;">
                    Binary: <strong>{self.results.get('binary', 'Unknown')}</strong>
                </p>
            </div>
        </div>
        """
    
    def _generate_taint_analysis_section(self):
        """Generate taint analysis findings"""
        taint_data = self.results.get('taint_analysis', {})
        sinks = taint_data.get('tainted_sinks', [])
        
        if not sinks:
            return ""
        
        html = """
        <div class="section">
            <h2>💉 Taint Analysis - Critical Findings</h2>
        """
        
        # Group by vulnerability type
        by_type = defaultdict(list)
        for sink in sinks:
            by_type[sink['type']].append(sink)
        
        for vuln_type, instances in sorted(by_type.items(), key=lambda x: len(x[1]), reverse=True):
            html += f"""
            <div class="taint-flow">
                <h4>{vuln_type} ({len(instances)} instances)</h4>
            """
            for sink in instances[:3]:
                html += f"""
                <div style="background: rgba(255,255,255,0.2); padding: 15px; margin: 10px 0; border-radius: 8px;">
                    <strong>{sink['function']}</strong> at {sink['address']}<br>
                    Tainted arguments: {', '.join(sink['tainted_args'])}<br>
                """
                if sink.get('exploit_hex'):
                    html += f'<div class="code-block" style="margin-top: 10px;">Input: {sink["exploit_hex"][:80]}...</div>'
                html += "</div>"
            
            if len(instances) > 3:
                html += f"<p>... and {len(instances) - 3} more instances</p>"
            
            html += "</div>"
        
        html += "</div>"
        return html
    
    def _generate_vulnerabilities_section(self):
        """Generate vulnerabilities section"""
        vulns = self.results.get('vulnerabilities', {})
        
        html = """
        <div class="section">
            <h2>🐛 Vulnerabilities Detected</h2>
            <ul class="vuln-list">
        """
        
        for vuln_type, instances in vulns.items():
            if not instances:
                continue
            
            is_critical = vuln_type in ['unconstrained_execution', 'taint_to_sink', 'crashed_paths']
            html += f"""
            <li class="vuln-item {'critical' if is_critical else ''}">
                <h4>{vuln_type.replace('_', ' ').title()} ({len(instances)} found)</h4>
            """
            
            for vuln in instances[:3]:
                html += f"""
                <div class="vuln-detail">
                    <strong>Address:</strong> {vuln.get('address', 'N/A')}<br>
                    <strong>Description:</strong> {vuln.get('description', 'No description')}
                </div>
                """
            
            if len(instances) > 3:
                html += f'<p style="margin-top: 10px; color: #666;">... and {len(instances) - 3} more</p>'
            
            html += "</li>"
        
        html += """
            </ul>
        </div>
        """
        return html
    
    def _generate_dangerous_apis_section(self):
        """Generate dangerous APIs section"""
        apis = self.results.get('dangerous_functions', [])
        
        if not apis:
            return ""
        
        html = """
        <div class="section">
            <h2>⚡ Dangerous API Calls</h2>
            <p style="margin-bottom: 20px; color: #666;">Found {} dangerous API calls in the binary</p>
        """.format(len(apis))
        
        # Group by category
        by_category = defaultdict(list)
        for api in apis:
            by_category[api.get('category', 'other')].append(api)
        
        for category, funcs in sorted(by_category.items()):
            html += f'<h3 style="margin: 20px 0 10px 0;">{category.upper()}</h3>'
            html += '<div>'
            for func in funcs[:10]:
                html += f'<span class="api-category {category}">{func["name"]}</span>'
            if len(funcs) > 10:
                html += f'<span style="margin-left: 10px; color: #666;">... and {len(funcs) - 10} more</span>'
            html += '</div>'
        
        html += "</div>"
        return html
    
    def _generate_recommendations(self):
        """Generate recommendations section"""
        return """
        <div class="section">
            <h2>💡 Recommendations</h2>
            <ul style="list-style-position: inside; color: #666; line-height: 2;">
                <li>Perform manual review of all critical findings</li>
                <li>Test exploit candidates in isolated sandbox environment</li>
                <li>Implement input validation for all user-controlled data</li>
                <li>Use address space layout randomization (ASLR)</li>
                <li>Enable stack canaries and DEP/NX protection</li>
                <li>Consider additional dynamic analysis tools</li>
            </ul>
        </div>
        """


def generate_report(analysis_results, output_path):
    """
    Convenience function to generate HTML report
    
    Args:
        analysis_results: Dictionary with analysis data
        output_path: Path to save HTML report
    
    Returns:
        Path to generated report
    """
    generator = ReportGenerator(analysis_results)
    return generator.generate_html_report(output_path)
