#!/usr/bin/env python3

"""
BountyX AI Helper - Analyzes vulnerability scan results and provides recommendations
"""

import os
import sys
import json
import argparse
import glob
from datetime import datetime
import re
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('bountyx_ai')

# Check if any AI models are available
try:
    import openai
    OPENAI_AVAILABLE = True
    logger.info("OpenAI module detected")
except ImportError:
    OPENAI_AVAILABLE = False
    logger.warning("OpenAI module not found")

try:
    from transformers import pipeline
    TRANSFORMERS_AVAILABLE = True
    logger.info("Transformers module detected")
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logger.warning("Transformers module not found")

class BountyXAI:
    def __init__(self, input_dir, output_format="json"):
        self.input_dir = input_dir
        self.output_format = output_format
        self.results = {}
        self.analysis = {}
        self.recommendations = {}
        self.priorities = {}

    def load_results(self):
        """Load all results from the results directory"""
        logger.info(f"Loading results from {self.input_dir}")
        
        # Load subdomain results
        subdomain_files = glob.glob(f"{self.input_dir}/subdomains/*.json")
        if subdomain_files:
            try:
                with open(subdomain_files[0], 'r') as f:
                    self.results['subdomains'] = json.load(f)
                logger.info(f"Loaded {len(self.results.get('subdomains', {}).get('subdomains', []))} subdomains")
            except Exception as e:
                logger.error(f"Error loading subdomain results: {e}")
        
        # Load port scan results
        port_files = glob.glob(f"{self.input_dir}/ports/*.json")
        if port_files:
            try:
                with open(port_files[0], 'r') as f:
                    self.results['ports'] = json.load(f)
                logger.info(f"Loaded port scan results")
            except Exception as e:
                logger.error(f"Error loading port scan results: {e}")
        
        # Load directory enumeration results
        dir_files = glob.glob(f"{self.input_dir}/directories/*.json")
        if dir_files:
            try:
                with open(dir_files[0], 'r') as f:
                    self.results['directories'] = json.load(f)
                logger.info(f"Loaded directory enumeration results")
            except Exception as e:
                logger.error(f"Error loading directory enumeration results: {e}")
        
        # Load live host results
        host_files = glob.glob(f"{self.input_dir}/livehosts/*.json")
        if host_files:
            try:
                with open(host_files[0], 'r') as f:
                    self.results['livehosts'] = json.load(f)
                logger.info(f"Loaded live host results")
            except Exception as e:
                logger.error(f"Error loading live host results: {e}")
        
        # Load vulnerability scan results
        vuln_files = glob.glob(f"{self.input_dir}/vulnerabilities/*.json")
        if vuln_files:
            for vuln_file in vuln_files:
                try:
                    with open(vuln_file, 'r') as f:
                        if 'vulnerabilities' not in self.results:
                            self.results['vulnerabilities'] = []
                        self.results['vulnerabilities'].append(json.load(f))
                    logger.info(f"Loaded vulnerability results from {vuln_file}")
                except Exception as e:
                    logger.error(f"Error loading vulnerability results from {vuln_file}: {e}")
        
        # Check if any results were loaded
        if not self.results:
            logger.warning("No results were loaded. Make sure the scans have completed.")
            return False
        
        return True

    def analyze_results(self):
        """Analyze the loaded results"""
        logger.info("Analyzing results")
        
        # Initialize analysis structure
        self.analysis = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'summary': {},
            'details': {}
        }
        
        # Analyze subdomains
        if 'subdomains' in self.results:
            subdomains = self.results['subdomains'].get('subdomains', [])
            self.analysis['summary']['subdomain_count'] = len(subdomains)
            self.analysis['details']['interesting_subdomains'] = self._find_interesting_subdomains(subdomains)
        
        # Analyze ports
        if 'ports' in self.results:
            self.analysis['details']['open_ports'] = self._analyze_ports(self.results['ports'])
            
            # Count open ports
            open_port_count = 0
            for host in self.results['ports'].get('scan_results', []):
                open_port_count += len(host.get('ports', []))
            
            self.analysis['summary']['open_port_count'] = open_port_count
        
        # Analyze directories
        if 'directories' in self.results:
            dir_scan = self.results['directories'].get('directory_scan', [])
            self.analysis['summary']['directory_count'] = len(dir_scan)
            self.analysis['details']['interesting_directories'] = self._find_interesting_directories(dir_scan)
        
        # Analyze live hosts
        if 'livehosts' in self.results:
            live_hosts = self.results['livehosts'].get('live_hosts', [])
            self.analysis['summary']['live_host_count'] = len(live_hosts)
        
        # Analyze vulnerabilities
        if 'vulnerabilities' in self.results:
            self.analysis['details']['vulnerabilities'] = self._analyze_vulnerabilities(self.results['vulnerabilities'])
            
            # Count vulnerabilities by severity
            vuln_count = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
            
            for vuln in self.analysis['details']['vulnerabilities']:
                severity = vuln.get('severity', 'info').lower()
                if severity in vuln_count:
                    vuln_count[severity] += 1
                else:
                    vuln_count['info'] += 1
            
            self.analysis['summary']['vulnerability_count'] = vuln_count
        
        return True

    def generate_recommendations(self):
        """Generate recommendations based on the analysis"""
        logger.info("Generating recommendations")
        
        # Initialize recommendations structure
        self.recommendations = {
            'high_priority': [],
            'medium_priority': [],
            'low_priority': []
        }
        
        # Analyze vulnerabilities for recommendations
        if 'vulnerabilities' in self.analysis['details']:
            for vuln in self.analysis['details']['vulnerabilities']:
                severity = vuln.get('severity', 'info').lower()
                
                recommendation = {
                    'title': vuln.get('title', 'Unnamed vulnerability'),
                    'description': vuln.get('description', ''),
                    'recommendation': self._get_recommendation_for_vulnerability(vuln)
                }
                
                if severity in ['critical', 'high']:
                    self.recommendations['high_priority'].append(recommendation)
                elif severity == 'medium':
                    self.recommendations['medium_priority'].append(recommendation)
                else:
                    self.recommendations['low_priority'].append(recommendation)
        
        # Add recommendations based on open ports
        if 'open_ports' in self.analysis['details']:
            for port_info in self.analysis['details']['open_ports']:
                if port_info['port'] in [22, 23, 3389, 5900]:
                    self.recommendations['medium_priority'].append({
                        'title': f"Remote Access Service on Port {port_info['port']}",
                        'description': f"Found {port_info['service']} running on port {port_info['port']}",
                        'recommendation': f"Restrict access to port {port_info['port']} to trusted IPs only and ensure strong authentication is in place."
                    })
                elif port_info['port'] in [80, 443]:
                    self.recommendations['low_priority'].append({
                        'title': f"Web Service on Port {port_info['port']}",
                        'description': f"Found {port_info['service']} running on port {port_info['port']}",
                        'recommendation': "Ensure the web server is properly configured with secure headers and up-to-date."
                    })
                elif port_info['port'] in [21, 20]:
                    self.recommendations['medium_priority'].append({
                        'title': f"FTP Service on Port {port_info['port']}",
                        'description': f"Found {port_info['service']} running on port {port_info['port']}",
                        'recommendation': "Consider replacing FTP with SFTP or FTPS for secure file transfers."
                    })
        
        # Add recommendations based on interesting directories
        if 'interesting_directories' in self.analysis['details']:
            for dir_info in self.analysis['details']['interesting_directories']:
                if '.git' in dir_info['url'] or '.env' in dir_info['url']:
                    self.recommendations['high_priority'].append({
                        'title': "Sensitive Information Exposure",
                        'description': f"Found {dir_info['url']} which may expose sensitive information",
                        'recommendation': f"Remove or restrict access to {dir_info['url']} immediately."
                    })
                elif 'wp-admin' in dir_info['url'] or 'admin' in dir_info['url']:
                    self.recommendations['medium_priority'].append({
                        'title': "Admin Interface Exposed",
                        'description': f"Found potential admin interface at {dir_info['url']}",
                        'recommendation': "Restrict access to admin interfaces and use strong passwords and 2FA."
                    })
        
        return True

    def prioritize_findings(self):
        """Prioritize findings based on severity and impact"""
        logger.info("Prioritizing findings")
        
        # Initialize priorities
        self.priorities = {
            'immediate_action': [],
            'short_term': [],
            'long_term': []
        }
        
        # Prioritize critical and high vulnerabilities for immediate action
        if 'high_priority' in self.recommendations:
            for rec in self.recommendations['high_priority']:
                self.priorities['immediate_action'].append({
                    'title': rec['title'],
                    'description': rec['description'],
                    'recommendation': rec['recommendation'],
                    'timeframe': 'As soon as possible (24-48 hours)'
                })
        
        # Prioritize medium vulnerabilities for short term
        if 'medium_priority' in self.recommendations:
            for rec in self.recommendations['medium_priority']:
                self.priorities['short_term'].append({
                    'title': rec['title'],
                    'description': rec['description'],
                    'recommendation': rec['recommendation'],
                    'timeframe': 'Within 1-2 weeks'
                })
        
        # Prioritize low vulnerabilities for long term
        if 'low_priority' in self.recommendations:
            for rec in self.recommendations['low_priority']:
                self.priorities['long_term'].append({
                    'title': rec['title'],
                    'description': rec['description'],
                    'recommendation': rec['recommendation'],
                    'timeframe': 'Within 1-3 months'
                })
        
        return True
    
    def use_ai_for_analysis(self):
        """Use AI models to enhance the analysis if available"""
        if not OPENAI_AVAILABLE and not TRANSFORMERS_AVAILABLE:
            logger.warning("No AI models available for enhanced analysis")
            return False
        
        logger.info("Using AI for enhanced analysis")
        
        # Try to use OpenAI first
        if OPENAI_AVAILABLE:
            api_key = os.getenv("OPENAI_API_KEY")
            if api_key:
                try:
                    logger.info("Using OpenAI for analysis")
                    openai.api_key = api_key
                    
                    # Prepare a summary of findings for the AI
                    prompt = self._prepare_ai_prompt()
                    
                    # Call OpenAI API
                    response = openai.Completion.create(
                        engine="text-davinci-003",
                        prompt=prompt,
                        max_tokens=1000,
                        temperature=0.7
                    )
                    
                    # Extract AI analysis
                    ai_analysis = response.choices[0].text.strip()
                    
                    # Add AI analysis to the results
                    self.analysis['ai_enhanced'] = {
                        'model': 'OpenAI text-davinci-003',
                        'analysis': ai_analysis
                    }
                    
                    logger.info("OpenAI analysis completed")
                    return True
                except Exception as e:
                    logger.error(f"Error using OpenAI: {e}")
        
        # Fall back to transformers if OpenAI is not available or failed
        if TRANSFORMERS_AVAILABLE:
            try:
                logger.info("Using HuggingFace transformers for analysis")
                
                # Use a summarization model
                summarizer = pipeline("summarization")
                
                # Prepare text to summarize
                text = self._prepare_transformers_text()
                
                # Generate summary
                if text:
                    summary = summarizer(text, max_length=250, min_length=50, do_sample=False)
                    
                    # Add AI analysis to the results
                    self.analysis['ai_enhanced'] = {
                        'model': 'HuggingFace Transformers',
                        'analysis': summary[0]['summary_text']
                    }
                    
                    logger.info("Transformers analysis completed")
                    return True
                else:
                    logger.warning("Not enough text for transformers to analyze")
            except Exception as e:
                logger.error(f"Error using transformers: {e}")
        
        return False

    def save_results(self, target):
        """Save analysis results to file with comprehensive remediation steps"""
        output_dir = f"{self.input_dir}/analysis"
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        filename_base = f"{output_dir}/{target}_analysis_{timestamp}"
        
        # Create the final output structure with enhanced remediation recommendations
        final_output = {
            'target': target,
            'timestamp': timestamp,
            'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'summary': self.analysis.get('summary', {}),
            'details': self.analysis.get('details', {}),
            'recommendations': self.recommendations,
            'priorities': self.priorities,
            'remediation_plan': {
                'immediate_actions': self._format_remediation_plan(self.priorities.get('immediate_action', [])),
                'short_term_actions': self._format_remediation_plan(self.priorities.get('short_term', [])),
                'long_term_actions': self._format_remediation_plan(self.priorities.get('long_term', []))
            }
        }
        
        # Add AI-enhanced analysis if available
        if 'ai_enhanced' in self.analysis:
            final_output['ai_enhanced'] = self.analysis['ai_enhanced']
        
        # Save in the requested format
        if self.output_format == 'json':
            with open(f"{filename_base}.json", 'w') as f:
                json.dump(final_output, f, indent=2)
            logger.info(f"Results saved to {filename_base}.json")
        elif self.output_format == 'txt':
            with open(f"{filename_base}.txt", 'w') as f:
                self._write_text_report(f, final_output)
            logger.info(f"Results saved to {filename_base}.txt")
        elif self.output_format == 'html':
            with open(f"{filename_base}.html", 'w') as f:
                self._write_html_report(f, final_output)
            logger.info(f"Results saved to {filename_base}.html")
        else:
            logger.error(f"Unsupported output format: {self.output_format}")
            return False
        
        return True

    def _write_text_report(self, file, data):
        """Write a text format report"""
        file.write(f"BountyX AI Analysis Report\n")
        file.write(f"=========================\n\n")
        file.write(f"Target: {data['target']}\n")
        file.write(f"Timestamp: {data['timestamp']}\n\n")
        
        # Write summary
        file.write("Summary\n-------\n")
        summary = data.get('summary', {})
        if 'subdomain_count' in summary:
            file.write(f"Subdomains found: {summary['subdomain_count']}\n")
        if 'live_host_count' in summary:
            file.write(f"Live hosts found: {summary['live_host_count']}\n")
        if 'open_port_count' in summary:
            file.write(f"Open ports found: {summary['open_port_count']}\n")
        if 'directory_count' in summary:
            file.write(f"Directories found: {summary['directory_count']}\n")
        if 'vulnerability_count' in summary:
            vuln_count = summary['vulnerability_count']
            file.write(f"Vulnerabilities found:\n")
            file.write(f"  Critical: {vuln_count.get('critical', 0)}\n")
            file.write(f"  High: {vuln_count.get('high', 0)}\n")
            file.write(f"  Medium: {vuln_count.get('medium', 0)}\n")
            file.write(f"  Low: {vuln_count.get('low', 0)}\n")
            file.write(f"  Info: {vuln_count.get('info', 0)}\n")
        file.write("\n")
        
        # Write AI-enhanced analysis if available
        if 'ai_enhanced' in data:
            file.write("AI-Enhanced Analysis\n-------------------\n")
            file.write(f"Model: {data['ai_enhanced']['model']}\n\n")
            file.write(f"{data['ai_enhanced']['analysis']}\n\n")
        
        # Write priorities
        file.write("Priorities\n----------\n")
        
        # Immediate actions
        file.write("Immediate Actions (24-48 hours):\n")
        for action in data['priorities'].get('immediate_action', []):
            file.write(f"- {action['title']}\n")
            file.write(f"  Description: {action['description']}\n")
            file.write(f"  Recommendation: {action['recommendation']}\n\n")
        
        # Short term actions
        file.write("Short Term Actions (1-2 weeks):\n")
        for action in data['priorities'].get('short_term', []):
            file.write(f"- {action['title']}\n")
            file.write(f"  Description: {action['description']}\n")
            file.write(f"  Recommendation: {action['recommendation']}\n\n")
        
        # Long term actions
        file.write("Long Term Actions (1-3 months):\n")
        for action in data['priorities'].get('long_term', []):
            file.write(f"- {action['title']}\n")
            file.write(f"  Description: {action['description']}\n")
            file.write(f"  Recommendation: {action['recommendation']}\n\n")
        
        # Write details
        file.write("Details\n-------\n")
        
        # Interesting subdomains
        if 'interesting_subdomains' in data.get('details', {}):
            file.write("Interesting Subdomains:\n")
            for subdomain in data['details']['interesting_subdomains']:
                file.write(f"- {subdomain}\n")
            file.write("\n")
        
        # Open ports
        if 'open_ports' in data.get('details', {}):
            file.write("Open Ports:\n")
            for port in data['details']['open_ports']:
                file.write(f"- Port {port['port']}: {port['service']} ({port.get('version', 'unknown')})\n")
            file.write("\n")
        
        # Interesting directories
        if 'interesting_directories' in data.get('details', {}):
            file.write("Interesting Directories:\n")
            for directory in data['details']['interesting_directories']:
                file.write(f"- {directory['url']} [Status: {directory.get('status', 'unknown')}]\n")
            file.write("\n")
        
        # Vulnerabilities
        if 'vulnerabilities' in data.get('details', {}):
            file.write("Vulnerabilities:\n")
            for vuln in data['details']['vulnerabilities']:
                file.write(f"- {vuln.get('title', 'Unnamed vulnerability')} [{vuln.get('severity', 'unknown').upper()}]\n")
                file.write(f"  Description: {vuln.get('description', 'No description')}\n")
                if 'recommendation' in vuln:
                    file.write(f"  Recommendation: {vuln['recommendation']}\n")
                file.write("\n")

    def _write_html_report(self, file, data):
        """Write an HTML format report"""
        html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>BountyX AI Analysis Report</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 20px;
                    color: #333;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                }
                h1, h2, h3, h4 {
                    color: #2c3e50;
                }
                .header {
                    background-color: #34495e;
                    color: white;
                    padding: 20px;
                    text-align: center;
                    margin-bottom: 20px;
                }
                .section {
                    margin-bottom: 30px;
                    padding: 20px;
                    background-color: #f9f9f9;
                    border-radius: 5px;
                }
                .subsection {
                    margin-bottom: 20px;
                }
                .vuln-critical, .priority-immediate {
                    background-color: #f8d7da;
                    border: 1px solid #f5c6cb;
                    padding: 10px;
                    border-radius: 5px;
                    margin-bottom: 10px;
                }
                .vuln-high, .priority-short {
                    background-color: #fff3cd;
                    border: 1px solid #ffeeba;
                    padding: 10px;
                    border-radius: 5px;
                    margin-bottom: 10px;
                }
                .vuln-medium {
                    background-color: #d1ecf1;
                    border: 1px solid #bee5eb;
                    padding: 10px;
                    border-radius: 5px;
                    margin-bottom: 10px;
                }
                .vuln-low, .priority-long {
                    background-color: #d4edda;
                    border: 1px solid #c3e6cb;
                    padding: 10px;
                    border-radius: 5px;
                    margin-bottom: 10px;
                }
                .summary-box {
                    display: flex;
                    flex-wrap: wrap;
                    justify-content: space-between;
                }
                .summary-item {
                    flex: 1;
                    min-width: 200px;
                    margin: 10px;
                    padding: 15px;
                    background-color: #e9ecef;
                    border-radius: 5px;
                    text-align: center;
                }
                .summary-item h3 {
                    margin-top: 0;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 20px;
                }
                th, td {
                    border: 1px solid #ddd;
                    padding: 8px;
                    text-align: left;
                }
                th {
                    background-color: #f2f2f2;
                }
                tr:nth-child(even) {
                    background-color: #f9f9f9;
                }
                .ai-section {
                    background-color: #e6f7ff;
                    border: 1px solid #91d5ff;
                    padding: 15px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>BountyX AI Analysis Report</h1>
                    <p>Target: {target}</p>
                    <p>Generated: {timestamp}</p>
                </div>
        """.format(
            target=data['target'],
            timestamp=data['timestamp']
        )
        
        # Add summary section
        html += """
                <div class="section">
                    <h2>Summary</h2>
                    <div class="summary-box">
        """
        
        summary = data.get('summary', {})
        
        if 'subdomain_count' in summary:
            html += """
                        <div class="summary-item">
                            <h3>Subdomains</h3>
                            <p>{count}</p>
                        </div>
            """.format(count=summary['subdomain_count'])
        
        if 'live_host_count' in summary:
            html += """
                        <div class="summary-item">
                            <h3>Live Hosts</h3>
                            <p>{count}</p>
                        </div>
            """.format(count=summary['live_host_count'])
        
        if 'open_port_count' in summary:
            html += """
                        <div class="summary-item">
                            <h3>Open Ports</h3>
                            <p>{count}</p>
                        </div>
            """.format(count=summary['open_port_count'])
        
        if 'directory_count' in summary:
            html += """
                        <div class="summary-item">
                            <h3>Directories</h3>
                            <p>{count}</p>
                        </div>
            """.format(count=summary['directory_count'])
        
        if 'vulnerability_count' in summary:
            vuln_count = summary['vulnerability_count']
            html += """
                        <div class="summary-item">
                            <h3>Vulnerabilities</h3>
                            <p>Critical: {critical}<br>
                               High: {high}<br>
                               Medium: {medium}<br>
                               Low: {low}<br>
                               Info: {info}</p>
                        </div>
            """.format(
                critical=vuln_count.get('critical', 0),
                high=vuln_count.get('high', 0),
                medium=vuln_count.get('medium', 0),
                low=vuln_count.get('low', 0),
                info=vuln_count.get('info', 0)
            )
        
        html += """
                    </div>
                </div>
        """
        
        # Add AI-enhanced section if available
        if 'ai_enhanced' in data:
            html += """
                <div class="section ai-section">
                    <h2>AI-Enhanced Analysis</h2>
                    <p><strong>Model:</strong> {model}</p>
                    <p>{analysis}</p>
                </div>
            """.format(
                model=data['ai_enhanced']['model'],
                analysis=data['ai_enhanced']['analysis'].replace('\n', '<br>')
            )
        
        # Add priorities section
        html += """
                <div class="section">
                    <h2>Action Priorities</h2>
        """
        
        # Immediate actions
        html += """
                    <div class="subsection">
                        <h3>Immediate Actions (24-48 hours)</h3>
        """
        
        for action in data['priorities'].get('immediate_action', []):
            html += """
                        <div class="priority-immediate">
                            <h4>{title}</h4>
                            <p><strong>Description:</strong> {description}</p>
                            <p><strong>Recommendation:</strong> {recommendation}</p>
                        </div>
            """.format(
                title=action['title'],
                description=action['description'],
                recommendation=action['recommendation']
            )
        
        html += """
                    </div>
        """
        
        # Short term actions
        html += """
                    <div class="subsection">
                        <h3>Short Term Actions (1-2 weeks)</h3>
        """
        
        for action in data['priorities'].get('short_term', []):
            html += """
                        <div class="priority-short">
                            <h4>{title}</h4>
                            <p><strong>Description:</strong> {description}</p>
                            <p><strong>Recommendation:</strong> {recommendation}</p>
                        </div>
            """.format(
                title=action['title'],
                description=action['description'],
                recommendation=action['recommendation']
            )
        
        html += """
                    </div>
        """
        
        # Long term actions
        html += """
                    <div class="subsection">
                        <h3>Long Term Actions (1-3 months)</h3>
        """
        
        for action in data['priorities'].get('long_term', []):
            html += """
                        <div class="priority-long">
                            <h4>{title}</h4>
                            <p><strong>Description:</strong> {description}</p>
                            <p><strong>Recommendation:</strong> {recommendation}</p>
                        </div>
            """.format(
                title=action['title'],
                description=action['description'],
                recommendation=action['recommendation']
            )
        
        html += """
                    </div>
                </div>
        """
        
        # Add details section
        html += """
                <div class="section">
                    <h2>Detailed Findings</h2>
        """
        
        # Interesting subdomains
        if 'interesting_subdomains' in data.get('details', {}):
            html += """
                    <div class="subsection">
                        <h3>Interesting Subdomains</h3>
                        <ul>
            """
            
            for subdomain in data['details']['interesting_subdomains']:
                html += f"<li>{subdomain}</li>"
            
            html += """
                        </ul>
                    </div>
            """
        
        # Open ports
        if 'open_ports' in data.get('details', {}):
            html += """
                    <div class="subsection">
                        <h3>Open Ports</h3>
                        <table>
                            <tr>
                                <th>Port</th>
                                <th>Service</th>
                                <th>Version</th>
                            </tr>
            """
            
            for port in data['details']['open_ports']:
                html += """
                            <tr>
                                <td>{port}</td>
                                <td>{service}</td>
                                <td>{version}</td>
                            </tr>
                """.format(
                    port=port['port'],
                    service=port['service'],
                    version=port.get('version', 'unknown')
                )
            
            html += """
                        </table>
                    </div>
            """
        
        # Interesting directories
        if 'interesting_directories' in data.get('details', {}):
            html += """
                    <div class="subsection">
                        <h3>Interesting Directories</h3>
                        <table>
                            <tr>
                                <th>URL</th>
                                <th>Status</th>
                            </tr>
            """
            
            for directory in data['details']['interesting_directories']:
                html += """
                            <tr>
                                <td>{url}</td>
                                <td>{status}</td>
                            </tr>
                """.format(
                    url=directory['url'],
                    status=directory.get('status', 'unknown')
                )
            
            html += """
                        </table>
                    </div>
            """
        
        # Vulnerabilities
        if 'vulnerabilities' in data.get('details', {}):
            html += """
                    <div class="subsection">
                        <h3>Vulnerabilities</h3>
            """
            
            for vuln in data['details']['vulnerabilities']:
                severity = vuln.get('severity', 'info').lower()
                css_class = f"vuln-{severity}" if severity in ['critical', 'high', 'medium', 'low'] else "vuln-low"
                
                html += """
                        <div class="{css_class}">
                            <h4>{title} [{severity}]</h4>
                            <p><strong>Description:</strong> {description}</p>
                """.format(
                    css_class=css_class,
                    title=vuln.get('title', 'Unnamed vulnerability'),
                    severity=severity.upper(),
                    description=vuln.get('description', 'No description')
                )
                
                if 'recommendation' in vuln:
                    html += f"<p><strong>Recommendation:</strong> {vuln['recommendation']}</p>"
                
                html += """
                        </div>
                """
            
            html += """
                    </div>
            """
        
        html += """
                </div>
                <div class="section">
                    <p>Generated by BountyX AI Helper</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        file.write(html)

    def _find_interesting_subdomains(self, subdomains):
        """Find potentially interesting subdomains"""
        interesting_keywords = [
            'admin', 'dev', 'staging', 'test', 'beta', 'api', 'internal',
            'vpn', 'mail', 'remote', 'portal', 'intranet', 'secure', 'login',
            'db', 'database', 'auth', 'jenkins', 'git', 'svn', 'jira', 'confluence'
        ]
        
        interesting = []
        for subdomain in subdomains:
            for keyword in interesting_keywords:
                if keyword in subdomain.lower():
                    interesting.append(subdomain)
                    break
        
        return interesting

    def _analyze_ports(self, port_data):
        """Analyze port scan data"""
        interesting_ports = []
        
        for host in port_data.get('scan_results', []):
            for port_info in host.get('ports', []):
                interesting_ports.append({
                    'host': host.get('host', 'unknown'),
                    'port': port_info.get('port', 0),
                    'service': port_info.get('service', 'unknown'),
                    'version': port_info.get('version', 'unknown')
                })
        
        return interesting_ports

    def _find_interesting_directories(self, directories):
        """Find potentially interesting directories"""
        interesting_keywords = [
            '.git', '.env', 'wp-admin', 'admin', 'backup', 'db', 'config',
            'dashboard', 'login', 'api', 'test', 'dev', 'staging', 'beta',
            'phpinfo', 'phpmyadmin', 'jenkins', 'jira', 'confluence',
            'password', 'credentials', 'sql', 'database'
        ]
        
        interesting = []
        for directory in directories:
            url = directory.get('url', '')
            for keyword in interesting_keywords:
                if keyword in url.lower():
                    interesting.append(directory)
                    break
        
        return interesting

    def _analyze_vulnerabilities(self, vulnerabilities):
        """Analyze vulnerability data"""
        analyzed_vulns = []
        
        for vuln_data in vulnerabilities:
            # Handle nuclei format
            if 'results' in vuln_data:
                for result in vuln_data['results']:
                    analyzed_vulns.append({
                        'title': result.get('info', {}).get('name', 'Unknown Vulnerability'),
                        'severity': result.get('info', {}).get('severity', 'info'),
                        'description': result.get('info', {}).get('description', ''),
                        'url': result.get('host', ''),
                        'recommendation': self._get_recommendation_for_vulnerability_type(
                            result.get('info', {}).get('name', ''),
                            result.get('matcher-name', '')
                        )
                    })
            # Handle manual checks format
            elif 'manual_checks' in vuln_data:
                for check in vuln_data['manual_checks']:
                    title = check.get('title', '')
                    severity = 'info'
                    
                    # Determine severity based on title content
                    if 'CRITICAL' in title:
                        severity = 'critical'
                    elif 'WARNING' in title:
                        severity = 'medium'
                    
                    analyzed_vulns.append({
                        'title': title,
                        'severity': severity,
                        'description': check.get('content', ''),
                        'recommendation': self._get_recommendation_for_vulnerability_type(title, '')
                    })
        
        return analyzed_vulns

    def _get_recommendation_for_vulnerability(self, vuln):
        """Generate a detailed recommendation for a specific vulnerability with remediation steps"""
        vuln_type = vuln.get('title', '').lower()
        severity = vuln.get('severity', 'medium').lower()
        
        # Get the basic recommendation based on vulnerability type
        recommendation = self._get_recommendation_for_vulnerability_type(vuln_type, '')
        
        # Add contextual information from the vulnerability details
        details = vuln.get('details', {})
        affected_url = details.get('url', vuln.get('url', ''))
        
        # Format the recommendation with specific information
        formatted_recommendation = {
            'summary': recommendation['summary'],
            'steps': recommendation['steps'],
            'code_example': recommendation['code_example'],
            'references': recommendation['references']
        }
        
        # Add target-specific information if available
        if affected_url:
            formatted_recommendation['affected_url'] = affected_url
            formatted_recommendation['steps'] = [
                step.replace('{{URL}}', affected_url) for step in formatted_recommendation['steps']
            ]
        
        # Add severity-based prioritization
        if severity in ['critical', 'high']:
            formatted_recommendation['timeframe'] = "Immediate (within 24-48 hours)"
        elif severity == 'medium':
            formatted_recommendation['timeframe'] = "Short-term (within 1-2 weeks)"
        else:
            formatted_recommendation['timeframe'] = "Medium-term (within 1 month)"
        
        return formatted_recommendation

    def _get_recommendation_for_vulnerability_type(self, vuln_name, matcher_name):
        """Generate a detailed recommendation based on vulnerability type with remediation steps, 
        code examples, and references"""
        vuln_name_lower = vuln_name.lower()
        matcher_name_lower = matcher_name.lower()
        
        # Comprehensive vulnerability remediation database
        remediation_db = {
            'sql injection': {
                'summary': "Protect against SQL injection attacks by using parameterized queries and input validation",
                'steps': [
                    "Replace dynamic SQL queries with parameterized queries or prepared statements",
                    "Implement proper input validation and sanitization for all user inputs",
                    "Apply the principle of least privilege to database accounts",
                    "Use an ORM (Object-Relational Mapping) library when possible",
                    "Implement a Web Application Firewall (WAF) as an additional layer of protection"
                ],
                'code_example': """
# Example of parameterized query in Python with SQLite:
import sqlite3
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# UNSAFE:
# username = request.args.get('username')
# cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")

# SAFE:
username = request.args.get('username')
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                """,
                'references': [
                    "OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                    "PortSwigger SQL Injection Guide: https://portswigger.net/web-security/sql-injection"
                ]
            },
            'xss': {
                'summary': "Prevent Cross-Site Scripting (XSS) by implementing proper output encoding and CSP headers",
                'steps': [
                    "Implement context-appropriate output encoding for all user-controlled data",
                    "Use Content-Security-Policy (CSP) headers to restrict script execution",
                    "Sanitize all user inputs before rendering them in HTML contexts",
                    "Use modern frameworks that automatically escape output",
                    "Implement X-XSS-Protection header as an additional defense"
                ],
                'code_example': """
# Example of CSP header implementation in Node.js:
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'nonce-{RANDOM_NONCE}'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:"],
    connectSrc: ["'self'"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
  }
})
                """,
                'references': [
                    "OWASP XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                    "Content Security Policy (CSP) Quick Reference: https://content-security-policy.com/"
                ]
            },
            'open redirect': {
                'summary': "Prevent open redirect vulnerabilities by validating destination URLs against a whitelist",
                'steps': [
                    "Implement a whitelist of allowed redirect destinations",
                    "Validate all redirect parameters against this whitelist",
                    "Use relative path redirects when possible",
                    "For external redirects, use an intermediate page that requires user confirmation",
                    "Consider implementing URL signing for sensitive redirects"
                ],
                'code_example': """
# Example of safe redirect implementation in Python:
from urllib.parse import urlparse
import re

def is_safe_redirect_url(url, allowed_hosts):
    parsed_url = urlparse(url)
    return (not parsed_url.netloc) or (parsed_url.netloc in allowed_hosts)

def safe_redirect(request):
    redirect_url = request.args.get('next', '/')
    allowed_hosts = ['example.com', 'subdomain.example.com']
    
    if is_safe_redirect_url(redirect_url, allowed_hosts):
        return redirect(redirect_url)
    else:
        return redirect('/')
                """,
                'references': [
                    "OWASP Unvalidated Redirects and Forwards Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
                ]
            },
            'csrf': {
                'summary': "Protect against Cross-Site Request Forgery (CSRF) with anti-CSRF tokens and proper validation",
                'steps': [
                    "Implement anti-CSRF tokens for all state-changing operations",
                    "Ensure tokens are unique per user session and per request",
                    "Add the 'SameSite=Strict' attribute to cookies",
                    "Use the 'X-CSRF-TOKEN' header for AJAX requests",
                    "Consider implementing custom request headers for sensitive operations"
                ],
                'code_example': """
# Example of CSRF protection in Flask:
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
csrf = CSRFProtect(app)

@app.route('/form', methods=['POST'])
def process_form():
    # CSRF token is automatically checked
    # Process form data
    return 'Form processed'
                """,
                'references': [
                    "OWASP CSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                    "SameSite Cookie Attribute: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"
                ]
            },
            'ssrf': {
                'summary': "Protect against Server-Side Request Forgery (SSRF) by validating and restricting URLs",
                'steps': [
                    "Implement a whitelist of allowed destinations",
                    "Validate and sanitize all user-provided URLs",
                    "Use a URL parsing library to canonicalize URLs before validation",
                    "Block requests to internal networks (127.0.0.0/8, 169.254.0.0/16, etc.)",
                    "Use network-level protections like firewalls to restrict server connections"
                ],
                'code_example': """
# Example of SSRF protection in Python:
import ipaddress
from urllib.parse import urlparse

def is_internal_ip(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        ip_addr = ipaddress.ip_address(ip)
        return (
            ip_addr.is_private or
            ip_addr.is_loopback or
            ip_addr.is_link_local
        )
    except:
        return False

def safe_request(url):
    parsed_url = urlparse(url)
    if is_internal_ip(parsed_url.netloc):
        raise ValueError("URL points to internal network")
    
    allowed_hosts = ['api.example.com', 'public-api.com']
    if parsed_url.netloc not in allowed_hosts:
        raise ValueError("URL hostname not in whitelist")
    
    # Make the request
    response = requests.get(url)
    return response
                """,
                'references': [
                    "OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                    "PortSwigger SSRF Guide: https://portswigger.net/web-security/ssrf"
                ]
            },
            'lfi': {
                'summary': "Protect against Local File Inclusion (LFI) by restricting file access and validating paths",
                'steps': [
                    "Implement strict input validation for file paths",
                    "Use a whitelist of allowed files or directories",
                    "Avoid using user input directly in file operations",
                    "Implement proper file access controls",
                    "Consider using a file abstraction layer instead of direct file system access"
                ],
                'code_example': """
# Example of safe file inclusion in PHP:
function safeInclude($file) {
    // Define the base directory for includes
    $baseDir = '/var/www/includes/';
    
    // Remove any path traversal attempts
    $file = basename($file);
    
    // Whitelist of allowed files
    $allowedFiles = ['header.php', 'footer.php', 'menu.php'];
    
    if (in_array($file, $allowedFiles) && file_exists($baseDir . $file)) {
        include($baseDir . $file);
        return true;
    }
    return false;
}

// Usage
$file = $_GET['include'];
if (!safeInclude($file)) {
    // Log the attempt and show error
    error_log("Potential LFI attempt: " . $file);
    include('error.php');
}
                """,
                'references': [
                    "OWASP File Inclusion Guide: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion"
                ]
            },
            'rfi': {
                'summary': "Protect against Remote File Inclusion (RFI) by disabling remote includes and validating sources",
                'steps': [
                    "Disable remote file includes if not needed (allow_url_include=Off in PHP)",
                    "Implement a whitelist of allowed external resources",
                    "Validate all URLs against the whitelist",
                    "Use content verification for included files",
                    "Consider alternatives to dynamic file inclusion"
                ],
                'code_example': """
# PHP configuration changes in php.ini:
allow_url_fopen = Off
allow_url_include = Off

# Example of safer dynamic inclusion in PHP:
function safeIncludeRemote($url) {
    // Whitelist of allowed domains
    $allowedDomains = ['trusted-cdn.com', 'company-repo.com'];
    
    // Parse the URL
    $parsed = parse_url($url);
    
    // Check if the domain is in the whitelist
    if (isset($parsed['host']) && in_array($parsed['host'], $allowedDomains)) {
        // Use file_get_contents with stream context to enforce HTTPS
        $context = stream_context_create([
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
            ],
        ]);
        
        $content = file_get_contents($url, false, $context);
        
        // Safety check on content
        if (strpos($content, '<?php') === false) {
            // Process the content
            return $content;
        }
    }
    
    return false;
}
                """,
                'references': [
                    "OWASP Remote File Inclusion Guide: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion"
                ]
            },
            'cve': {
                'summary': "Address known Common Vulnerabilities and Exposures (CVEs) by applying patches and updates",
                'steps': [
                    "Identify the specific CVE affecting your software",
                    "Update the affected software to the latest patched version",
                    "If patches are not available, implement temporary mitigations as recommended by the vendor",
                    "Set up a vulnerability management process to track and prioritize patching",
                    "Consider using a Web Application Firewall (WAF) to block exploitation attempts"
                ],
                'code_example': """
# Example of security patching process:
1. Set up automated vulnerability scanning:
   - Use tools like OWASP Dependency Check, Snyk, or GitHub Dependency Graph
   - Integrate scanning into CI/CD pipeline

2. Implement a patch management system:
   ```bash
   # Example update script for Linux server
   #!/bin/bash
   
   # Update package lists
   apt-get update
   
   # Apply security updates
   apt-get upgrade -y
   
   # Log the update
   echo "Security update applied on $(date)" >> /var/log/security-updates.log
   ```
                """,
                'references': [
                    "National Vulnerability Database: https://nvd.nist.gov/",
                    "OWASP Dependency Check: https://owasp.org/www-project-dependency-check/"
                ]
            },
            'outdated': {
                'summary': "Fix outdated software vulnerabilities by updating components and implementing security patches",
                'steps': [
                    "Inventory all software components and dependencies",
                    "Update to the latest stable and secure versions",
                    "Set up automated dependency checking",
                    "Implement a regular update schedule and policy",
                    "Consider containerization to isolate components and simplify updates"
                ],
                'code_example': """
# Example of automated dependency updates in Node.js:
# package.json
{
  "name": "your-app",
  "scripts": {
    "audit": "npm audit fix",
    "update-deps": "npm update",
    "security-check": "snyk test"
  },
  "devDependencies": {
    "snyk": "^1.500.0"
  }
}

# GitHub Actions Workflow for automated updates
name: Security Updates
on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sundays
jobs:
  update-dependencies:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Update dependencies
        run: npm update
      - name: Test changes
        run: npm test
      - name: Create Pull Request
        uses: peter-evans/create-pull-request@v3
        with:
          title: 'Dependency Updates'
          branch: 'automated-updates'
                """,
                'references': [
                    "OWASP Top 10 - A9:2017 Using Components with Known Vulnerabilities: https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities",
                    "Snyk - Dependency Vulnerability Scanner: https://snyk.io/"
                ]
            },
            'missing header': {
                'summary': "Implement security headers to improve web application defense against common attacks",
                'steps': [
                    "Implement Content-Security-Policy (CSP) header",
                    "Add X-XSS-Protection header",
                    "Set X-Content-Type-Options: nosniff header",
                    "Configure Strict-Transport-Security (HSTS) header",
                    "Add X-Frame-Options header to prevent clickjacking"
                ],
                'code_example': """
# Example security headers in Nginx:
server {
    listen 443 ssl;
    server_name example.com;
    
    # Security headers
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Other server configuration...
}

# Example security headers in Express.js:
const helmet = require('helmet');
app.use(helmet());
                """,
                'references': [
                    "OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/",
                    "Mozilla Observatory: https://observatory.mozilla.org/"
                ]
            },
            'information disclosure': {
                'summary': "Prevent sensitive information disclosure by controlling error messages and removing debugging info",
                'steps': [
                    "Configure custom error pages to avoid revealing system information",
                    "Remove version information from HTTP headers",
                    "Disable directory listings on web servers",
                    "Implement proper exception handling to avoid stack traces in responses",
                    "Remove comments containing sensitive information from client-side code"
                ],
                'code_example': """
# Example of custom error handling in Express.js:
app.use((err, req, res, next) => {
  // Log the error internally
  console.error(err);
  
  // Return a generic error message to the client
  res.status(500).json({
    status: 'error',
    message: 'An internal server error occurred'
  });
});

# Example of properly redacting sensitive information in logs:
function logSanitizer(logObject) {
  const sensitiveFields = ['password', 'token', 'ssn', 'creditCard', 'secret'];
  
  return Object.keys(logObject).reduce((acc, key) => {
    if (sensitiveFields.includes(key.toLowerCase())) {
      acc[key] = '[REDACTED]';
    } else {
      acc[key] = logObject[key];
    }
    return acc;
  }, {});
}
                """,
                'references': [
                    "OWASP Information Leakage Guide: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/07-Map_Application_Architecture"
                ]
            },
            'directory listing': {
                'summary': "Disable directory listing to prevent unauthorized browsing of server directories",
                'steps': [
                    "Disable directory listing in web server configuration",
                    "Create index files in all directories that need to be accessed",
                    "Configure a custom 403 Forbidden page",
                    "Use access controls to restrict directory access",
                    "Regularly audit accessible directories"
                ],
                'code_example': """
# Apache configuration (.htaccess):
Options -Indexes
ErrorDocument 403 /error/forbidden.html

# Nginx configuration:
server {
    # ...
    
    # Disable directory listing
    autoindex off;
    
    # Custom error page
    error_page 403 /error/forbidden.html;
    
    # ...
}
                """,
                'references': [
                    "OWASP Testing for Directory Traversal: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include"
                ]
            },
            'default credentials': {
                'summary': "Eliminate default credential vulnerabilities by changing passwords and implementing proper authentication",
                'steps': [
                    "Change all default credentials on all systems and components",
                    "Implement a strong password policy for all accounts",
                    "Set up multi-factor authentication (MFA) where possible",
                    "Audit system accounts regularly",
                    "Implement password rotation for service accounts"
                ],
                'code_example': """
# Example of strong password policy implementation in Node.js:
const passwordValidator = require('password-validator');

// Create a password schema
const passwordSchema = new passwordValidator();
passwordSchema
  .is().min(12)                                   // Minimum length 12
  .is().max(100)                                  // Maximum length 100
  .has().uppercase()                              // Must have uppercase letters
  .has().lowercase()                              // Must have lowercase letters
  .has().digits(2)                                // Must have at least 2 digits
  .has().not().spaces()                           // Should not have spaces
  .has().symbols(1)                               // Must have at least 1 symbol
  .is().not().oneOf(['Password123!', 'Admin123!']); // Blacklist common passwords

// Validate a password
function validatePassword(password) {
  return passwordSchema.validate(password, { list: true });
}
                """,
                'references': [
                    "OWASP Authentication Best Practices: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                    "NIST Password Guidelines: https://pages.nist.gov/800-63-3/sp800-63b.html"
                ]
            },
            'sensitive file': {
                'summary': "Protect sensitive files by removing them from publicly accessible locations and implementing access controls",
                'steps': [
                    "Remove sensitive files from web-accessible directories",
                    "Move configuration files outside the web root",
                    "Use environment variables for sensitive configuration",
                    "Implement proper file permissions",
                    "Use .gitignore to prevent committing sensitive files"
                ],
                'code_example': """
# Example .gitignore file:
# Ignore sensitive files
.env
.env.*
config/secrets.yml
credentials.json
private_key.pem
*.key
*.p12
*.pfx
*.password

# Example of using environment variables instead of config files:
# Instead of:
# database.json
{
  "host": "db.example.com",
  "username": "admin",
  "password": "super-secret-password"
}

# Use environment variables:
const dbConfig = {
  host: process.env.DB_HOST,
  username: process.env.DB_USER,
  password: process.env.DB_PASSWORD
};
                """,
                'references': [
                    "OWASP Sensitive Data Exposure: https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                    "The Twelve-Factor App - Config: https://12factor.net/config"
                ]
            },
            'ssl tls': {
                'summary': "Fix SSL/TLS vulnerabilities by configuring proper protocols, cipher suites, and certificates",
                'steps': [
                    "Disable outdated protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1)",
                    "Enable only strong cipher suites",
                    "Configure proper certificate validation",
                    "Implement HTTP Strict Transport Security (HSTS)",
                    "Use secure flag for cookies"
                ],
                'code_example': """
# Nginx secure TLS configuration:
server {
    listen 443 ssl;
    server_name example.com;
    
    # TLS configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    
    # ...
}
                """,
                'references': [
                    "Mozilla SSL Configuration Generator: https://ssl-config.mozilla.org/",
                    "OWASP Transport Layer Protection Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
                ]
            },
            'cors': {
                'summary': "Configure proper Cross-Origin Resource Sharing (CORS) policies to prevent unauthorized access",
                'steps': [
                    "Specify the exact origins that should be allowed access",
                    "Limit the HTTP methods allowed for cross-origin requests",
                    "Restrict which HTTP headers can be used",
                    "Control whether credentials can be included in cross-origin requests",
                    "Set appropriate caching directives for preflight responses"
                ],
                'code_example': """
# Example of secure CORS configuration in Express.js:
const cors = require('cors');

// Basic CORS configuration
app.use(cors({
  origin: ['https://example.com', 'https://www.example.com'],
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 600 // Cache preflight requests for 10 minutes
}));

# Example of CORS configuration in Nginx:
location /api/ {
  if ($request_method = 'OPTIONS') {
    add_header 'Access-Control-Allow-Origin' 'https://example.com';
    add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS';
    add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization';
    add_header 'Access-Control-Max-Age' '600';
    add_header 'Content-Type' 'text/plain; charset=utf-8';
    add_header 'Content-Length' '0';
    return 204;
  }
  
  add_header 'Access-Control-Allow-Origin' 'https://example.com';
  add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS';
  add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization';
  add_header 'Access-Control-Expose-Headers' 'Content-Length,Content-Range';
  
  # Pass to backend
  proxy_pass http://backend;
}
                """,
                'references': [
                    "OWASP CORS Guide: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html",
                    "MDN CORS: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
                ]
            }
        }
        
        # Find the most appropriate recommendation
        for vuln_type, recommendation in remediation_db.items():
            if vuln_type in vuln_name_lower or vuln_type in matcher_name_lower:
                return recommendation
        
        # Check for partial matches
        for vuln_type, recommendation in remediation_db.items():
            pattern = r'\b' + re.escape(vuln_type.split()[0]) + r'\b'
            if re.search(pattern, vuln_name_lower) or re.search(pattern, matcher_name_lower):
                return recommendation
        
        # Default generic recommendation if no specific match is found
        return {
            'summary': "Review and fix this vulnerability based on security best practices",
            'steps': [
                "Identify the root cause of the vulnerability",
                "Research OWASP guidelines for this type of issue",
                "Apply security patches or updates if available",
                "Implement appropriate input validation and output encoding",
                "Consider adding additional security controls"
            ],
            'code_example': """
# General security best practices:
1. Apply input validation
2. Use parameterized queries
3. Implement output encoding
4. Follow the principle of least privilege
5. Keep all software updated
            """,
            'references': [
                "OWASP Top 10: https://owasp.org/www-project-top-ten/",
                "SANS CWE Top 25: https://www.sans.org/top25-software-errors/"
            ]
        }

    def _prepare_ai_prompt(self):
        """Prepare a prompt for AI analysis with focus on remediation recommendations"""
        # Create a detailed prompt for the AI
        prompt = """You are a senior cybersecurity expert analyzing bug bounty scan results. 
Based on the following findings, provide a comprehensive analysis with detailed remediation steps.
Focus on actionable recommendations with code examples where appropriate.

Your response should include:
1. A concise summary of the most critical findings
2. Detailed remediation steps for each vulnerability, prioritized by severity
3. Code examples to fix the most critical issues
4. References to security best practices and standards
5. A recommended timeline for addressing each category of findings

"""
        
        # Add summary information
        if 'summary' in self.analysis:
            prompt += "\n## SCAN SUMMARY:\n"
            summary = self.analysis['summary']
            if 'subdomain_count' in summary:
                prompt += f"- {summary['subdomain_count']} subdomains discovered\n"
            if 'live_host_count' in summary:
                prompt += f"- {summary['live_host_count']} live hosts found\n"
            if 'open_port_count' in summary:
                prompt += f"- {summary['open_port_count']} open ports detected\n"
            if 'directory_count' in summary:
                prompt += f"- {summary['directory_count']} directories enumerated\n"
            if 'vulnerability_count' in summary:
                vuln_count = summary['vulnerability_count']
                prompt += f"- Vulnerabilities: {vuln_count.get('critical', 0)} critical, {vuln_count.get('high', 0)} high, {vuln_count.get('medium', 0)} medium, {vuln_count.get('low', 0)} low, {vuln_count.get('info', 0)} info\n"
            prompt += "\n"
        
        # Add vulnerabilities
        if 'vulnerabilities' in self.analysis.get('details', {}):
            prompt += "Vulnerabilities:\n"
            for vuln in self.analysis['details']['vulnerabilities']:
                prompt += f"- {vuln.get('title', 'Unknown')} ({vuln.get('severity', 'unknown').upper()}): {vuln.get('description', 'No description')}\n"
            prompt += "\n"
        
        # Add open ports
        if 'open_ports' in self.analysis.get('details', {}):
            prompt += "Open Ports:\n"
            for port in self.analysis['details']['open_ports']:
                prompt += f"- Port {port['port']}: {port['service']} ({port.get('version', 'unknown')})\n"
            prompt += "\n"
        
        # Add interesting directories
        if 'interesting_directories' in self.analysis.get('details', {}):
            prompt += "Interesting Directories:\n"
            for directory in self.analysis['details']['interesting_directories']:
                prompt += f"- {directory['url']} [Status: {directory.get('status', 'unknown')}]\n"
            prompt += "\n"
        
        # Add request for analysis
        prompt += "Based on these findings, please provide:\n"
        prompt += "1. A concise analysis of the security posture\n"
        prompt += "2. Prioritized recommendations (immediate, short-term, and long-term)\n"
        prompt += "3. Any patterns or notable security concerns\n"
        
        return prompt

    def _prepare_transformers_text(self):
        """Prepare text for transformers analysis"""
        # Create a summary of the findings
        text = "Bug bounty scan results summary: "
        
        # Add summary information
        if 'summary' in self.analysis:
            summary = self.analysis['summary']
            if 'subdomain_count' in summary:
                text += f"{summary['subdomain_count']} subdomains discovered. "
            if 'live_host_count' in summary:
                text += f"{summary['live_host_count']} live hosts found. "
            if 'open_port_count' in summary:
                text += f"{summary['open_port_count']} open ports detected. "
            if 'directory_count' in summary:
                text += f"{summary['directory_count']} directories enumerated. "
            if 'vulnerability_count' in summary:
                vuln_count = summary['vulnerability_count']
                text += f"Vulnerabilities: {vuln_count.get('critical', 0)} critical, {vuln_count.get('high', 0)} high, {vuln_count.get('medium', 0)} medium, {vuln_count.get('low', 0)} low, {vuln_count.get('info', 0)} info. "
        
        # Add top vulnerabilities
        if 'vulnerabilities' in self.analysis.get('details', {}):
            text += "Most critical vulnerabilities include: "
            high_severity_vulns = [v for v in self.analysis['details']['vulnerabilities'] 
                                  if v.get('severity', '').lower() in ['critical', 'high']]
            
            for i, vuln in enumerate(high_severity_vulns[:3]):  # Take top 3 critical/high vulns
                if i > 0:
                    text += ", "
                text += f"{vuln.get('title', 'Unknown')} ({vuln.get('severity', '').upper()})"
        
        # Add notable findings
        text += " Notable findings include "
        
        if 'interesting_directories' in self.analysis.get('details', {}) and self.analysis['details']['interesting_directories']:
            text += f"sensitive directories ({len(self.analysis['details']['interesting_directories'])} found), "
        
        if 'open_ports' in self.analysis.get('details', {}) and self.analysis['details']['open_ports']:
            common_services = []
            for port in self.analysis['details']['open_ports']:
                if port['service'] not in common_services:
                    common_services.append(port['service'])
            text += f"open services ({', '.join(common_services[:3])}), "
        
        # Clean up text
        text = text.rstrip(", ") + "."
        
        # Ensure the text is substantial enough for the model
        if len(text) < 100:
            logger.warning("Generated text is too short for transformers to analyze effectively")
            return None
        
        return text


def main():
    parser = argparse.ArgumentParser(description='BountyX AI Helper - Analyzes vulnerability scan results')
    parser.add_argument('--target', required=True, help='Target domain or IP')
    parser.add_argument('--input-dir', required=True, help='Input directory containing scan results')
    parser.add_argument('--output-format', default='json', choices=['json', 'txt', 'html'], help='Output format')
    args = parser.parse_args()
    
    logger.info(f"Starting BountyX AI Helper for target: {args.target}")
    logger.info(f"Using input directory: {args.input_dir}")
    logger.info(f"Output format: {args.output_format}")
    
    # Create AI helper instance
    ai_helper = BountyXAI(args.input_dir, args.output_format)
    
    # Load and analyze results
    if ai_helper.load_results():
        logger.info("Successfully loaded results")
        
        if ai_helper.analyze_results():
            logger.info("Successfully analyzed results")
            
            # Try to enhance with AI
            ai_helper.use_ai_for_analysis()
            
            # Generate recommendations and priorities
            if ai_helper.generate_recommendations():
                logger.info("Successfully generated recommendations")
                
                if ai_helper.prioritize_findings():
                    logger.info("Successfully prioritized findings")
                    
                    # Save results
                    if ai_helper.save_results(args.target):
                        logger.info("Successfully saved results")
                        return 0
    
    logger.error("AI Helper process failed")
    return 1


if __name__ == "__main__":
    sys.exit(main())
