# phishnet_x_international.py
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import requests
import re
import whois
import tldextract
import ssl
import socket
import datetime
from bs4 import BeautifulSoup
import threading
from urllib.parse import urlparse
from PIL import Image, ImageTk
import os
import base64
import geoip2.database
from datetime import datetime
import dns.resolver
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PhishNetXInternational:
    def __init__(self, root):
        self.root = root
        self.root.title("PhishNet X - Advanced Phishing Detection System")
        self.root.geometry("1400x900")
        self.root.configure(bg="#2a2a2e")

        # Create a requests session with proper SSL verification
        self.session = requests.Session()
        self.session.verify = True
        
        # API Keys
        self.virustotal_api_key = "6a1bb536e05a2385da5b1da68962e7c9d90b5cb278e372965c2e2b64f70604c6"
        self.whois_api_key = "Zlx3KliMIXYS0j6RCfZuKJpQaGEidQCz"

        # Security Engine Initialization
        self.detection_rules = self.load_detection_rules()
        self.geoip_reader = geoip2.database.Reader('data/GeoLite2-City.mmdb')

        # Configure Style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()

        self.setup_ui()
        self.setup_menu()

    def configure_styles(self):
        style_config = {
            'TFrame': {'configure': {'background': '#2a2a2e'}},
            'TNotebook': {'configure': {'background': '#2a2a2e', 'borderwidth': 0}},
            'TNotebook.Tab': {
                'configure': {
                    'background': '#3a3a3e',
                    'foreground': 'white',
                    'padding': [15, 5],
                    'font': ('Segoe UI', 10)
                },
                'map': {
                    'background': [('selected', '#007acc')],
                    'foreground': [('selected', 'white')]
                }
            },
            'TLabel': {'configure': {'background': '#2a2a2e', 'foreground': 'white'}},
            'TButton': {
                'configure': {
                    'background': '#007acc',
                    'foreground': 'white',
                    'font': ('Segoe UI', 10),
                    'borderwidth': 1
                },
                'map': {'background': [('active', '#005f9e')]}
            }
        }

        for element, config in style_config.items():
            self.style.configure(element, **config.get('configure', {}))
            if 'map' in config:
                self.style.map(element, **config['map'])

    def setup_ui(self):
        # Main Container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Header Section
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        # Logo and Title
        logo_img = Image.open("logo1.png").resize((60, 60))
        self.logo = ImageTk.PhotoImage(logo_img)
        ttk.Label(header_frame, image=self.logo).pack(side=tk.LEFT, padx=10)

        title_frame = ttk.Frame(header_frame)
        title_frame.pack(side=tk.LEFT)
        ttk.Label(title_frame, text="PhishNet X", font=('Segoe UI', 24, 'bold')).pack(anchor=tk.W)
        ttk.Label(title_frame, text="Advanced Phishing Detection System", font=('Segoe UI', 14)).pack(anchor=tk.W)

        # Analysis Notebook
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # URL Analysis Tab
        self.url_tab = ttk.Frame(self.notebook)
        self.setup_url_tab()
        self.notebook.add(self.url_tab, text="URL Analysis")

        # Email Analysis Tab
        self.email_tab = ttk.Frame(self.notebook)
        self.setup_email_tab()
        self.notebook.add(self.email_tab, text="Email Analysis")

        # Results Tab
        self.results_tab = ttk.Frame(self.notebook)
        self.setup_results_tab()
        self.notebook.add(self.results_tab, text="Analysis Results")

    def setup_url_tab(self):
        # URL Input Section
        input_frame = ttk.Frame(self.url_tab)
        input_frame.pack(pady=20, padx=20, fill=tk.X)

        ttk.Label(input_frame, text="Enter URL for Analysis:", font=('Segoe UI', 12)).pack(side=tk.LEFT)
        self.url_entry = ttk.Entry(input_frame, width=70)
        self.url_entry.pack(side=tk.LEFT, padx=10)
        ttk.Button(input_frame, text="Start Analysis", command=self.start_url_analysis).pack(side=tk.LEFT)

        # Status Frame
        status_frame = ttk.Frame(self.url_tab)
        status_frame.pack(fill=tk.X, padx=20, pady=(5, 10))

        # Analysis Status Label
        self.analysis_status = ttk.Label(
            status_frame,
            text="Ready",
            font=('Segoe UI', 11, 'bold'),
            foreground='#007acc',
            background='#2a2a2e'
        )
        self.analysis_status.pack(side=tk.LEFT, padx=(0, 10))

        # Status Bar
        self.status_bar = ttk.Label(
            status_frame,
            text="",
            font=('Segoe UI', 10),
            anchor=tk.W,
            padding=(5, 2)
        )
        self.status_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # URL Results Display
        results_frame = ttk.Frame(self.url_tab)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # Summary Frame (Moved to top of results)
        summary_frame = ttk.Frame(results_frame)
        summary_frame.pack(fill=tk.X, pady=(0, 10))

        self.risk_meter = ttk.Label(summary_frame, text="Security Risk: 0%", font=('Segoe UI', 14))
        self.risk_meter.pack(side=tk.LEFT, padx=20)

        self.verdict_label = ttk.Label(summary_frame, text="Final Verdict: ", font=('Segoe UI', 14))
        self.verdict_label.pack(side=tk.LEFT, padx=20)

        # Create a frame for the treeview and scrollbars
        tree_frame = ttk.Frame(results_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        # Detailed Results Treeview with scrollbars
        self.url_results_tree = ttk.Treeview(tree_frame, columns=('Check', 'Result'), show='headings')
        self.url_results_tree.heading('Check', text='Detection Check')
        self.url_results_tree.heading('Result', text='Result')
        self.url_results_tree.column('Check', width=400, minwidth=200)  # Detection check column
        self.url_results_tree.column('Result', width=600, minwidth=200)  # Result column

        # Add scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.url_results_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.url_results_tree.xview)
        self.url_results_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout for treeview and scrollbars
        self.url_results_tree.grid(column=0, row=0, sticky='nsew')
        vsb.grid(column=1, row=0, sticky='ns')
        hsb.grid(column=0, row=1, sticky='ew')

        # Configure grid weights
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)

        # Bind double-click event
        self.url_results_tree.bind('<Double-1>', self.show_detailed_result)

    def setup_email_tab(self):
        # Email Input Section
        input_frame = ttk.Frame(self.email_tab)
        input_frame.pack(pady=20, padx=20, fill=tk.X)

        # Sender's Address Section
        sender_frame = ttk.LabelFrame(input_frame, text="Sender's Email Address")
        sender_frame.pack(fill=tk.X, pady=(0, 10))
        self.sender_entry = ttk.Entry(sender_frame, width=80, font=('Segoe UI', 10))
        self.sender_entry.pack(padx=5, pady=5)

        # Subject Section
        subject_frame = ttk.LabelFrame(input_frame, text="Email Subject")
        subject_frame.pack(fill=tk.X, pady=(0, 10))
        self.subject_entry = ttk.Entry(subject_frame, width=80, font=('Segoe UI', 10))
        self.subject_entry.pack(padx=5, pady=5)

        # Email Body Section
        body_frame = ttk.LabelFrame(input_frame, text="Email Body (Include any links or suspicious content)")
        body_frame.pack(fill=tk.X, pady=(0, 10))
        self.body_text = scrolledtext.ScrolledText(body_frame, width=80, height=8, font=('Segoe UI', 10))
        self.body_text.pack(padx=5, pady=5)

        # Analysis Progress Frame
        progress_frame = ttk.Frame(input_frame)
        progress_frame.pack(fill=tk.X, pady=5)
        
        # Progress Label
        self.email_analysis_status = ttk.Label(
            progress_frame,
            text="Ready for Analysis",
            font=('Segoe UI', 11, 'bold'),
            foreground='#007acc'
        )
        self.email_analysis_status.pack(side=tk.LEFT, padx=5)

        # Analyze Button
        ttk.Button(progress_frame, text="Analyze Email", command=self.start_email_analysis).pack(side=tk.RIGHT, padx=5)

        # Results Section with more height due to reduced body space
        results_frame = ttk.LabelFrame(input_frame, text="Analysis Results")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        # Email Findings Text Area
        self.email_findings_text = scrolledtext.ScrolledText(results_frame, height=15, width=80, font=('Segoe UI', 10))
        self.email_findings_text.pack(pady=10, padx=5, fill=tk.BOTH, expand=True)
        self.email_findings_text.configure(state='disabled')

    def setup_results_tab(self):
        # Detailed Analysis Sections
        notebook = ttk.Notebook(self.results_tab)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Technical Details Frame
        tech_frame = ttk.Frame(notebook)
        self.setup_technical_panel(tech_frame)
        notebook.add(tech_frame, text="Technical Details")

        # Threat Intelligence Frame
        intel_frame = ttk.Frame(notebook)
        self.setup_intel_panel(intel_frame)
        notebook.add(intel_frame, text="Threat Intelligence")

    def setup_technical_panel(self, parent):
        # Technical Details Frame
        tech_frame = ttk.LabelFrame(parent, text="Technical Analysis")
        tech_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # DNS Information
        dns_frame = ttk.LabelFrame(tech_frame, text="DNS Information")
        dns_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.dns_info = {
            'IP Address': ttk.Label(dns_frame, text="IP: N/A", font=('Segoe UI', 10)),
            'DNS Records': ttk.Label(dns_frame, text="DNS: N/A", font=('Segoe UI', 10)),
            'Nameservers': ttk.Label(dns_frame, text="Nameservers: N/A", font=('Segoe UI', 10))
        }
        for label in self.dns_info.values():
            label.pack(fill=tk.X, padx=5, pady=2)

        # HTTP Response Information
        http_frame = ttk.LabelFrame(tech_frame, text="HTTP Response")
        http_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.http_info = {
            'Status': ttk.Label(http_frame, text="Status: N/A", font=('Segoe UI', 10)),
            'Server': ttk.Label(http_frame, text="Server: N/A", font=('Segoe UI', 10)),
            'Content-Type': ttk.Label(http_frame, text="Content-Type: N/A", font=('Segoe UI', 10))
        }
        for label in self.http_info.values():
            label.pack(fill=tk.X, padx=5, pady=2)

        # SSL Information
        ssl_frame = ttk.LabelFrame(tech_frame, text="SSL/TLS Information")
        ssl_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.ssl_info = {
            'Version': ttk.Label(ssl_frame, text="SSL Version: N/A", font=('Segoe UI', 10)),
            'Issuer': ttk.Label(ssl_frame, text="Issuer: N/A", font=('Segoe UI', 10)),
            'Valid Until': ttk.Label(ssl_frame, text="Valid Until: N/A", font=('Segoe UI', 10)),
            'Cipher': ttk.Label(ssl_frame, text="Cipher Suite: N/A", font=('Segoe UI', 10))
        }
        for label in self.ssl_info.values():
            label.pack(fill=tk.X, padx=5, pady=2)

    def setup_intel_panel(self, parent):
        # Threat Intelligence Frame
        intel_frame = ttk.LabelFrame(parent, text="Threat Intelligence Analysis")
        intel_frame.pack(fill=tk.X, padx=10, pady=5)

        # VirusTotal Results Section
        vt_frame = ttk.LabelFrame(intel_frame, text="VirusTotal Analysis")
        vt_frame.pack(fill=tk.X, padx=5, pady=5)

        # Create Treeview for VirusTotal results
        tree_frame = ttk.Frame(vt_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        self.vt_tree = ttk.Treeview(tree_frame, columns=('Engine', 'Result'), show='headings', height=6)
        self.vt_tree.heading('Engine', text='Engine')
        self.vt_tree.heading('Result', text='Result')
        self.vt_tree.column('Engine', width=200)
        self.vt_tree.column('Result', width=400)

        # Add scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.vt_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.vt_tree.xview)
        self.vt_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # Grid layout
        self.vt_tree.grid(column=0, row=0, sticky='nsew')
        vsb.grid(column=1, row=0, sticky='ns')
        hsb.grid(column=0, row=1, sticky='ew')

        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)

        # Domain Age Section
        domain_frame = ttk.LabelFrame(intel_frame, text="Domain Information")
        domain_frame.pack(fill=tk.X, padx=5, pady=5)

        self.domain_info = {
            'Age': ttk.Label(domain_frame, text="Domain Age: N/A", font=('Segoe UI', 10)),
            'Registration': ttk.Label(domain_frame, text="Registration Date: N/A", font=('Segoe UI', 10)),
            'Reputation': ttk.Label(domain_frame, text="Domain Reputation: N/A", font=('Segoe UI', 10))
        }
        for label in self.domain_info.values():
            label.pack(fill=tk.X, padx=5, pady=2)

        # WHOIS Information Section
        whois_frame = ttk.LabelFrame(intel_frame, text="WHOIS Information")
        whois_frame.pack(fill=tk.X, padx=5, pady=5)

        self.whois_text = scrolledtext.ScrolledText(whois_frame, height=6, font=('Segoe UI', 10))
        self.whois_text.pack(fill=tk.X, padx=5, pady=5)
        # Make WHOIS information read-only
        self.whois_text.configure(state='disabled')

        # Geolocation Information Section
        geo_frame = ttk.LabelFrame(intel_frame, text="Geolocation Information")
        geo_frame.pack(fill=tk.X, padx=5, pady=5)

        self.geo_labels = {
            'Country': ttk.Label(geo_frame, text="Country: N/A", font=('Segoe UI', 10)),
            'City': ttk.Label(geo_frame, text="City: N/A", font=('Segoe UI', 10)),
            'Coordinates': ttk.Label(geo_frame, text="Coordinates: N/A", font=('Segoe UI', 10)),
            'Timezone': ttk.Label(geo_frame, text="Timezone: N/A", font=('Segoe UI', 10))
        }
        for label in self.geo_labels.values():
            label.pack(fill=tk.X, padx=5, pady=2)

    def setup_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Report", command=self.export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        # Help Menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="User Guide", command=self.show_help)
        help_menu.add_command(label="About", command=self.show_about)

    def update_technical_info(self, url):
        """Update technical information with improved error handling."""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            if not domain:
                self.status_bar.config(text="Invalid domain")
                return

            try:
                # Try to resolve domain first
                ip_address = socket.gethostbyname(domain)
                
                # Update DNS Info
                self.dns_info['IP Address'].config(text=f"IP: {ip_address}")
                
                try:
                    dns_records = dns.resolver.resolve(domain, 'A')
                    records_text = ", ".join([str(record) for record in dns_records])
                    self.dns_info['DNS Records'].config(text=f"DNS: {records_text}")
                except Exception as e:
                    self.dns_info['DNS Records'].config(text="DNS: No records found")
                
                try:
                    nameservers = dns.resolver.resolve(domain, 'NS')
                    ns_text = ", ".join([str(ns) for ns in nameservers])
                    self.dns_info['Nameservers'].config(text=f"Nameservers: {ns_text}")
                except Exception as e:
                    self.dns_info['Nameservers'].config(text="Nameservers: No records found")

                # Get HTTP Response Information
                try:
                    # Try with SSL verification first
                    try:
                        response = self.session.head(url, timeout=5)
                    except requests.exceptions.SSLError:
                        response = self.session.head(url, timeout=5, verify=False)
                        self.http_info['Status'].config(text="Status: SSL Certificate Invalid")
                    else:
                        self.http_info['Status'].config(text=f"Status: {response.status_code} {response.reason}")
                    
                    self.http_info['Server'].config(text=f"Server: {response.headers.get('Server', 'Not specified')}")
                    self.http_info['Content-Type'].config(text=f"Content-Type: {response.headers.get('Content-Type', 'Not specified')}")
                except requests.exceptions.RequestException as e:
                    self.http_info['Status'].config(text="Status: Connection failed")
                    self.http_info['Server'].config(text="Server: N/A")
                    self.http_info['Content-Type'].config(text="Content-Type: N/A")

            except socket.gaierror:
                # Update UI to show domain is unreachable
                self.dns_info['IP Address'].config(text="IP: Domain unreachable")
                self.dns_info['DNS Records'].config(text="DNS: Domain unreachable")
                self.dns_info['Nameservers'].config(text="Nameservers: Domain unreachable")
                self.http_info['Status'].config(text="Status: Domain unreachable")
                self.http_info['Server'].config(text="Server: N/A")
                self.http_info['Content-Type'].config(text="Content-Type: N/A")

        except Exception as e:
            print(f"Error updating technical info: {str(e)}")
            self.status_bar.config(text=f"Error updating technical information: {str(e)}")

    def get_ssl_certificate(self, url):
        """Get SSL certificate information with improved error handling."""
        results = {
            'version': 'N/A',
            'issuer': 'N/A',
            'valid_until': 'N/A',
            'cipher': 'N/A',
            'status': 'N/A'
        }

        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            if not domain:
                results['status'] = 'Invalid domain'
                return results

            # First check if domain resolves
            try:
                socket.gethostbyname(domain)
            except socket.gaierror:
                results['status'] = 'Domain unreachable'
                return results

            # Now try to get SSL info
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    results['version'] = ssock.version()
                    results['cipher'] = ssock.cipher()[0] if ssock.cipher() else 'N/A'
                    
                    if cert:
                        issuer = dict(x[0] for x in cert['issuer'])
                        results['issuer'] = issuer.get('organizationName', issuer.get('commonName', 'N/A'))
                        results['valid_until'] = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').strftime('%Y-%m-%d')
                        results['status'] = 'Valid'

            return results

        except ssl.SSLError as e:
            results['status'] = f'SSL Error: {str(e)}'
            return results
        except socket.timeout:
            results['status'] = 'Connection timeout'
            return results
        except Exception as e:
            print(f"Error retrieving SSL certificate: {str(e)}")
            results['status'] = f'Error: {str(e)}'
            return results

    def run_url_analysis(self, url):
        """Run URL analysis in a separate thread with proper thread synchronization."""
        try:
            # Store results in instance variables to avoid thread issues
            self.analysis_results = {
                'basic_checks': self.check_basic_url_patterns(url),
                'security_checks': self.check_security_features(url),
                'content_analysis': self.analyze_web_content(url),
                'reputation': self.check_url_reputation(url),
                'geo_data': self.get_geoip_info(url),
                'ssl_info': self.get_ssl_certificate(url),
                'whois_data': self.get_whois_info(url),
                'domain_info': self.get_domain_info(url)
            }

            total_score = sum([v.get('score', 0) for v in self.analysis_results.values()])

            # Use a queue to safely communicate between threads
            def update_gui():
                try:
                    # Update technical information
                    self.update_technical_info(url)
                    
                    # Update results
                    self.update_url_results(self.analysis_results, total_score)
                    
                    # Update status
                    self.status_bar.config(text="Analysis Complete")
                    self.analysis_status.config(
                        text="✓ Analysis Complete",
                        foreground='#00ff00'
                    )
                except Exception as gui_error:
                    print(f"Error updating GUI: {str(gui_error)}")
                    self.show_analysis_error(f"Error updating results: {str(gui_error)}")
                    self.analysis_status.config(
                        text="❌ Analysis Failed",
                        foreground='#ff0000'
                    )

            # Schedule GUI updates in the main thread
            if not self.root.winfo_exists():
                return
            self.root.after(0, update_gui)

        except Exception as e:
            print(f"Analysis error: {str(e)}")
            if self.root.winfo_exists():
                self.root.after(0, lambda: self.show_analysis_error(str(e)))
                self.root.after(0, lambda: self.analysis_status.config(
                    text="❌ Analysis Failed",
                    foreground='#ff0000'
                ))

    def start_url_analysis(self):
        """Start URL analysis with proper input validation and thread handling."""
        url = self.url_entry.get().strip()
        
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL.")
            return
            
        if not self.validate_url(url):
            messagebox.showerror("Invalid URL", "Please enter a valid URL (e.g., https://example.com)")
            return

        # Reset previous results
        self.risk_meter.config(text="Security Risk: 0%")
        self.verdict_label.config(text="Final Verdict: Analyzing...", foreground='#007acc')
        
        # Clear previous results from Treeview
        for item in self.url_results_tree.get_children():
            self.url_results_tree.delete(item)
            
        # Clear VirusTotal results
        for item in self.vt_tree.get_children():
            self.vt_tree.delete(item)
        
        # Reset domain information
        for label in self.domain_info.values():
            label.config(text=label['text'].split(':')[0] + ": N/A")
            
        # Reset WHOIS information
        self.whois_text.configure(state='normal')
        self.whois_text.delete(1.0, tk.END)
        self.whois_text.configure(state='disabled')
        
        # Reset geolocation information
        for label in self.geo_labels.values():
            label.config(text=label['text'].split(':')[0] + ": N/A")

        # Reset SSL information
        for label in self.ssl_info.values():
            label.config(text=label['text'].split(':')[0] + ": N/A")

        # Update status indicators
        self.status_bar.config(text="Analyzing URL...")
        self.analysis_status.config(
            text="⟳ Analysis in Progress",
            foreground='#007acc'
        )
        
        # Start analysis in a separate thread
        analysis_thread = threading.Thread(target=self.run_url_analysis, args=(url,), daemon=True)
        analysis_thread.start()

    def start_email_analysis(self):
        """Start email analysis with proper reset and thread handling."""
        # Get values from the separate input fields
        sender = self.sender_entry.get().strip()
        subject = self.subject_entry.get().strip()
        body = self.body_text.get("1.0", tk.END).strip()

        # Basic validation
        if not sender or not subject or not body:
            messagebox.showwarning("Input Error", "Please fill in all fields (Sender, Subject, and Body).")
            return

        try:
            # Reset status and clear previous results
            self.email_analysis_status.config(
                text="⟳ Analysis in Progress",
                foreground='#007acc'
            )

            # Clear and reset the findings text
            self.email_findings_text.configure(state='normal')
            self.email_findings_text.delete(1.0, tk.END)
            
            # Show analyzing message
            self.email_findings_text.tag_configure('header', font=('Segoe UI', 10, 'bold'))
            self.email_findings_text.insert(1.0, "⟳ Analyzing email...\n\n", 'header')
            self.email_findings_text.insert(tk.END, "Please wait while we check for suspicious patterns...\n")
            
            # Configure tags for different risk levels (reset them)
            self.email_findings_text.tag_configure('high_risk', foreground='#ff0000')  # Red
            self.email_findings_text.tag_configure('medium_risk', foreground='#ffa500')  # Orange
            self.email_findings_text.tag_configure('low_risk', foreground='#ffcc00')  # Yellow
            self.email_findings_text.tag_configure('safe', foreground='#00cc00')  # Green
            
            self.email_findings_text.see(1.0)  # Scroll to top
            self.email_findings_text.configure(state='disabled')
            
            # Force update the UI
            self.email_findings_text.update()
            self.root.update_idletasks()

            # Create headers dictionary
            headers = {
                'from': sender,
                'subject': subject,
                'content-type': 'text/plain'
            }

            # Start analysis in a separate thread with daemon=True
            analysis_thread = threading.Thread(
                target=self.run_email_analysis,
                args=(sender, subject, body, headers),
                daemon=True
            )
            analysis_thread.start()
        
        except Exception as e:
            self.email_findings_text.configure(state='normal')
            self.email_findings_text.delete(1.0, tk.END)
            self.email_findings_text.insert(1.0, f"Error starting analysis: {str(e)}")
            self.email_findings_text.configure(state='disabled')
            self.email_analysis_status.config(
                text="❌ Analysis Failed",
                foreground='#ff0000'
            )

    def run_email_analysis(self, sender, subject, body, headers):
        """Run email analysis in a separate thread with proper thread synchronization."""
        try:
            # Perform email analysis
            analysis_results = self.analyze_email(subject, sender, body, headers)

            # Update UI with results in the main thread
            def update_gui():
                try:
                    self.update_email_results(analysis_results)
                    self.email_analysis_status.config(
                text="✓ Analysis Complete",
                foreground='#00ff00'
                    )
                except Exception as gui_error:
                    print(f"Error updating email results: {str(gui_error)}")
                    self.email_findings_text.configure(state='normal')
                    self.email_findings_text.delete(1.0, tk.END)
                    self.email_findings_text.insert(1.0, f"Error displaying results: {str(gui_error)}")
                    self.email_findings_text.configure(state='disabled')
                    self.email_analysis_status.config(
                        text="❌ Analysis Failed",
                        foreground='#ff0000'
                    )

            # Schedule GUI updates in the main thread
            if not self.root.winfo_exists():
                return
            self.root.after(0, update_gui)
        
        except Exception as e:
            print(f"Email analysis error: {str(e)}")
            if self.root.winfo_exists():
                self.root.after(0, lambda: self.email_findings_text.configure(state='normal'))
                self.root.after(0, lambda: self.email_findings_text.delete(1.0, tk.END))
                self.root.after(0, lambda: self.email_findings_text.insert(1.0, f"Analysis Error: {str(e)}\n"))
                self.root.after(0, lambda: self.email_findings_text.configure(state='disabled'))
                self.root.after(0, lambda: self.email_analysis_status.config(
                    text="❌ Analysis Failed",
                    foreground='#ff0000'
                ))

    def analyze_email(self, subject, sender, body, headers):
        results = {
            'suspicious_patterns': [],
            'risk_score': 0,
            'header_analysis': {},
            'content_analysis': {},
            'sender_analysis': {},
            'links_analysis': {},
            'attachment_analysis': {}
        }

        try:
            # 1. Enhanced Sender Analysis
            if sender:
                try:
                    domain = sender.split('@')[-1].lower() if '@' in sender else ''
                    sender_name = sender.split('@')[0].lower()
                    
                    # List of major financial institutions and their domains
                    financial_domains = {
                        'bankofamerica': 'bankofamerica.com',
                        'chase': 'chase.com',
                        'wellsfargo': 'wellsfargo.com',
                        'citibank': 'citi.com',
                        'paypal': 'paypal.com',
                        'capitalone': 'capitalone.com'
                    }
                    
                    # Check for typosquatting in financial domains
                    for brand, real_domain in financial_domains.items():
                        if brand in domain.replace('-', '').replace('.', '').lower():
                            if domain != real_domain:
                                results['suspicious_patterns'].append(f"⚠️ CRITICAL: Suspicious sender domain - Possible impersonation of {brand.title()}")
                                results['suspicious_patterns'].append(f"⚠️ Found: {domain} | Legitimate domain: {real_domain}")
                                results['risk_score'] += 45
                    
                    # Check for deceptive sender names
                    suspicious_sender_keywords = {
                        r'support|security|admin|service': ("Generic service account", 15),
                        r'verify|confirm|secure': ("Action-requiring sender", 15),
                        r'account|billing|payment': ("Financial-related sender", 20),
                        r'urgent|immediate|restricted': ("Urgency-indicating sender", 25)
                    }
                    
                    for pattern, (description, score) in suspicious_sender_keywords.items():
                        if re.search(pattern, sender_name, re.IGNORECASE):
                            if domain not in self.detection_rules.get('trusted_domains', []):
                                results['suspicious_patterns'].append(f"⚠️ WARNING: {description}: {sender_name}")
                                results['risk_score'] += score

                except Exception as e:
                    print(f"Error in sender analysis: {str(e)}")

            # 2. Enhanced Subject Analysis
            if subject:
                # Check for urgency and action-required language
                urgent_patterns = {
                    r'(?:immediate|urgent|critical).*(?:action|attention|required)': ("Urgent action requirement", 30),
                    r'(?:verify|confirm|validate).*(?:account|identity)': ("Account verification request", 25),
                    r'(?:security|suspicious).*(?:alert|activity)': ("Security alert", 25),
                    r'(?:access|account).*(?:restricted|limited|blocked)': ("Account restriction threat", 35),
                    r'(?:expired|expiring|expires)': ("Expiration threat", 20)
                }

                for pattern, (description, score) in urgent_patterns.items():
                    if re.search(pattern, subject, re.IGNORECASE):
                        results['suspicious_patterns'].append(f"⚠️ HIGH RISK: {description} in subject")
                        results['risk_score'] += score

            # 3. Enhanced Body Content Analysis
            if body:
                # Check for URLs
                urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
                for url in urls:
                    parsed_url = urlparse(url)
                    url_domain = parsed_url.netloc.lower()
                    
                    # Check for deceptive URLs
                    for brand, real_domain in financial_domains.items():
                        if brand in url_domain.replace('-', '').replace('.', '').lower():
                            if real_domain not in url_domain:
                                results['suspicious_patterns'].append(f"⚠️ CRITICAL: Suspicious URL - Possible {brand.title()} website impersonation")
                                results['suspicious_patterns'].append(f"⚠️ Found URL: {url_domain}")
                                results['risk_score'] += 40

                # Check for threatening language and urgency
                threat_patterns = {
                    r'(?:permanent|immediate).*(?:restrict|limit|block)': ("Account restriction threat", 35),
                    r'within.*(?:hour|day).*(?:restrict|limit|block)': ("Time-pressure threat", 30),
                    r'(?:verify|confirm).*(?:immediately|urgently)': ("Urgent verification request", 25),
                    r'(?:unusual|suspicious).*(?:activity|login|access)': ("Security threat language", 20),
                    r'(?:failure|fail).*(?:result|lead).*(?:restrict|limit)': ("Consequence threat", 30)
                }

                for pattern, (description, score) in threat_patterns.items():
                    if re.search(pattern, body, re.IGNORECASE):
                        results['suspicious_patterns'].append(f"⚠️ HIGH RISK: {description} in message body")
                        results['risk_score'] += score

                # Check for sensitive information requests
                sensitive_patterns = {
                    r'(?:verify|confirm|update).*(?:information|details)': ("Information verification request", 20),
                    r'(?:click|follow).*(?:link|button)': ("Action link request", 15),
                    r'(?:personal|account).*(?:details|information)': ("Personal information request", 25)
                }

                for pattern, (description, score) in sensitive_patterns.items():
                    if re.search(pattern, body, re.IGNORECASE):
                        results['suspicious_patterns'].append(f"⚠️ WARNING: {description}")
                        results['risk_score'] += score

            # Normalize final risk score with more granular thresholds
            max_base_score = 100
            results['risk_score'] = min(100, (results['risk_score'] / max_base_score) * 100)

            # Adjust verdict thresholds
            if results['risk_score'] >= 75:
                results['verdict'] = '🔴 HIGH RISK - Likely Phishing'
            elif results['risk_score'] >= 50:
                results['verdict'] = '🟡 MEDIUM RISK - Suspicious'
            elif results['risk_score'] >= 25:
                results['verdict'] = '🟠 LOW RISK - Some Concerns'
            else:
                results['verdict'] = '🟢 SAFE - Likely Legitimate'

            if not results['suspicious_patterns']:
                results['suspicious_patterns'].append("No suspicious patterns detected.")

            return results

        except Exception as e:
            print(f"Error in email analysis: {str(e)}")
            results['suspicious_patterns'].append(f"Analysis error: {str(e)}")
            return results

    def is_new_domain(self, domain):
        """Check if a domain is less than 30 days old."""
        try:
            if not domain:
                return False
                
            domain_info = whois.whois(domain)
            if not domain_info.creation_date:
                return False
                
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                
            age = (datetime.now() - creation_date).days
            return age < 30
        except Exception as e:
            print(f"Error checking domain age: {str(e)}")
            return False

    def is_typosquatting(self, domain):
        """Check if a domain might be typosquatting."""
        try:
            if not domain:
                return False
                
            # List of commonly targeted domains
            common_domains = [
                'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
                'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com',
                'google.com', 'linkedin.com', 'paypal.com', 'chase.com'
            ]
            
            # Check for common typosquatting patterns
            for target_domain in common_domains:
                # Exact character replacement (e.g., 'l' with '1')
                if domain.replace('1', 'l') == target_domain or domain.replace('0', 'o') == target_domain:
                    return True
                    
                # Similar looking domain
                if self.calculate_domain_similarity(domain, target_domain) > 0.85:
                    return True
                    
                # Character insertion/deletion
                if len(domain) == len(target_domain) + 1 or len(domain) == len(target_domain) - 1:
                    if self.calculate_domain_similarity(domain, target_domain) > 0.9:
                        return True
            
            return False
            
        except Exception as e:
            print(f"Error checking typosquatting: {str(e)}")
            return False

    def calculate_domain_similarity(self, domain1, domain2):
        # Calculate Levenshtein distance between domains
        def levenshtein(s1, s2):
            if len(s1) < len(s2):
                return levenshtein(s2, s1)
            if len(s2) == 0:
                return len(s1)
            previous_row = range(len(s2) + 1)
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row
            return previous_row[-1]

        # Normalize the similarity score
        max_len = max(len(domain1), len(domain2))
        if max_len == 0:
            return 0
        distance = levenshtein(domain1.lower(), domain2.lower())
        return 1 - (distance / max_len)

    def update_email_results(self, results):
        # Enable text widget for updating
        self.email_findings_text.configure(state='normal')
        
        # Clear previous results
        self.email_findings_text.delete('1.0', tk.END)
        
        # Display header with current timestamp
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.email_findings_text.insert(tk.END, f"=== Email Analysis Results ({current_time}) ===\n\n")
        
        # Display risk score and verdict with color coding
        risk_score = results['risk_score']
        
        # Configure tags for different risk levels
        self.email_findings_text.tag_configure('high_risk', foreground='#ff0000')  # Red
        self.email_findings_text.tag_configure('medium_risk', foreground='#ffa500')  # Orange
        self.email_findings_text.tag_configure('low_risk', foreground='#ffcc00')  # Yellow
        self.email_findings_text.tag_configure('safe', foreground='#00cc00')  # Green
        self.email_findings_text.tag_configure('header', font=('Segoe UI', 10, 'bold'))
        
        self.email_findings_text.insert(tk.END, f"Risk Score: {risk_score}%\n", 'header')
        self.email_findings_text.insert(tk.END, f"Verdict: {results['verdict']}\n\n", 'header')

        # Display detailed findings with color coding
        if results['suspicious_patterns']:
            self.email_findings_text.insert(tk.END, "Suspicious Patterns Detected:\n", 'header')
            for pattern in results['suspicious_patterns']:
                if "CRITICAL" in pattern:
                    self.email_findings_text.insert(tk.END, f"• {pattern}\n", 'high_risk')
                elif "HIGH RISK" in pattern:
                    self.email_findings_text.insert(tk.END, f"• {pattern}\n", 'high_risk')
                elif "WARNING" in pattern:
                    self.email_findings_text.insert(tk.END, f"• {pattern}\n", 'medium_risk')
                elif "No suspicious patterns detected" in pattern:
                    self.email_findings_text.insert(tk.END, f"• {pattern}\n", 'safe')
                else:
                    self.email_findings_text.insert(tk.END, f"• {pattern}\n")
        else:
            self.email_findings_text.insert(tk.END, "No suspicious patterns detected.\n", 'safe')
        
        # Add a separator line
        self.email_findings_text.insert(tk.END, "\n" + "="*50 + "\n")
        
        # Disable text widget to make it read-only
        self.email_findings_text.configure(state='disabled')

    def update_url_results(self, results, total_score):
        try:
            # Clear previous results
            for item in self.url_results_tree.get_children():
                self.url_results_tree.delete(item)

            # Clear VirusTotal results
            self.vt_tree.delete(*self.vt_tree.get_children())

            # Add total risk score as first row
            self.url_results_tree.insert('', 'end', values=("Total Risk Score", f"{total_score} points"))

            # Get domain from results
            url = results.get('url', self.url_entry.get().strip())
            parsed_url = urlparse(url)
            domain = parsed_url.netloc

            # Process and display results
            for category in ['basic_checks', 'security_checks', 'content_analysis', 'reputation', 'geo_data', 'ssl_info', 'whois_data']:
                if category in results:
                    category_data = results[category]
                    if isinstance(category_data, dict):
                        if 'results' in category_data:
                            for check, result in category_data['results']:
                                self.url_results_tree.insert('', 'end', values=(check, result))
                        else:
                            filtered_data = {k: v for k, v in category_data.items() if k not in ['score', 'risk_score', 'error']}
                            for key, value in filtered_data.items():
                                display_key = key.replace('_', ' ').title()
                                self.url_results_tree.insert('', 'end', values=(display_key, value))

            # Update VirusTotal results in the Threat Intelligence tab
            if 'reputation' in results:
                vt_data = results['reputation']
                if isinstance(vt_data, dict):
                    if 'error' in vt_data:
                        self.vt_tree.insert('', 'end', values=("Status", "No VirusTotal data available"))
                    else:
                        for key, value in vt_data.items():
                            if key not in ['score', 'error', 'details']:
                                display_key = key.replace('_', ' ').title()
                                self.vt_tree.insert('', 'end', values=(display_key, str(value)))

            # Update domain information in the Threat Intelligence tab
            if 'domain_info' in results:
                domain_data = results['domain_info']
                self.update_domain_info(domain_data)

            # Update WHOIS information
            if 'whois_data' in results:
                whois_data = results['whois_data']
                self.whois_text.configure(state='normal')
                self.whois_text.delete(1.0, tk.END)
                if isinstance(whois_data, dict):
                    if 'error' in whois_data:
                        self.whois_text.insert(tk.END, "WHOIS information unavailable\n")
                    else:
                        for key, value in whois_data.items():
                            if key not in ['error', 'score', 'risk_score', 'risk_factors']:
                                if isinstance(value, (list, tuple)):
                                    value = ', '.join(map(str, value))
                                self.whois_text.insert(tk.END, f"{key.replace('_', ' ').title()}: {value}\n")
                self.whois_text.configure(state='disabled')

            # Update geolocation information
            if 'geo_data' in results:
                geo_data = results['geo_data']
                self.update_geo_info(geo_data)

            # Update SSL information
            if 'ssl_info' in results:
                ssl_data = results['ssl_info']
                self.update_ssl_info(ssl_data)

            # Update risk meter
            risk_percent = min(100, total_score)
            self.risk_meter.config(text=f"Security Risk: {risk_percent}%")

            # Determine final verdict with adjusted thresholds
            if not domain:
                final_verdict = "Invalid URL"
                color = "#ff0000"
            elif any('getaddrinfo failed' in str(v) for v in results.values() if isinstance(v, dict) and 'error' in v):
                final_verdict = "Domain Unreachable"
                color = "#ff0000"
            elif risk_percent >= 40:  # Increased threshold for high risk
                final_verdict = "High Risk"
                color = "#ff0000"
            elif risk_percent >= 25:  # Adjusted medium risk threshold
                final_verdict = "Medium Risk"
                color = "#ffa500"
            elif risk_percent >= 10:  # Adjusted low risk threshold
                final_verdict = "Likely Safe"
                color = "#ffcc00"
            else:
                final_verdict = "Totally Safe"
                color = "#00ff00"

            # Update verdict label
            self.verdict_label.config(text=f"Final Verdict: {final_verdict}", foreground=color)

            # Update status
            self.analysis_status.config(
                text="✓ Analysis Complete",
                foreground='#00ff00'
            )

        except Exception as e:
            self.verdict_label.config(text="Final Verdict: Error in analysis", foreground="#ff0000")
            self.analysis_status.config(text="❌ Analysis Failed", foreground='#ff0000')
            print(f"Error updating results: {str(e)}")

    def update_ssl_info(self, ssl_data):
        """Update SSL information with improved error handling."""
        try:
            # Map the SSL data fields to our UI labels
            field_mapping = {
                'Version': 'version',
                'Issuer': 'issuer',
                'Valid Until': 'valid_until',
                'Cipher': 'cipher'
            }
            
            for ui_field, data_field in field_mapping.items():
                if ui_field in self.ssl_info:
                    value = ssl_data.get(data_field, 'N/A')
                    self.ssl_info[ui_field].config(text=f"{ui_field}: {value}")

            # Update status if available
            if 'status' in ssl_data:
                status = ssl_data['status']
                if status != 'Valid':
                    for label in self.ssl_info.values():
                        label.config(foreground='#ff0000')  # Red for invalid/error
                else:
                    for label in self.ssl_info.values():
                        label.config(foreground='#00ff00')  # Green for valid
        except Exception as e:
            print(f"Error updating SSL info: {str(e)}")
            for label in self.ssl_info.values():
                label.config(text=f"{label['text'].split(':')[0]}: Error updating SSL information")

    def update_whois_info(self, whois_data):
        # Enable widget temporarily for updating
        self.whois_text.configure(state='normal')
        # Clear previous results
        self.whois_text.delete(1.0, tk.END)
        for key, value in whois_data.items():
            self.whois_text.insert(tk.END, f"{key}: {value}\n")
        # Make widget read-only again
        self.whois_text.configure(state='disabled')

    def update_geo_info(self, geo_data):
        self.geo_labels['Country'].config(text=f"Country: {geo_data.get('country', 'N/A')}")
        self.geo_labels['City'].config(text=f"City: {geo_data.get('city', 'N/A')}")
        self.geo_labels['Coordinates'].config(text=f"Coordinates: {geo_data.get('coordinates', 'N/A')}")
        self.geo_labels['Timezone'].config(text=f"Timezone: {geo_data.get('timezone', 'N/A')}")

    def validate_url(self, url):
        """Validate URL with improved error handling."""
        try:
            # Add http:// if no scheme is provided
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url

            result = urlparse(url)
            return bool(result.scheme in ['http', 'https'] and result.netloc)
        except:
            return False

    def export_report(self):
        # Implementation for report generation
        pass

    def show_about(self):
        messagebox.showinfo("About PhishNet X", 
            "Advanced Phishing Detection System\nVersion 2.1\n\nCybersecurity International")

    def show_help(self):
        help_text = """User Guide:
1. Enter URL in the URL Analysis tab
2. Click 'Start Analysis' for comprehensive scan
3. Review detailed technical findings
4. Use Email Analysis for suspicious """    

    def load_detection_rules(self):
        return {
            'suspicious_keywords': ['login', 'account', 'security', 'bank', 'verify'],
            'suspicious_tlds': [
                # Known malicious TLDs
                'tk', 'xyz', 'top', 'icu', 'gq', 'ml', 'ga', 'cf', 'pw',
                # Uncommon TLDs often used in phishing
                'info', 'biz', 'su', 'ws', 'name', 'work', 'click', 'loan',
                # Country TLDs sometimes abused
                'ru', 'cn', 'to', 'cc'
            ],
            'trusted_domains': [
                # Government Domains
                'irs.gov', 'usa.gov', 'treasury.gov', 'medicare.gov', 'sba.gov',
                # Major email providers
                'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'protonmail.com',
                # Major companies
                'microsoft.com', 'apple.com', 'amazon.com', 'google.com', 'facebook.com',
                'linkedin.com', 'twitter.com', 'instagram.com',
                # Banks and Financial
                'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com', 'paypal.com',
                # Cloud Services
                'dropbox.com', 'box.com', 'icloud.com', 'onedrive.com', 'drive.google.com'
            ],
            'government_keywords': [
                'irs', 'internal revenue', 'tax', 'refund', 'treasury', 'government',
                'federal', 'medicare', 'social security', 'ssn', 'stimulus'
            ],
            'legitimate_action_words': [
                'confirm your subscription', 'verify your email', 'reset your password',
                'activate your account', 'complete your registration', 'update your profile',
                'track your package', 'view your statement', 'access your account'
            ],
            'suspicious_domain_patterns': {
                'homograph': ['xn--', '⁰', '¹', '²', '³', '⁴', '⁵', '⁶', '⁷', '⁸', '⁹'],
                'combosquatting': ['secure-', 'login-', 'account-', 'support-', 'verify-'],
                'bitsquatting': ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'],
                'common_misspellings': {
                    'com': ['con', 'cpm', 'cm', 'cmo', 'co'],
                    'net': ['nte', 'ent', 'ne', 'nett'],
                    'org': ['ogr', 'rg', 'or']
                }
            }
        }

    def check_url_reputation(self, url):
        """Check URL reputation using VirusTotal API v3."""
        try:
            # First check internet connectivity
            try:
                socket.create_connection(("8.8.8.8", 53), timeout=3)
            except OSError:
                return {
                    "error": "No internet connection available",
                    "score": 0,
                    "status": "offline"
                }

            headers = {
                "accept": "application/json",
                "x-apikey": self.virustotal_api_key
            }

            # First, get the URL identifier
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            # Try to get existing analysis first
            try:
                analysis_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
                response = requests.get(analysis_url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    results = response.json()
                    last_analysis_stats = results['data']['attributes']['last_analysis_stats']
                    last_analysis_date = results['data']['attributes'].get('last_analysis_date', '')
                    
                    return {
                        'malicious': last_analysis_stats.get('malicious', 0),
                        'suspicious': last_analysis_stats.get('suspicious', 0),
                        'harmless': last_analysis_stats.get('harmless', 0),
                        'undetected': last_analysis_stats.get('undetected', 0),
                        'timeout': last_analysis_stats.get('timeout', 0),
                        'score': min(100, (last_analysis_stats.get('malicious', 0) * 20) + (last_analysis_stats.get('suspicious', 0) * 10)),
                        'last_analysis_date': datetime.fromtimestamp(last_analysis_date).strftime('%Y-%m-%d %H:%M:%S') if last_analysis_date else 'N/A'
                    }
            except requests.exceptions.RequestException as e:
                print(f"Error accessing VirusTotal API: {str(e)}")
                return {
                    "error": "Unable to access VirusTotal API. Using offline analysis only.",
                    "score": 0,
                    "status": "offline"
                }
            
            # If URL not found or error occurred, perform offline analysis
            return self.perform_offline_analysis(url)

        except Exception as e:
            print(f"Error checking URL reputation: {str(e)}")
            return self.perform_offline_analysis(url)

    def perform_offline_analysis(self, url):
        """Perform offline analysis when VirusTotal is unavailable."""
        score = 0
        reasons = []
        
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Check for suspicious TLDs
            if any(domain.endswith(tld) for tld in self.detection_rules['suspicious_tlds']):
                score += 25
                reasons.append("Suspicious TLD detected")
            
            # Check for IP-based URLs
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                score += 30
                reasons.append("IP-based URL detected")
            
            # Check for suspicious keywords
            if any(keyword in url.lower() for keyword in self.detection_rules['suspicious_keywords']):
                score += 20
                reasons.append("Suspicious keywords detected")
            
            # Check for excessive special characters
            special_chars = sum(1 for c in url if not c.isalnum())
            if special_chars > len(url) * 0.2:  # More than 20% special characters
                score += 15
                reasons.append("Excessive special characters")
            
            return {
                "score": score,
                "analysis_type": "offline",
                "reasons": reasons,
                "status": "completed_offline"
            }
        except Exception as e:
            return {
                "error": f"Offline analysis error: {str(e)}",
                "score": 0,
                "status": "error"
            }

    def show_analysis_error(self, error_message):
        messagebox.showerror("Analysis Error", error_message)

    def show_detailed_result(self, event):
        # Get the selected item
        item = self.url_results_tree.selection()[0]
        check, result = self.url_results_tree.item(item)['values']

        # Create popup window
        popup = tk.Toplevel(self.root)
        popup.title("Detailed Result")
        popup.geometry("600x400")
        popup.configure(bg="#2a2a2e")

        # Make the window modal
        popup.transient(self.root)
        popup.grab_set()

        # Add content
        content_frame = ttk.Frame(popup)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Check/Category Label
        ttk.Label(
            content_frame,
            text=check,
            font=('Segoe UI', 12, 'bold'),
            wraplength=560
        ).pack(fill=tk.X, pady=(0, 10))

        # Result Text
        result_text = scrolledtext.ScrolledText(
            content_frame,
            wrap=tk.WORD,
            font=('Segoe UI', 10),
            height=15
        )
        result_text.pack(fill=tk.BOTH, expand=True)
        result_text.insert('1.0', str(result))
        result_text.configure(state='disabled')  # Make read-only

        # Close button
        ttk.Button(
            content_frame,
            text="Close",
            command=popup.destroy
        ).pack(pady=(10, 0))

    def get_domain_info(self, url):
        """Get domain information including age, registration, and reputation."""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            if not domain:
                return {
                    'error': 'Invalid domain',
                    'age': 'N/A',
                    'registration': 'N/A',
                    'reputation': 'N/A'
                }

            try:
                # Try to resolve domain first
                ip_address = socket.gethostbyname(domain)
                
                # Get WHOIS information
                domain_info = whois.whois(domain)
                
                results = {
                    'age': 'N/A',
                    'registration': 'N/A',
                    'reputation': 'N/A',
                    'registrar': domain_info.registrar if domain_info.registrar else 'N/A',
                    'status': 'Active'
                }

                # Calculate domain age if creation date exists
                if domain_info.creation_date:
                    if isinstance(domain_info.creation_date, list):
                        creation_date = domain_info.creation_date[0]
                    else:
                        creation_date = domain_info.creation_date
                    
                    age = (datetime.now() - creation_date).days
                    results['age'] = f"{age} days"
                    results['registration'] = creation_date.strftime('%Y-%m-%d')

                # Add reputation information
                if domain in self.detection_rules['trusted_domains']:
                    results['reputation'] = 'Trusted Domain'
                elif any(tld in domain for tld in self.detection_rules['suspicious_tlds']):
                    results['reputation'] = 'Suspicious TLD'
                else:
                    results['reputation'] = 'Unknown'

                return results

            except socket.gaierror:
                return {
                    'error': 'Domain does not exist',
                    'age': 'N/A',
                    'registration': 'N/A',
                    'reputation': 'N/A',
                    'status': 'Unreachable'
                }
            except whois.parser.PywhoisError:
                return {
                    'error': 'WHOIS information unavailable',
                    'age': 'N/A',
                    'registration': 'N/A',
                    'reputation': 'Unknown',
                    'status': 'Unknown'
                }
                
        except Exception as e:
            print(f"Error getting domain information: {str(e)}")
            return {
                'error': str(e),
                'age': 'N/A',
                'registration': 'N/A',
                'reputation': 'N/A',
                'status': 'Error'
            }

    def update_domain_info(self, domain_data):
        # Update domain information labels
        self.domain_info['Age'].config(text=f"Domain Age: {domain_data.get('age', 'N/A')}")
        self.domain_info['Registration'].config(text=f"Registration Date: {domain_data.get('registration', 'N/A')}")
        self.domain_info['Reputation'].config(text=f"Domain Reputation: {domain_data.get('reputation', 'N/A')}")

    def check_basic_url_patterns(self, url):
        """Check URL for basic suspicious patterns with improved typosquatting detection."""
        results = {
            'score': 0,
            'results': []
        }
        
        try:
            parsed_url = urlparse(url)
            domain_parts = tldextract.extract(url)
            domain = parsed_url.netloc.lower()
            path = parsed_url.path.lower()
            
            # Enhanced typosquatting detection for financial and popular domains
            typosquatting_patterns = {
                'paypal': [
                    {'pattern': r'paypa[l1]', 'replace': '1', 'original': 'l'},
                    {'pattern': r'pa[y4]pal', 'replace': '4', 'original': 'y'},
                    {'pattern': r'p[a@]ypal', 'replace': '@', 'original': 'a'}
                ],
                'apple': [
                    {'pattern': r'app[l1]e', 'replace': '1', 'original': 'l'},
                    {'pattern': r'[a@]pple', 'replace': '@', 'original': 'a'}
                ],
                'amazon': [
                    {'pattern': r'amaz[o0]n', 'replace': '0', 'original': 'o'},
                    {'pattern': r'[a@]mazon', 'replace': '@', 'original': 'a'}
                ],
                'microsoft': [
                    {'pattern': r'micr[o0]s[o0]ft', 'replace': '0', 'original': 'o'},
                    {'pattern': r'micr[0o]soft', 'replace': '0', 'original': 'o'}
                ],
                'google': [
                    {'pattern': r'g[o0][o0]gle', 'replace': '0', 'original': 'o'},
                    {'pattern': r'go[o0]g[l1]e', 'replace': '1', 'original': 'l'}
                ]
            }

            # Check for typosquatting
            domain_without_tld = domain_parts.domain.lower()
            for brand, patterns in typosquatting_patterns.items():
                for pattern_data in patterns:
                    if re.search(pattern_data['pattern'], domain_without_tld):
                        # Verify it's actually typosquatting and not the legitimate domain
                        if domain_without_tld != brand:
                            found_char = pattern_data['replace']
                            original_char = pattern_data['original']
                            results['results'].append((
                                "Critical Typosquatting Detected",
                                f"High Risk - Possible {brand.title()} impersonation: "
                                f"Uses '{found_char}' instead of '{original_char}'"
                            ))
                            results['score'] += 50  # Higher score for typosquatting
                            break

            # Check for IP-based URLs
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed_url.netloc):
                results['results'].append(("IP-based URL", "High Risk - IP address used instead of domain name"))
                results['score'] += 25

            # Check for suspicious TLDs
            suspicious_tlds = self.detection_rules.get('suspicious_tlds', [])
            if domain_parts.suffix in suspicious_tlds:
                results['results'].append(("Suspicious TLD", f"High Risk - Suspicious top-level domain: .{domain_parts.suffix}"))
                results['score'] += 20

            # Check for URL length
            if len(url) > 100:
                results['results'].append(("Long URL", "Medium Risk - Unusually long URL"))
                results['score'] += 10

            # Check for multiple subdomains
            subdomain_count = len(domain_parts.subdomain.split('.')) if domain_parts.subdomain else 0
            if subdomain_count > 3:
                results['results'].append(("Multiple Subdomains", "Medium Risk - Excessive number of subdomains"))
                results['score'] += 15

            # Check for deceptive subdomain use
            if domain_parts.subdomain:
                legitimate_domains = ['paypal', 'apple', 'amazon', 'microsoft', 'google']
                for legit_domain in legitimate_domains:
                    if legit_domain in domain_parts.subdomain.lower() and legit_domain not in domain_parts.domain.lower():
                        results['results'].append((
                            "Deceptive Subdomain",
                            f"Critical Risk - Using legitimate brand '{legit_domain}' in subdomain to deceive"
                        ))
                        results['score'] += 45
                        break

            # Context-aware keyword checking with brand protection
            suspicious_keywords = self.detection_rules.get('suspicious_keywords', [])
            found_keywords = []
            
            # Don't flag 'login' or 'signin' if they appear in standard paths
            standard_paths = ['/login', '/signin', '/auth', '/account']
            is_standard_path = any(path.startswith(std_path) for std_path in standard_paths)
            
            for kw in suspicious_keywords:
                if kw.lower() in url.lower():
                    # Skip login-related keywords for legitimate paths
                    if kw in ['login', 'account', 'signin'] and (
                        is_standard_path or
                        domain.endswith(('.edu', '.gov', '.mil')) or
                        domain_parts.domain in ['microsoft', 'google', 'apple', 'amazon'] or
                        f"{domain_parts.domain}.{domain_parts.suffix}" in self.detection_rules['trusted_domains']
                    ):
                        continue
                    found_keywords.append(kw)

            if found_keywords:
                results['results'].append(("Suspicious Keywords", f"Medium Risk - Found suspicious terms: {', '.join(found_keywords)}"))
                results['score'] += 15 if not any(k in ['login', 'account', 'signin'] for k in found_keywords) else 5

            # Check for URL encoding abuse
            encoded_count = url.count('%')
            if encoded_count > 3:
                results['results'].append(("URL Encoding", "Medium Risk - Excessive URL encoding detected"))
                results['score'] += 15

            # Domain-specific checks with improved context
            suspicious_patterns = self.detection_rules.get('suspicious_domain_patterns', {})

            # Check for homograph attacks only if not a trusted domain
            if not domain_parts.domain in self.detection_rules.get('trusted_domains', []):
                homograph_patterns = suspicious_patterns.get('homograph', [])
                for pattern in homograph_patterns:
                    if pattern in domain:
                        results['results'].append(("Homograph Attack", "Critical Risk - Possible IDN homograph attack detected"))
                        results['score'] += 40
                        break

            # Check for mixed character sets
            if re.search(r'[а-яА-Я].*[a-zA-Z]|[a-zA-Z].*[а-яА-Я]', domain):
                results['results'].append(("Mixed Scripts", "Critical Risk - Mixed character sets detected"))
                results['score'] += 45

            # Check for repeated characters only if not a legitimate brand
            if re.search(r'(.)\1{2,}', domain_parts.domain):
                if not domain_parts.domain.lower() in ['google', 'amazon']:
                    results['results'].append(("Character Repetition", "Medium Risk - Suspicious character repetition"))
                    results['score'] += 20

            # Check for excessive dashes
            if domain.count('-') > 2:
                results['results'].append(("Excessive Dashes", "Medium Risk - Suspicious use of dashes"))
                results['score'] += 15

        except Exception as e:
            results['results'].append(("Error", f"Error analyzing URL patterns: {str(e)}"))
        
        return results

    def check_security_features(self, url):
        """Check security features of the URL and its hosting."""
        results = {
            'score': 0,
            'results': []
        }
        
        try:
            # Check HTTPS
            if not url.startswith('https://'):
                results['results'].append(("No HTTPS", "High Risk - Connection not secure"))
                results['score'] += 25

            # Get SSL certificate info
            if url.startswith('https://'):
                ssl_info = self.get_ssl_certificate(url)
                if ssl_info.get('version') == 'N/A':
                    results['results'].append(("SSL Certificate", "High Risk - Invalid or missing SSL certificate"))
                    results['score'] += 25
                elif ssl_info.get('valid_until'):
                    try:
                        expiry = datetime.strptime(ssl_info['valid_until'], '%Y-%m-%d')
                        if expiry < datetime.now():
                            results['results'].append(("SSL Certificate", "High Risk - Expired SSL certificate"))
                            results['score'] += 25
                    except:
                        pass

        except Exception as e:
            results['results'].append(("Error", f"Error checking security features: {str(e)}"))
        
        return results

    def analyze_web_content(self, url):
        """Analyze the content of the webpage with improved context awareness."""
        results = {
            'score': 0,
            'results': []
        }
        
        try:
            # Parse the domain for context checks
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            domain_parts = tldextract.extract(url)
            base_domain = f"{domain_parts.domain}.{domain_parts.suffix}"

            # Try with SSL verification first
            try:
                response = self.session.get(url, timeout=5)
            except requests.exceptions.SSLError:
                # If SSL verification fails, try without verification but add it as a risk factor
                response = self.session.get(url, timeout=5, verify=False)
                results['results'].append(("SSL Verification", "High Risk - Invalid SSL Certificate"))
                results['score'] += 25

            soup = BeautifulSoup(response.text, 'html.parser')

            # Check for login forms with context
            login_forms = soup.find_all('form')
            for form in login_forms:
                if any(field in str(form).lower() for field in ['password', 'login', 'username']):
                    # Don't flag login forms on legitimate business/enterprise domains
                    if any([
                        base_domain in self.detection_rules['trusted_domains'],  # Known trusted domains
                        domain.endswith(('.edu', '.gov', '.mil')),  # Educational/Government domains
                        domain.endswith(('.com', '.org', '.net')) and len(domain_parts.domain) > 3,  # Established business domains
                        'login' in parsed_url.path.lower() or 'signin' in parsed_url.path.lower()  # Expected login paths
                    ]):
                        results['results'].append(("Login Form", "Safe - Legitimate login page detected"))
                    else:
                        # Check for additional risk factors before flagging
                        risk_factors = []
                        
                        # Check if form submits to a different domain
                        if form.get('action'):
                            form_action = form['action']
                            if form_action.startswith('http'):
                                action_domain = urlparse(form_action).netloc
                                if action_domain and action_domain != domain:
                                    risk_factors.append("Form submits to different domain")
                                    results['score'] += 25
                        
                        # Check for suspicious input fields
                        suspicious_fields = ['card', 'credit', 'cvv', 'ssn', 'social']
                        found_suspicious = [field for field in suspicious_fields if any(input_tag.get('name', '').lower().find(field) != -1 for input_tag in form.find_all('input'))]
                        if found_suspicious:
                            risk_factors.append(f"Suspicious input fields: {', '.join(found_suspicious)}")
                            results['score'] += 20
                        
                        if risk_factors:
                            results['results'].append(("Login Form", f"Medium Risk - Suspicious login form detected: {'; '.join(risk_factors)}"))

            # Check for suspicious scripts
            scripts = soup.find_all('script')
            for script in scripts:
                if script.get('src'):
                    script_src = script['src']
                    if not script_src.startswith(('https://', '/')):
                        # Don't flag common CDN sources
                        common_cdns = ['ajax.googleapis.com', 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'code.jquery.com']
                        if not any(cdn in script_src for cdn in common_cdns):
                            results['results'].append(("Insecure Script", "Medium Risk - External script from insecure source"))
                            results['score'] += 15
                            break

            # Check for mixed content only if critical
            if url.startswith('https://'):
                critical_mixed_content = False
                for tag in soup.find_all(['script', 'link', 'iframe']):
                    src = tag.get('src') or tag.get('href')
                    if src and src.startswith('http://'):
                        critical_mixed_content = True
                        break
                
                if critical_mixed_content:
                    results['results'].append(("Mixed Content", "Medium Risk - Critical resources loaded insecurely"))
                    results['score'] += 15

        except Exception as e:
            results['results'].append(("Error", f"Error analyzing web content: {str(e)}"))
        
        return results

    def get_geoip_info(self, url):
        """Get geolocation information with improved error handling."""
        results = {
            'country': 'N/A',
            'city': 'N/A',
            'coordinates': 'N/A',
            'timezone': 'N/A',
            'status': 'N/A'
        }
        
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            if not domain:
                results['status'] = 'Invalid domain'
                return results

            try:
                # Try to resolve domain first
                ip_address = socket.gethostbyname(domain)
                
                # Get geolocation data
                geo_data = self.geoip_reader.city(ip_address)
                
                if geo_data:
                    results['country'] = geo_data.country.name if geo_data.country else 'Unknown'
                    results['city'] = geo_data.city.name if geo_data.city else 'Unknown'
                    if geo_data.location:
                        results['coordinates'] = f"{geo_data.location.latitude}, {geo_data.location.longitude}"
                        results['timezone'] = geo_data.location.time_zone
                    results['status'] = 'Success'
                
                return results

            except socket.gaierror:
                results['status'] = 'Domain unreachable'
                return results
            except geoip2.errors.AddressNotFoundError:
                results['status'] = 'IP not found in database'
                return results
            
        except Exception as e:
            print(f"Error getting geolocation info: {str(e)}")
            results['status'] = f'Error: {str(e)}'
            return results

    def get_whois_info(self, url):
        """Get WHOIS information for a URL."""
        whois_data = {
            'registrar': 'N/A',
            'creation_date': 'N/A',
            'expiration_date': 'N/A',
            'last_updated': 'N/A',
            'registrant': 'N/A',
            'admin_email': 'N/A',
            'status': 'offline'
        }
        
        try:
            # Check internet connectivity first
            try:
                socket.create_connection(("8.8.8.8", 53), timeout=3)
            except OSError:
                whois_data['error'] = "No internet connection available"
                return whois_data

            # Extract domain from URL
            domain = urlparse(url).netloc
            if not domain:
                whois_data['error'] = "Invalid domain"
                return whois_data
            
            # Get WHOIS information with timeout
            try:
                domain_info = whois.whois(domain, timeout=10)
            except Exception as whois_error:
                whois_data['error'] = f"WHOIS lookup failed: {str(whois_error)}"
                return whois_data
            
            if domain_info:
                # Handle registrar information
                whois_data['registrar'] = domain_info.registrar if domain_info.registrar else 'N/A'
                
                # Handle dates
                if domain_info.creation_date:
                    creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
                    whois_data['creation_date'] = creation_date.strftime('%Y-%m-%d')
                
                if domain_info.expiration_date:
                    expiration_date = domain_info.expiration_date[0] if isinstance(domain_info.expiration_date, list) else domain_info.expiration_date
                    whois_data['expiration_date'] = expiration_date.strftime('%Y-%m-%d')
                
                if domain_info.updated_date:
                    updated_date = domain_info.updated_date[0] if isinstance(domain_info.updated_date, list) else domain_info.updated_date
                    whois_data['last_updated'] = updated_date.strftime('%Y-%m-%d')
                
                # Handle registrant information
                whois_data['registrant'] = domain_info.registrant_name if hasattr(domain_info, 'registrant_name') else 'N/A'
                whois_data['admin_email'] = domain_info.emails[0] if isinstance(domain_info.emails, list) else domain_info.emails if domain_info.emails else 'N/A'
                
                # Calculate risk score based on WHOIS data
                risk_score = 0
                risk_factors = []
                
                # New domains (less than 6 months old) are considered higher risk
                if whois_data['creation_date'] != 'N/A':
                    creation_date = datetime.strptime(whois_data['creation_date'], '%Y-%m-%d')
                    domain_age = (datetime.now() - creation_date).days
                    if domain_age < 180:  # Less than 6 months
                        risk_score += 20
                        risk_factors.append("Domain less than 6 months old")
                
                # Check for private/redacted WHOIS information
                if 'privacy' in str(domain_info).lower() or 'redacted' in str(domain_info).lower():
                    risk_score += 10
                    risk_factors.append("Privacy/Redacted WHOIS information")
                
                # Check for missing or incomplete information
                missing_fields = sum(1 for value in whois_data.values() if value == 'N/A')
                if missing_fields > 3:
                    risk_score += 15
                    risk_factors.append("Incomplete WHOIS information")
                
                whois_data['risk_score'] = risk_score
                whois_data['risk_factors'] = risk_factors
                whois_data['status'] = 'success'
        
        except Exception as e:
            print(f"Error getting WHOIS info: {str(e)}")
            whois_data['error'] = str(e)
            whois_data['status'] = 'error'
        
        return whois_data

if __name__ == "__main__":
    root = tk.Tk()
    app = PhishNetXInternational(root)
    root.mainloop()