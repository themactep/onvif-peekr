#!/usr/bin/env python3
"""
ONVIF Peekr - A GUI application for exploring ONVIF camera capabilities
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import datetime
from pathlib import Path
import json
import logging
from typing import Optional, Dict, Any
import xml.dom.minidom
import hashlib
import base64
import uuid
import time

import requests
from requests.auth import HTTPDigestAuth, HTTPBasicAuth


class CustomONVIFClient:
    """Custom ONVIF client with manual WS-Security authentication"""

    def __init__(self, ip: str, port: int, username: str, password: str):
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password
        self.base_url = f"http://{ip}:{port}"
        self.session = requests.Session()
        self.session.timeout = 10

        # Service endpoints
        self.endpoints = {
            'device': f"{self.base_url}/onvif/device_service",
            'media': f"{self.base_url}/onvif/media_service",
            'ptz': f"{self.base_url}/onvif/ptz_service",
            'events': f"{self.base_url}/onvif/events_service",
            'imaging': f"{self.base_url}/onvif/imaging_service",
        }

        # Cached data
        self.profiles = []
        self.capabilities = None

    def generate_ws_security_header(self) -> str:
        """Generate WS-Security header with username token"""
        # Generate nonce and timestamp
        nonce = os.urandom(16)
        nonce_b64 = base64.b64encode(nonce).decode('utf-8')

        # Create timestamp (UTC)
        created = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        # Create password digest: Base64(SHA1(nonce + created + password))
        digest_input = nonce + created.encode('utf-8') + self.password.encode('utf-8')
        password_digest = base64.b64encode(hashlib.sha1(digest_input).digest()).decode('utf-8')

        # Create WS-Security header
        ws_security = f'''
        <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                       xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
            <wsse:UsernameToken wsu:Id="UsernameToken-{uuid.uuid4()}">
                <wsse:Username>{self.username}</wsse:Username>
                <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{password_digest}</wsse:Password>
                <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce_b64}</wsse:Nonce>
                <wsu:Created>{created}</wsu:Created>
            </wsse:UsernameToken>
        </wsse:Security>'''

        return ws_security.strip()

    def create_soap_envelope(self, body: str, action: str, use_ws_security: bool = True) -> str:
        """Create SOAP envelope with optional WS-Security"""
        headers = ""
        if use_ws_security:
            headers = self.generate_ws_security_header()

        envelope = f'''<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
               xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
               xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"
               xmlns:tev="http://www.onvif.org/ver10/events/wsdl"
               xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl"
               xmlns:tt="http://www.onvif.org/ver10/schema">
    <soap:Header>
        {headers}
    </soap:Header>
    <soap:Body>
        {body}
    </soap:Body>
</soap:Envelope>'''

        return envelope

    def make_request(self, service: str, operation: str, body: str, use_ws_security: bool = True) -> Dict[str, Any]:
        """Make ONVIF SOAP request"""
        endpoint = self.endpoints.get(service)
        if not endpoint:
            raise ValueError(f"Unknown service: {service}")

        # Create SOAP envelope
        soap_envelope = self.create_soap_envelope(body, operation, use_ws_security)

        # Headers
        headers = {
            'Content-Type': 'application/soap+xml; charset=utf-8',
            'SOAPAction': f'"http://www.onvif.org/ver10/{service}/wsdl/{operation}"'
        }

        try:
            # Try with WS-Security first
            response = self.session.post(endpoint, data=soap_envelope, headers=headers)

            if response.status_code == 401 and use_ws_security:
                # Try with HTTP Digest Auth
                self.session.auth = HTTPDigestAuth(self.username, self.password)
                soap_envelope_no_ws = self.create_soap_envelope(body, operation, False)
                response = self.session.post(endpoint, data=soap_envelope_no_ws, headers=headers)

            if response.status_code == 401:
                # Try with HTTP Basic Auth
                self.session.auth = HTTPBasicAuth(self.username, self.password)
                soap_envelope_no_ws = self.create_soap_envelope(body, operation, False)
                response = self.session.post(endpoint, data=soap_envelope_no_ws, headers=headers)

            return {
                'success': response.status_code == 200,
                'status_code': response.status_code,
                'request_xml': soap_envelope,
                'response_xml': response.text,
                'error': None if response.status_code == 200 else f"HTTP {response.status_code}"
            }

        except Exception as e:
            return {
                'success': False,
                'status_code': 0,
                'request_xml': soap_envelope,
                'response_xml': '',
                'error': str(e)
            }


class ONVIFPeekr:
    def __init__(self, root):
        self.root = root
        self.root.title("ONVIF Peekr - Camera Explorer")
        self.root.geometry("800x700")
        self.root.minsize(600, 500)  # Set minimum window size

        # Configure window behavior
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Center the window on screen
        self.center_window()

        # Application state
        self.camera: Optional[CustomONVIFClient] = None
        self.is_connected = False
        self.is_running = False
        self.save_directory = ""
        self.current_session_dir = ""

        # Connection details
        self.camera_ip = ""
        self.camera_port = 80
        self.camera_username = ""
        self.camera_password = ""

        # Operation counter for sequential file naming
        self.operation_counter = 1

        # Setup logging
        self.setup_logging()

        # Create GUI
        self.create_widgets()

        # Create menu bar
        self.create_menu()

        # ONVIF operations to execute - now all use custom client
        self.onvif_operations = [
            # (operation_name, service_type, soap_body, requires_auth)
            ("GetDeviceInformation", "device", '<tds:GetDeviceInformation/>', True),
            ("GetCapabilities", "device", '<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>', False),
            ("GetServices", "device", '<tds:GetServices><tds:IncludeCapability>true</tds:IncludeCapability></tds:GetServices>', False),
            ("GetProfiles", "media", '<trt:GetProfiles/>', True),
            ("GetVideoSources", "media", '<trt:GetVideoSources/>', True),
            ("GetAudioSources", "media", '<trt:GetAudioSources/>', True),
            ("GetVideoSourceConfigurations", "media", '<trt:GetVideoSourceConfigurations/>', True),
            ("GetAudioSourceConfigurations", "media", '<trt:GetAudioSourceConfigurations/>', True),
            ("GetVideoEncoderConfigurations", "media", '<trt:GetVideoEncoderConfigurations/>', True),
            ("GetAudioEncoderConfigurations", "media", '<trt:GetAudioEncoderConfigurations/>', True),
            ("GetMetadataConfigurations", "media", '<trt:GetMetadataConfigurations/>', True),
            ("GetStreamUri", "media", None, True),  # Will be generated dynamically
            ("GetSnapshotUri", "media", None, True),  # Will be generated dynamically
            ("GetConfigurations", "ptz", '<tptz:GetConfigurations/>', True),
            ("GetNodes", "ptz", '<tptz:GetNodes/>', True),
            ("GetPresets", "ptz", None, True),  # Will be generated dynamically
            ("GetEventProperties", "events", '<tev:GetEventProperties/>', True),
            ("GetServiceCapabilities", "events", '<tev:GetServiceCapabilities/>', True),
        ]

    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def center_window(self):
        """Center the window on the screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Session", command=self.new_session)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

    def create_widgets(self):
        """Create and layout GUI widgets"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Connection frame
        conn_frame = ttk.LabelFrame(main_frame, text="Camera Connection", padding="10")
        conn_frame.grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))

        # IP Address
        ttk.Label(conn_frame, text="IP Address:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.ip_var = tk.StringVar(value="192.168.1.10")
        ttk.Entry(conn_frame, textvariable=self.ip_var, width=20).grid(row=0, column=1, padx=(0, 10))

        # Port
        ttk.Label(conn_frame, text="Port:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.port_var = tk.StringVar(value="80")
        ttk.Entry(conn_frame, textvariable=self.port_var, width=20).grid(row=0, column=3, padx=(0, 10))

        # Username
        ttk.Label(conn_frame, text="Username:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.username_var = tk.StringVar(value="thingino")
        ttk.Entry(conn_frame, textvariable=self.username_var, width=20).grid(row=1, column=1, padx=(0, 10), pady=(5, 0))

        # Password
        ttk.Label(conn_frame, text="Password:").grid(row=1, column=2, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.password_var = tk.StringVar(value="thingino")
        ttk.Entry(conn_frame, textvariable=self.password_var, width=20).grid(row=1, column=3, padx=(0, 10), pady=(5, 0))

        # Connect button
        self.connect_btn = ttk.Button(conn_frame, text="Connect", command=self.toggle_connection)
        self.connect_btn.grid(row=2, column=0, columnspan=2, pady=(10, 0), sticky=tk.W)

        # Connection status
        self.status_var = tk.StringVar(value="Disconnected")
        ttk.Label(conn_frame, textvariable=self.status_var, foreground="red").grid(row=2, column=2, columnspan=2, pady=(10, 0), sticky=tk.W)

        # Save location frame
        save_frame = ttk.LabelFrame(main_frame, text="Save Location", padding="10")
        save_frame.grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))

        self.save_path_var = tk.StringVar(value=str(Path.home() / "onvif_logs"))
        ttk.Entry(save_frame, textvariable=self.save_path_var, width=50).grid(row=0, column=0, padx=(0, 10))
        ttk.Button(save_frame, text="Browse", command=self.browse_save_location).grid(row=0, column=1)

        # Save raw XML checkbox
        self.save_raw_xml_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(save_frame, text="Save raw XML files", variable=self.save_raw_xml_var).grid(row=1, column=0, sticky="w", pady=(10, 0))

        # Control frame
        control_frame = ttk.LabelFrame(main_frame, text="Operations", padding="10")
        control_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        self.start_btn = ttk.Button(control_frame, text="Start Exploration", command=self.start_exploration, state="disabled")
        self.start_btn.grid(row=0, column=0, padx=(0, 10))

        self.stop_btn = ttk.Button(control_frame, text="Stop", command=self.stop_exploration, state="disabled")
        self.stop_btn.grid(row=0, column=1, padx=(0, 10))

        # Add quit button
        self.quit_btn = ttk.Button(control_frame, text="Quit", command=self.on_closing)
        self.quit_btn.grid(row=0, column=2)

        # Progress frame
        progress_frame = ttk.LabelFrame(main_frame, text="Progress", padding="10")
        progress_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        self.progress_var = tk.StringVar(value="Ready")
        ttk.Label(progress_frame, textvariable=self.progress_var).grid(row=0, column=0, sticky=tk.W)

        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate')
        self.progress_bar.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(5, 0))

        # Log frame
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding="10")
        log_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))

        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, width=80)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(4, weight=1)
        conn_frame.columnconfigure(1, weight=1)
        save_frame.columnconfigure(0, weight=1)
        progress_frame.columnconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

    def log_message(self, message: str, level: str = "INFO"):
        """Add message to log display"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {level}: {message}\n"

        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        self.root.update_idletasks()

        # Also log to file
        if level == "ERROR":
            self.logger.error(message)
        elif level == "WARNING":
            self.logger.warning(message)
        else:
            self.logger.info(message)

    def browse_save_location(self):
        """Browse for save directory"""
        directory = filedialog.askdirectory(initialdir=self.save_path_var.get())
        if directory:
            self.save_path_var.set(directory)

    def toggle_connection(self):
        """Connect or disconnect from camera"""
        if not self.is_connected:
            self.connect_camera()
        else:
            self.disconnect_camera()

    def connect_camera(self):
        """Connect to ONVIF camera"""
        try:
            ip = self.ip_var.get().strip()
            port = int(self.port_var.get().strip())
            username = self.username_var.get().strip()
            password = self.password_var.get()

            if not ip:
                messagebox.showerror("Error", "Please enter IP address")
                return

            # Store connection details for direct HTTP requests
            self.camera_ip = ip
            self.camera_port = port
            self.camera_username = username
            self.camera_password = password

            self.log_message(f"Connecting to {ip}:{port}...")
            self.progress_var.set("Connecting...")

            # Create custom ONVIF client
            self.camera = CustomONVIFClient(ip, port, username, password)

            # Test connection by getting device information
            self.log_message("Testing connection with GetDeviceInformation...")
            result = self.camera.make_request("device", "GetDeviceInformation", '<tds:GetDeviceInformation/>', True)

            if not result['success']:
                # Try without WS-Security
                self.log_message("WS-Security failed, trying without authentication...")
                result = self.camera.make_request("device", "GetDeviceInformation", '<tds:GetDeviceInformation/>', False)

            if result['success']:
                self.log_message("Connection successful!")

                # Try to get capabilities to see what services are available
                self.log_message("Getting device capabilities...")
                cap_result = self.camera.make_request("device", "GetCapabilities",
                                                    '<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>', False)

                if cap_result['success']:
                    self.log_message("Device capabilities retrieved successfully")

                # Try to get media profiles
                self.log_message("Getting media profiles...")
                profile_result = self.camera.make_request("media", "GetProfiles", '<trt:GetProfiles/>', True)

                if profile_result['success']:
                    self.log_message("Media profiles retrieved successfully")
                else:
                    self.log_message("Media profiles failed - some operations may not work")

                self.is_connected = True
                self.status_var.set("Connected")
                self.connect_btn.config(text="Disconnect")
                self.start_btn.config(state="normal")
                self.progress_var.set("Connected")

            else:
                raise Exception(f"Connection failed: {result['error']}")

        except Exception as e:
            self.log_message(f"Connection failed: {str(e)}", "ERROR")
            messagebox.showerror("Connection Error", f"Failed to connect: {str(e)}")
            self.progress_var.set("Connection failed")

    def disconnect_camera(self):
        """Disconnect from camera"""
        self.camera = None
        self.is_connected = False

        # Clear cached data
        if hasattr(self, 'camera') and self.camera:
            self.camera.profiles = []
            self.camera.capabilities = None

        # Clear connection details
        self.camera_ip = ""
        self.camera_port = 80
        self.camera_username = ""
        self.camera_password = ""

        self.status_var.set("Disconnected")
        self.connect_btn.config(text="Connect")
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="disabled")
        self.log_message("Disconnected from camera")
        self.progress_var.set("Disconnected")

    def start_exploration(self):
        """Start ONVIF exploration in a separate thread"""
        if not self.is_connected:
            messagebox.showerror("Error", "Please connect to camera first")
            return

        if not self.save_path_var.get().strip():
            messagebox.showerror("Error", "Please select save location")
            return

        self.is_running = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")

        # Create session directory
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        ip = self.ip_var.get().strip()
        self.current_session_dir = Path(self.save_path_var.get()) / f"{ip}_{timestamp}"
        self.current_session_dir.mkdir(parents=True, exist_ok=True)

        self.log_message(f"Starting exploration, saving to: {self.current_session_dir}")

        # Clear any cached data from previous runs
        if self.camera:
            self.camera.profiles = []
            self.camera.capabilities = None

        # Reset operation counter for new session
        self.operation_counter = 1

        # Start exploration in separate thread
        thread = threading.Thread(target=self.run_exploration, daemon=True)
        thread.start()

    def stop_exploration(self):
        """Stop the exploration process"""
        self.is_running = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.log_message("Exploration stopped by user")
        self.progress_var.set("Stopped")

    def run_exploration(self):
        """Run ONVIF exploration operations"""
        try:
            total_operations = len(self.onvif_operations)
            self.progress_bar.config(maximum=total_operations)

            results = []

            for i, operation_info in enumerate(self.onvif_operations):
                if not self.is_running:
                    break

                operation, service_type = operation_info[0], operation_info[1]

                self.progress_var.set(f"Executing {operation}...")
                self.progress_bar.config(value=i)
                self.root.update_idletasks()

                result = self.execute_onvif_operation(operation_info)
                results.append(result)

                self.log_message(f"Completed {operation}: {'SUCCESS' if result['success'] else 'FAILED'}")

            # Save summary
            self.save_summary(results)

            if self.is_running:
                self.progress_bar.config(value=total_operations)
                self.progress_var.set("Exploration completed")
                self.log_message("Exploration completed successfully")

        except Exception as e:
            self.log_message(f"Exploration error: {str(e)}", "ERROR")
        finally:
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")

    def execute_onvif_operation(self, operation_info) -> Dict[str, Any]:
        """Execute a single ONVIF operation and save request/response"""
        operation, service_type, soap_body, requires_auth = operation_info

        result = {
            'operation': operation,
            'service_type': service_type,
            'success': False,
            'error': None,
            'timestamp': datetime.datetime.now().isoformat(),
            'method': 'custom_client'
        }

        try:
            self.log_message(f"Executing {operation} using custom ONVIF client")

            # Generate SOAP body if needed
            if soap_body is None:
                soap_body = self.generate_soap_body(operation, service_type)

            # Make the request
            onvif_result = self.camera.make_request(service_type, operation, soap_body, requires_auth)

            if onvif_result['success']:
                self.log_message(f"SUCCESS: {operation}")
                result['success'] = True

                # Save the request/response
                self.save_direct_soap_data(operation, onvif_result['request_xml'], onvif_result['response_xml'])

            else:
                error_msg = onvif_result['error'] or f"HTTP {onvif_result['status_code']}"
                result['error'] = error_msg
                self.log_message(f"FAILED: {operation} - {error_msg}", "ERROR")

                # Still save the request/response for debugging
                if onvif_result['request_xml'] or onvif_result['response_xml']:
                    self.save_direct_soap_data(operation, onvif_result['request_xml'], onvif_result['response_xml'])

            # Increment counter after each operation (successful or failed)
            self.operation_counter += 1

        except Exception as e:
            error_msg = str(e)
            result['error'] = error_msg
            self.log_message(f"EXCEPTION in {operation}: {error_msg}", "ERROR")

        return result

    def generate_soap_body(self, operation: str, service_type: str) -> str:
        """Generate SOAP body for operations that need dynamic parameters"""
        if operation == "GetStreamUri":
            # Need to get profiles first
            profile_token = self.get_first_profile_token()
            if profile_token:
                return f'''<trt:GetStreamUri>
                    <trt:ProfileToken>{profile_token}</trt:ProfileToken>
                    <trt:StreamSetup>
                        <tt:Stream>RTP-Unicast</tt:Stream>
                        <tt:Transport>
                            <tt:Protocol>RTSP</tt:Protocol>
                        </tt:Transport>
                    </trt:StreamSetup>
                </trt:GetStreamUri>'''
            else:
                raise Exception("No profiles available for GetStreamUri")

        elif operation == "GetSnapshotUri":
            profile_token = self.get_first_profile_token()
            if profile_token:
                return f'''<trt:GetSnapshotUri>
                    <trt:ProfileToken>{profile_token}</trt:ProfileToken>
                </trt:GetSnapshotUri>'''
            else:
                raise Exception("No profiles available for GetSnapshotUri")

        elif operation == "GetPresets":
            profile_token = self.get_first_profile_token()
            if profile_token:
                return f'''<tptz:GetPresets>
                    <tptz:ProfileToken>{profile_token}</tptz:ProfileToken>
                </tptz:GetPresets>'''
            else:
                raise Exception("No profiles available for GetPresets")

        else:
            raise Exception(f"No SOAP body generator for {operation}")

    def get_first_profile_token(self) -> Optional[str]:
        """Get the first available profile token"""
        try:
            # Try to get profiles if we don't have them cached
            if not self.camera.profiles:
                result = self.camera.make_request("media", "GetProfiles", '<trt:GetProfiles/>', True)
                if result['success']:
                    # Parse the response to extract profile tokens
                    # This is a simplified parser - in a real implementation you'd use proper XML parsing
                    response_xml = result['response_xml']
                    if 'token=' in response_xml:
                        # Extract first token (simplified)
                        import re
                        tokens = re.findall(r'token="([^"]+)"', response_xml)
                        if tokens:
                            return tokens[0]

            # If we have cached profiles, return the first one
            if self.camera.profiles:
                return self.camera.profiles[0].get('token')

            return None

        except Exception as e:
            self.log_message(f"Error getting profile token: {e}", "ERROR")
            return None

    def save_soap_data(self, operation: str, service, response):
        """Save SOAP request and response data to XML files"""
        # Use sequential numbering for filenames
        sequence_num = f"{self.operation_counter:03d}"

        # Save request (if available from service history)
        request_filename = f"{sequence_num}_{operation}_request.xml"
        request_path = self.current_session_dir / request_filename

        # Save response
        response_filename = f"{sequence_num}_{operation}_response.xml"
        response_path = self.current_session_dir / response_filename

        try:
            # LOG RAW RESPONSE DATA
            self.log_message(f"SAVING SOAP DATA for {operation}")
            self.log_message(f"Response object: {response}")
            self.log_message(f"Response type: {type(response)}")
            if hasattr(response, '__dict__'):
                self.log_message(f"Response __dict__: {response.__dict__}")

            # Try to get actual SOAP XML first (bypass zeep's broken serialization)
            soap_response_xml = self.get_soap_response_xml(service, operation)

            if soap_response_xml:
                self.log_message(f"Got actual SOAP response XML for {operation}")
                # Save formatted response (default)
                formatted_xml = self.format_xml(soap_response_xml)
                with open(response_path, 'w', encoding='utf-8') as f:
                    f.write(formatted_xml)

                # Conditionally save raw response
                if self.save_raw_xml_var.get():
                    raw_dir = self.current_session_dir / "raw"
                    raw_dir.mkdir(exist_ok=True)
                    raw_response_path = raw_dir / response_path.name
                    with open(raw_response_path, 'w', encoding='utf-8') as f:
                        f.write(soap_response_xml)
            else:
                self.log_message(f"No SOAP response XML found, falling back to object serialization for {operation}")
                # Fallback to our custom serialization
                raw_response_xml = self.get_raw_response_xml(response, operation)
                formatted_xml = self.format_xml(raw_response_xml)
                with open(response_path, 'w', encoding='utf-8') as f:
                    f.write(formatted_xml)


            # Try to get actual SOAP request XML
            soap_request_xml = self.get_soap_request_xml(service, operation)

            # Save request XML
            if soap_request_xml:
                self.log_message(f"Got actual SOAP request XML for {operation}")
                # Save formatted request (default)
                formatted_request = self.format_xml(soap_request_xml)
                with open(request_path, 'w', encoding='utf-8') as f:
                    f.write(formatted_request)

                # Conditionally save raw request
                if self.save_raw_xml_var.get():
                    raw_dir = self.current_session_dir / "raw"
                    raw_dir.mkdir(exist_ok=True)
                    raw_request_path = raw_dir / request_path.name
                    with open(raw_request_path, 'w', encoding='utf-8') as f:
                        f.write(soap_request_xml)
            else:
                self.log_message(f"No SOAP request XML found, creating placeholder for {operation}")
                # Create a basic request placeholder
                request_xml = self.create_request_placeholder(operation)
                with open(request_path, 'w', encoding='utf-8') as f:
                    f.write(request_xml)

        except Exception as e:
            self.log_message(f"Error saving SOAP data for {operation}: {str(e)}", "ERROR")

    def save_direct_soap_data(self, operation: str, request_xml: str, response_xml: str):
        """Save SOAP request and response data from direct HTTP requests"""
        # Use sequential numbering for filenames
        sequence_num = f"{self.operation_counter:03d}"

        # File names (formatted files are the default)
        request_filename = f"{sequence_num}_{operation}_request.xml"
        response_filename = f"{sequence_num}_{operation}_response.xml"

        # Main paths for formatted files
        request_path = self.current_session_dir / request_filename
        response_path = self.current_session_dir / response_filename

        try:
            # Always save formatted versions (these are the default files)
            formatted_request = self.format_xml(request_xml)
            with open(request_path, 'w', encoding='utf-8') as f:
                f.write(formatted_request)

            formatted_response = self.format_xml(response_xml)
            with open(response_path, 'w', encoding='utf-8') as f:
                f.write(formatted_response)

            # Conditionally save raw versions if checkbox is checked
            if self.save_raw_xml_var.get():
                # Create raw subdirectory if it doesn't exist
                raw_dir = self.current_session_dir / "raw"
                raw_dir.mkdir(exist_ok=True)

                # Save raw files in subdirectory
                raw_request_path = raw_dir / request_filename
                raw_response_path = raw_dir / response_filename

                with open(raw_request_path, 'w', encoding='utf-8') as f:
                    f.write(request_xml)

                with open(raw_response_path, 'w', encoding='utf-8') as f:
                    f.write(response_xml)

                self.log_message(f"SOAP data saved for {operation} ({sequence_num})")
                self.log_message(f"  Formatted: {request_filename}, {response_filename}")
                self.log_message(f"  Raw: raw/{request_filename}, raw/{response_filename}")
            else:
                self.log_message(f"SOAP data saved for {operation} ({sequence_num})")
                self.log_message(f"  Formatted: {request_filename}, {response_filename}")
                self.log_message(f"  Raw files skipped (checkbox unchecked)")

        except Exception as e:
            self.log_message(f"Error saving SOAP data for {operation}: {str(e)}", "ERROR")

    def get_raw_response_xml(self, response, operation: str) -> str:
        """Get raw XML representation of the response"""
        try:
            # Try zeep helpers first for real ONVIF responses
            response_dict = None

            try:
                from zeep import helpers
                self.log_message(f"Trying zeep.helpers.serialize_object for {operation}")
                response_dict = helpers.serialize_object(response)
                self.log_message(f"Zeep serialization result: {response_dict}")
                self.log_message(f"Zeep serialization type: {type(response_dict)}")
            except Exception as e:
                self.log_message(f"Zeep serialization failed: {e}")
                response_dict = None

            # If zeep serialization didn't work or returned the same object, try manual
            if response_dict is None or response_dict is response:
                self.log_message(f"Falling back to manual serialization for {operation}")
                response_dict = self._serialize_object_manually(response)
                self.log_message(f"Manual serialization result: {response_dict}")

            # Convert to XML
            if response_dict is not None:
                return self.dict_to_clean_xml(response_dict, operation)
            else:
                raise Exception("Failed to serialize response")

        except Exception as e:
            self.log_message(f"All serialization methods failed for {operation}: {e}")
            # Fallback to string representation
            return f'''<?xml version="1.0" encoding="UTF-8"?>
<{operation}Response>
  <RawData><![CDATA[{str(response)}]]></RawData>
</{operation}Response>'''

    def _serialize_object_manually(self, obj):
        """Manually serialize object to dictionary"""
        if obj is None:
            return None

        # Handle XML Element objects (from lxml) first
        if self._is_xml_element(obj):
            return self._serialize_xml_element(obj)

        # Handle zeep objects and other complex objects specially
        elif hasattr(obj, '__class__') and ('zeep' in str(type(obj)) or hasattr(obj, '__dict__')):
            return self._serialize_zeep_object(obj)

        # Handle lists and tuples
        elif isinstance(obj, (list, tuple)):
            return [self._serialize_object_manually(item) for item in obj]

        # Handle dictionaries
        elif isinstance(obj, dict):
            return {key: self._serialize_object_manually(value) for key, value in obj.items()}

        # Handle objects with __dict__
        elif hasattr(obj, '__dict__'):
            result = {}
            for key, value in obj.__dict__.items():
                if not key.startswith('_'):
                    result[key] = self._serialize_object_manually(value)
            return result

        # Handle other iterable types (but not strings/bytes)
        elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes)):
            return [self._serialize_object_manually(item) for item in obj]

        # Handle primitive types
        else:
            return obj



    def _is_xml_element(self, obj):
        """Check if object is an XML element"""
        # Check for lxml Element (most reliable)
        if hasattr(obj, 'tag') and hasattr(obj, 'text') and hasattr(obj, 'attrib'):
            return True

        # Check type name for XML element types
        type_str = str(type(obj))
        if 'element' in type_str.lower() and ('xml' in type_str.lower() or 'etree' in type_str.lower()):
            return True

        # Check for specific XML element string patterns (more restrictive)
        obj_str = str(obj)
        if obj_str.startswith('<Element {') and 'at 0x' in obj_str and obj_str.endswith('>'):
            return True

        return False

    def _serialize_xml_element(self, element):
        """Serialize XML element to dictionary"""
        try:
            result = {}

            # Add tag name
            if hasattr(element, 'tag'):
                tag = element.tag
                # Remove namespace if present
                if '}' in tag:
                    tag = tag.split('}')[1]
                result['_tag'] = tag

            # Add text content
            if hasattr(element, 'text') and element.text:
                result['_text'] = element.text.strip()

            # Add attributes
            if hasattr(element, 'attrib') and element.attrib:
                result['_attributes'] = dict(element.attrib)

            # Add child elements
            if hasattr(element, '__iter__'):
                children = {}
                for child in element:
                    child_data = self._serialize_xml_element(child)
                    child_tag = child_data.get('_tag', 'unknown')

                    # Handle multiple children with same tag
                    if child_tag in children:
                        if not isinstance(children[child_tag], list):
                            children[child_tag] = [children[child_tag]]
                        children[child_tag].append(child_data)
                    else:
                        children[child_tag] = child_data

                if children:
                    result['_children'] = children

            return result if result else {'_empty_element': str(element)}

        except Exception as e:
            # Fallback to string representation
            return {'_xml_element_error': str(element), '_error': str(e)}

    def get_soap_request_xml(self, service, operation: str) -> str:
        """Try to extract SOAP request XML from captured data"""
        try:
            # Method 1: Use our captured SOAP request
            if hasattr(self, 'last_soap_request') and self.last_soap_request:
                if isinstance(self.last_soap_request, bytes):
                    return self.last_soap_request.decode('utf-8')
                else:
                    return str(self.last_soap_request)

            # Method 2: Try to get from transport session (fallback)
            if hasattr(service, 'service') and hasattr(service.service, 'transport'):
                transport = service.service.transport
                if hasattr(transport, 'session'):
                    session = transport.session
                    if hasattr(session, 'last_request') and session.last_request:
                        if hasattr(session.last_request, 'body'):
                            return session.last_request.body.decode('utf-8')
                        elif hasattr(session.last_request, 'content'):
                            return session.last_request.content.decode('utf-8')

        except:
            pass
        return None

    def get_soap_response_xml(self, service, operation: str) -> str:
        """Try to extract SOAP response XML from captured data"""
        try:
            # Method 1: Use our captured SOAP response
            if hasattr(self, 'last_soap_response') and self.last_soap_response:
                if isinstance(self.last_soap_response, bytes):
                    return self.last_soap_response.decode('utf-8')
                else:
                    return str(self.last_soap_response)

            # Method 2: Try to get from transport session (fallback)
            if hasattr(service, 'service') and hasattr(service.service, 'transport'):
                transport = service.service.transport
                if hasattr(transport, 'session'):
                    session = transport.session
                    if hasattr(session, 'last_response') and session.last_response:
                        if hasattr(session.last_response, 'content'):
                            return session.last_response.content.decode('utf-8')
                        elif hasattr(session.last_response, 'text'):
                            return session.last_response.text

        except:
            pass
        return None

    def format_xml(self, xml_content: str) -> str:
        """Format XML using xmllint if available, otherwise use minidom"""
        try:
            # First try with xmllint command
            import subprocess

            try:
                # Try to use xmllint --format command
                result = subprocess.run([
                    'xmllint', '--format', '-'
                ], input=xml_content, capture_output=True, text=True, timeout=10)

                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        except:
            pass

        # Fallback to minidom formatting
        try:
            import xml.dom.minidom
            dom = xml.dom.minidom.parseString(xml_content)
            return dom.toprettyxml(indent="  ", encoding=None)
        except:
            # Return raw content if all formatting fails
            return xml_content

    def dict_to_clean_xml(self, data, root_name: str) -> str:
        """Convert dictionary to clean XML"""
        xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>']
        xml_lines.append(f'<{root_name}Response>')
        xml_lines.extend(self._dict_to_xml_lines_clean(data, 1))
        xml_lines.append(f'</{root_name}Response>')
        return '\n'.join(xml_lines)

    def _dict_to_xml_lines_clean(self, data, indent_level=0):
        """Convert dictionary to clean XML lines"""
        lines = []
        indent = "  " * indent_level

        if isinstance(data, dict):
            for key, value in data.items():
                # Clean up key names
                clean_key = str(key).replace('_', '').replace('{', '').replace('}', '')
                if clean_key.startswith('attr'):
                    continue  # Skip zeep attributes

                if value is None:
                    lines.append(f'{indent}<{clean_key}/>')
                elif isinstance(value, (dict, list)):
                    lines.append(f'{indent}<{clean_key}>')
                    lines.extend(self._dict_to_xml_lines_clean(value, indent_level + 1))
                    lines.append(f'{indent}</{clean_key}>')
                else:
                    from xml.sax.saxutils import escape
                    lines.append(f'{indent}<{clean_key}>{escape(str(value))}</{clean_key}>')
        elif isinstance(data, list):
            for item in data:
                lines.extend(self._dict_to_xml_lines_clean(item, indent_level))
        else:
            from xml.sax.saxutils import escape
            lines.append(f'{indent}{escape(str(data))}')

        return lines

    def create_request_placeholder(self, operation: str) -> str:
        """Create a placeholder request XML when actual SOAP request is not available"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
               xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
               xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"
               xmlns:tev="http://www.onvif.org/ver10/events/wsdl">
  <soap:Header/>
  <soap:Body>
    <tds:{operation}>
      <!-- Request parameters for {operation} -->
      <!-- Actual request XML not captured in this implementation -->
    </tds:{operation}>
  </soap:Body>
</soap:Envelope>'''



    def save_summary(self, results):
        """Save exploration summary to JSON file"""
        summary_path = self.current_session_dir / "exploration_summary.json"

        summary = {
            'camera_info': {
                'ip': self.ip_var.get(),
                'port': self.port_var.get(),
                'username': self.username_var.get()
            },
            'exploration_time': datetime.datetime.now().isoformat(),
            'total_operations': len(results),
            'successful_operations': len([r for r in results if r['success']]),
            'failed_operations': len([r for r in results if not r['success']]),
            'results': results
        }

        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)

        self.log_message(f"Summary saved to: {summary_path}")

    def on_closing(self):
        """Handle window closing event"""
        if self.is_running:
            if messagebox.askokcancel("Quit", "Exploration is running. Do you want to stop and quit?"):
                self.stop_exploration()
                self.root.after(1000, self._force_quit)  # Give time for cleanup
            return

        if self.is_connected:
            self.disconnect_camera()

        self.root.quit()
        self.root.destroy()

    def _force_quit(self):
        """Force quit after cleanup delay"""
        self.root.quit()
        self.root.destroy()

    def new_session(self):
        """Start a new session"""
        if self.is_running:
            messagebox.showwarning("Warning", "Please stop the current exploration before starting a new session.")
            return

        if self.is_connected:
            self.disconnect_camera()

        # Clear log
        self.log_text.delete(1.0, tk.END)
        self.log_message("New session started")
        self.progress_var.set("Ready")

    def show_about(self):
        """Show about dialog"""
        about_text = """ONVIF Peekr v1.0.0

A GUI application for exploring ONVIF camera capabilities and logging SOAP request/response data.

© 2025 Paul Philippov, paul@themactep.com"""

        messagebox.showinfo("About ONVIF Peekr", about_text)


def main():
    """Main application entry point"""
    root = tk.Tk()
    app = ONVIFPeekr(root)
    root.mainloop()


if __name__ == "__main__":
    main()
