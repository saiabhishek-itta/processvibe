import streamlit as st
import pandas as pd
import numpy as np
import xml.etree.ElementTree as ET
import requests
from requests.auth import HTTPBasicAuth
import urllib3
import json
import time
import io
import plotly.express as px
import plotly.graph_objects as go
from collections import Counter
import base64
from PIL import Image
from io import BytesIO
from datetime import datetime, timedelta
import re

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Page configuration
st.set_page_config(
    page_title="SAP ProcessVibe AI", 
    layout="wide", 
    page_icon="📊",
    initial_sidebar_state="expanded"
)

# --- Constants and Configuration ---
# SAP OData Service Details
server_url = "http://itpmoccm02.coe.c.na-us-1.cloud.sap:8050"
odata_path = "/sap/opu/odata/sap/ZPROCESS_VIBE_SRV/objectSet"
odata_url = "https://itpmoccm02.coe.c.na-us-1.cloud.sap:44350/sap/opu/odata/sap/zprocess_vibe_srv/objectSet"

# Document Extraction Service Details
dox_url = "https://aiservices-dox.cfapps.eu10.hana.ondemand.com"
dox_client_id = "sb-50cf201b-74df-4a55-aeb8-15e1797283ac!b554526|na-f20548c0-157d-417b-8bbb-1c9f35ecfb2d!b20821"
dox_client_secret = "b3ec36fe-4fc0-408b-a4d7-d7d4e23eecbc$nJdbl76aUxX25zZvB-TGwpOAa4uFaZOLI-G7pYMa5y8="
dox_uaa_url = "https://2ws-vrz9x36p3y5v.authentication.eu10.hana.ondemand.com"

# --- Custom CSS Styling for SAP Theme ---
def load_css():
    st.markdown("""
        <style>
            /* SAP Color Palette */
            :root {
                --sap-primary-color: #0a6ed1;
                --sap-secondary-color: #0070f2;
                --sap-background-color: #f7f7f7;
                --sap-border-color: #d1d1d1;
                --sap-text-color: #32363a;
                --sap-accent-color: #0854a0;
                --sap-success-color: #107e3e;
                --sap-warning-color: #e9730c;
                --sap-error-color: #bb0000;
            }

            [class*="st-"] {
                font-family: "72", "72full", Arial, sans-serif;
            }

            .stApp {
                background-color: var(--sap-background-color);
            }

            h1, h2, h3, h4 {
                color: var(--sap-primary-color);
                padding: 2px;
            }

            .block-container {
                padding: 2rem 2rem;
            }

            .stMetric {
                background-color: white;
                border: 1px solid var(--sap-border-color);
                border-radius: 12px;
                padding: 1rem;
                margin-bottom: 1rem;
            }

            .stDataFrame, .stPlotlyChart {
                background-color: white;
                border: 1px solid var(--sap-border-color);
                border-radius: 8px;
            }

            .stProgress > div > div > div {
                background-color: var(--sap-primary-color);
            }

            .stMultiSelect, .stSelectbox, .stTextInput {
                background-color: white;
                border-radius: 6px;
                border: 1px solid var(--sap-border-color);
            }
                
            /* Style the tab container */
            .stTabs [data-baseweb="tab-list"] {
                border-bottom: 2px solid #d1d1d1;
            }

            /* Default tab style */
            .stTabs [data-baseweb="tab"] {
                background-color: #ffffff;
                color: #32363a;
                border: 1px solid #d1d1d1;
                padding: 0.5rem 1rem;
                margin-right: 0.5rem;
                border-radius: 8px 8px 0 0;
                font-weight: 500;
            }

            /* Highlight selected tab */
            .stTabs [aria-selected="true"] {
                background-color: #e0f3ff;
                color: #0a6ed1;
                border-bottom: 2px solid #0a6ed1;
                box-shadow: inset 0 -3px 0 0 #0a6ed1;
                font-weight: 600;
            }

            /* Login container styling */
            .login-container {
                max-width: 400px;
                margin: 0 auto;
                padding: 2rem;
                background-color: white;
                border-radius: 8px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                border: 1px solid var(--sap-border-color);
            }

            /* Login button styling */
            .login-button {
                background-color: var(--sap-primary-color);
                color: white;
                border: none;
                border-radius: 4px;
                padding: 0.5rem 1rem;
                font-weight: 600;
                width: 100%;
                cursor: pointer;
                transition: background-color 0.3s;
            }

            .login-button:hover {
                background-color: var(--sap-accent-color);
            }

            /* Logo styling */
            .logo-container {
                text-align: center;
                margin-bottom: 2rem;
            }

            /* Success and error messages */
            .success-message {
                background-color: #ecfaf3;
                color: var(--sap-success-color);
                border: 1px solid var(--sap-success-color);
                border-radius: 4px;
                padding: 0.5rem 1rem;
                margin-bottom: 1rem;
            }

            .error-message {
                background-color: #ffeaea;
                color: var(--sap-error-color);
                border: 1px solid var(--sap-error-color);
                border-radius: 4px;
                padding: 0.5rem 1rem;
                margin-bottom: 1rem;
            }

            /* Custom button styles */
            .sap-button {
                background-color: var(--sap-primary-color);
                color: white;
                border: none;
                border-radius: 4px;
                padding: 0.5rem 1rem;
                font-weight: 500;
                cursor: pointer;
            }

            .sap-button:hover {
                background-color: var(--sap-accent-color);
            }

            /* Document card styling */
            .document-card {
                background-color: white;
                border: 1px solid var(--sap-border-color);
                border-radius: 8px;
                padding: 1rem;
                margin-bottom: 1rem;
                transition: box-shadow 0.3s;
            }

            .document-card:hover {
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            }

            /* Status indicators */
            .status-indicator {
                display: inline-block;
                width: 10px;
                height: 10px;
                border-radius: 50%;
                margin-right: 6px;
            }

            .status-success {
                background-color: var(--sap-success-color);
            }

            .status-warning {
                background-color: var(--sap-warning-color);
            }

            .status-error {
                background-color: var(--sap-error-color);
            }

            .status-pending {
                background-color: var(--sap-secondary-color);
            }
            
            /* Hide Streamlit branding */
            #MainMenu, footer, header {
                visibility: hidden;
            }
            
            /* Custom card for metrics */
            .metric-card {
                background-color: white;
                border-radius: 8px;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.05);
                padding: 16px;
                margin-bottom: 16px;
                transition: transform 0.3s ease;
            }
            
            .metric-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            }
            
            .metric-title {
                color: var(--sap-text-color);
                font-size: 0.9rem;
                font-weight: 600;
                margin-bottom: 8px;
            }
            
            .metric-value {
                font-size: 2rem;
                font-weight: 700;
                color: var(--sap-primary-color);
            }
            
            .metric-subtext {
                font-size: 0.8rem;
                color: #666;
                margin-top: 4px;
            }
            
            /* Process steps styling */
            .process-step {
                display: flex;
                align-items: center;
                margin-bottom: 12px;
            }
            
            .step-number {
                background-color: var(--sap-primary-color);
                color: white;
                width: 24px;
                height: 24px;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                font-weight: bold;
                margin-right: 12px;
                flex-shrink: 0;
            }
            
            .step-content {
                flex-grow: 1;
            }
            
            .step-title {
                font-weight: 600;
                margin-bottom: 4px;
            }
            
            .step-description {
                font-size: 0.9rem;
                color: var(--sap-text-color);
            }
        </style>
    """, unsafe_allow_html=True)

# --- Helper Classes and Functions ---

class SAPDocumentExtraction:
    def __init__(self, config_dict):
        """
        Initialize the SAP Document Extraction client

        Args:
            config_dict (dict): Configuration dictionary
        """
        self.config = config_dict
        self.base_url = self.config.get('url')
        self.client_id = self.config.get('uaa', {}).get('clientid')
        self.client_secret = self.config.get('uaa', {}).get('clientsecret')
        self.uaa_url = self.config.get('uaa', {}).get('url')
        self.access_token = None
        self.token_expiry = 0
    
    def _get_auth_token(self):
        """Get OAuth token for authentication"""
        if self.access_token and time.time() < self.token_expiry:
            return self.access_token
            
        auth_url = f"{self.uaa_url}/oauth/token"
        auth_data = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        
        response = requests.post(auth_url, data=auth_data)
        if response.status_code != 200:
            raise Exception(f"Authentication failed: {response.text}")
            
        token_data = response.json()
        self.access_token = token_data.get('access_token')
        self.token_expiry = time.time() + token_data.get('expires_in', 3600) - 300  # 5 min buffer
        
        return self.access_token
    
    def _get_headers(self):
        """Get headers with authentication token for API requests"""
        token = self._get_auth_token()
        return {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json',
        }

    def get_document_details(self):
        """
        Get list of all documents and their details
        
        Returns:
            dict: Document details
        """
        headers = self._get_headers()
        url = f"{self.base_url}/document-information-extraction/v1/document/jobs"
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            raise Exception(f"Failed to get document details: {response.text}")
            
        return response.json()

    def get_extraction_results(self, document_id):
        """
        Get extraction results for a document
        
        Args:
            document_id (str): Document ID
            
        Returns:
            dict: Extraction results
        """
        headers = self._get_headers()
        url = f"{self.base_url}/document-information-extraction/v1/document/jobs/{document_id}"
        
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            raise Exception(f"Failed to get extraction results: {response.text}")
            
        return response.json()
    
    def upload_document(self, file_bytes, file_name):
        """
        Upload a document to the Document Extraction service
        
        Args:
            file_bytes (bytes): Document file bytes
            file_name (str): Document file name
            
        Returns:
            dict: Upload response
        """
        headers = self._get_headers()
        url = f"{self.base_url}/document-information-extraction/v1/document/jobs"
        
        files = {
            'file': (file_name, file_bytes)
        }
        
        data = {
            'options': json.dumps({
                'extraction': {
                    'headerFields': ['Functional_Spec_ID', 'Description_ID', 'Develop_Class'],
                    'lineItemFields': ['Transport', 'Object_Type', 'Object_Identifier']
                }
            })
        }
        
        response = requests.post(url, headers=headers, files=files, data=data)
        if response.status_code != 202:
            raise Exception(f"Failed to upload document: {response.text}")
            
        return response.json()


def post_to_sap_odata(url, username, password, payload):
    """
    Sends a POST request to an SAP OData service using CSRF token authentication.

    Args:
        url (str): The OData service base URL.
        username (str): Basic auth username.
        password (str): Basic auth password.
        payload (dict): JSON payload to send.

    Returns:
        Response object from the POST request.
    """
    auth = HTTPBasicAuth(username, password)

    # Step 1: Fetch CSRF token
    token_headers = {
        "X-CSRF-Token": "Fetch",
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json",
        "Accept-Language": "en-US",
        "SAP-Client": "000"  # Match the sap-client in the Set-Cookie
    }

    try:
        token_response = requests.get(url, headers=token_headers, auth=auth, verify=False)
        token_response.raise_for_status()
    except requests.RequestException as e:
        st.error(f"Error fetching CSRF token: {e}")
        return None

    csrf_token = token_response.headers.get("x-csrf-token")
    cookies = token_response.cookies

    if not csrf_token:
        st.error("Failed to retrieve CSRF token.")
        return None

    # Step 2: Send POST request with token and cookies
    post_headers = {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrf_token,
        "X-Requested-With": "XMLHttpRequest"
    }

    try:
        post_response = requests.post(
            url,
            json=payload,
            headers=post_headers,
            cookies=cookies,
            auth=auth,
            verify=False
        )
        post_response.raise_for_status()
        return post_response
    except requests.RequestException as e:
        st.error(f"Error during POST request: {e}")
        return None


def create_payloads_from_extraction(extraction_data):
    """
    Creates multiple payloads from extraction data based on the mapping schema

    Args:
        extraction_data (dict): The document extraction results
        
    Returns:
        list: List of payload dictionaries ready for posting
    """
    payloads = []

    # Extract values from the headerFields
    header_fields = {field['name']: field['value'] for field in extraction_data['extraction']['headerFields']}
    functional_spec_id = header_fields.get('Functional_Spec_ID')
    description_id = header_fields.get('Description_ID')
    develop_class = header_fields.get('Develop_Class')

    # Process each line item to create a payload
    line_items = extraction_data['extraction'].get('lineItems', [])

    if not line_items:
        return payloads  # Empty list if no line items

    # Handle different line item formats
    if not isinstance(line_items[0], list):
        # Handle case where lineItems is a list of dictionaries
        for line_item in line_items:
            # Create a mapping of field names to values for the current line item
            if isinstance(line_item, dict):
                line_data = line_item
            else:
                line_data = {item['name']: item['value'] for item in line_item}
            
            payload = {
                "Trkorr": line_data.get('Transport'),
                "ObjType": line_data.get('Object_Type'),
                "ObjName": line_data.get('Object_Identifier'),
                "Process": description_id,
                "FSId": functional_spec_id,
                "Devclass": develop_class
            }
            payloads.append(payload)
    else:
        # Handle case where lineItems is a list of lists
        for line_item in line_items:
            # Create a mapping of field names to values for the current line item
            line_data = {item['name']: item['value'] for item in line_item}
            
            payload = {
                "Trkorr": line_data.get('Transport'),
                "ObjType": line_data.get('Object_Type'),
                "ObjName": line_data.get('Object_Identifier'),
                "Process": description_id,
                "FSId": functional_spec_id,
                "Devclass": develop_class
            }
            payloads.append(payload)

    return payloads


def parse_xml_data(xml_content):
    """
    Parse XML data from SAP OData service

    Args:
        xml_content: XML content to parse

    Returns:
        DataFrame: Parsed data as a pandas DataFrame
    """
    # Create namespace map
    namespaces = {
        'atom': 'http://www.w3.org/2005/Atom',
        'm': 'http://schemas.microsoft.com/ado/2007/08/dataservices/metadata',
        'd': 'http://schemas.microsoft.com/ado/2007/08/dataservices'
    }

    # Parse the XML
    root = ET.fromstring(xml_content)

    # Extract data from each entry
    data = []
    for entry in root.findall('.//atom:entry', namespaces):
        properties = entry.find('.//m:properties', namespaces)
        
        # Extract properties
        trkorr = properties.find('./d:Trkorr', namespaces).text
        obj_type = properties.find('./d:ObjType', namespaces).text
        obj_name = properties.find('./d:ObjName', namespaces).text
        process = properties.find('./d:Process', namespaces).text
        devclass = properties.find('./d:Devclass', namespaces).text
        fs_id = properties.find('./d:FSId', namespaces).text
        status = properties.find('./d:Status', namespaces).text
        
        data.append({
            'Transport': trkorr,
            'Type': obj_type,
            'Name': obj_name,
            'Process': process,
            'Dev Class': devclass,
            'FS ID': fs_id,
            'Status': status
        })

    return pd.DataFrame(data)


@st.cache_data(show_spinner="Fetching SAP data...")
def get_data_from_odata(username, password):
    """
    Fetch data from SAP OData service
    
    Args:
        username (str): SAP username
        password (str): SAP password
        
    Returns:
        DataFrame: Parsed data as a pandas DataFrame
    """
    try:
        response = requests.get(
            server_url + odata_path, 
            auth=(username, password),
            verify=False
        )
        response.raise_for_status()
        
        # Parse the XML response
        df = parse_xml_data(response.text)
        
        # Add impacted flag (for demonstration, every other row is marked as impacted)
        df['impacted'] = ['yes' if i % 2 == 0 else 'no' for i in range(len(df))]
        
        return df
    except Exception as e:
        st.error(f"❌ Error fetching OData: {e}")
        return pd.DataFrame()
def load_image(image_path):
    """
    Load an image file
    
    Args:
        image_path (str): Path to the image file
        
    Returns:
        Image object or None if file not found
    """
    try:
        with open(image_path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        st.warning(f"Image file not found: {image_path}")
        return None
    
def create_processvibe_logo():
    """Generate the SAP ProcessVibe logo as HTML with image"""
    # Try to load the logo image
    logo_path = "logotr.png"
    logo_bytes = load_image(logo_path)
    
    if logo_bytes:
        # Encode the image as base64
        encoded = base64.b64encode(logo_bytes).decode()
        logo_html = f'<img src="data:image/png;base64,{encoded}" alt="ProcessVibe Logo" style="height: 150px; margin-right: 10px; vertical-align: middle;">'
        
        return f"""
        <div style="text-align: center; margin-bottom: 0.5rem;">
        {logo_html}
        </div>
        <div style="text-align: center; margin-bottom: 1.5rem;">
            <div style="font-size: 1rem; color: #666; margin-top: 0.5rem;">Powered by AI</div>
        </div>
        """
    else:
        # Fallback to text-only logo
        return """
        <div style="text-align: center; margin-bottom: 1.5rem;">
            <span style="font-size: 2.5rem; font-weight: 700; color: #0a6ed1;">S<span style="color: #000;">AP</span> Process<span style="color: #0a6ed1;">V</span><span style="color: #000;">I</span>be</span>
            <div style="font-size: 1rem; color: #666; margin-top: 0.5rem;">Powered by AI</div>
        </div>
        """

# --- Session State Initialization ---
def init_session_state():
    """Initialize session state variables"""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'username' not in st.session_state:
        st.session_state.username = ""
    if 'password' not in st.session_state:
        st.session_state.password = ""
    if 'active_tab' not in st.session_state:
        st.session_state.active_tab = "document"
    if 'extraction_data_dict' not in st.session_state:
        st.session_state.extraction_data_dict = {}  # Dictionary to store multiple document extractions
    if 'active_document_id' not in st.session_state:
        st.session_state.active_document_id = None  # Track which document is currently active
    if 'payloads_dict' not in st.session_state:
        st.session_state.payloads_dict = {}  # Dictionary to store payloads for each document
    if 'post_results_dict' not in st.session_state:
        st.session_state.post_results_dict = {}  # Dictionary to store post results for each document
    if 'available_documents' not in st.session_state:
        st.session_state.available_documents = []  # List to store available documents from API
    if 'mapping_history' not in st.session_state:
        st.session_state.mapping_history = []  # List to store mapping script execution history
    if 'data_refresh_timestamp' not in st.session_state:
        st.session_state.data_refresh_timestamp = datetime.now()  # Track when data was last refreshed

def authenticate(username, password):
    """
    Simple authentication function - in a real app, this would verify against SAP
    
    Args:
        username (str): Username
        password (str): Password
        
    Returns:
        bool: True if authenticated, False otherwise
    """
    # For demo purposes, accept any non-empty credentials
    # In a real application, this would validate against SAP credentials
    return username and password

# --- UI Components ---

def render_login_page():
    """Render the login page"""
    st.markdown(create_processvibe_logo(), unsafe_allow_html=True)
    
    # Create a centered login form
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        with st.form("login_form"):
            st.subheader("Login")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Login")
            
            if submit:
                if authenticate(username, password):
                    st.session_state.authenticated = True
                    st.session_state.username = "I760927"#username
                    st.session_state.password = "Welcome@123SAI"#password
                    st.rerun()
                else:
                    st.error("Invalid username or password. Please try again.")

def render_document_tab():
    """Render the document management tab"""
    # Initialize the SAP Document Extraction client
    config = {
        "url": dox_url,
        "uaa": {
            "clientid": dox_client_id,
            "clientsecret": dox_client_secret,
            "url": dox_uaa_url
        }
    }
    client = SAPDocumentExtraction(config_dict=config)
    
    # Document Upload Section
    st.subheader("📄 Document Upload")
    
    # Upload document form
    uploaded_file = st.file_uploader("Upload document for extraction", type=["pdf", "png", "jpg", "jpeg", "tiff"])
    
    if uploaded_file is not None:
        if st.button("Upload to Document Extraction Service"):
            try:
                with st.spinner("Uploading document..."):
                    file_bytes = uploaded_file.getvalue()
                    upload_response = client.upload_document(file_bytes, uploaded_file.name)
                    st.success(f"Document uploaded successfully! Job ID: {upload_response.get('id')}")
                    
                    # Refresh document list
                    document_details = client.get_document_details()
                    if 'results' in document_details:
                        st.session_state.available_documents = document_details['results']
                    
                    # Set the uploaded document as the selected document
                    st.session_state.selected_doc_id = upload_response.get('id')
                    st.session_state.selected_doc_name = uploaded_file.name
                    st.rerun()
            except Exception as e:
                st.error(f"Error uploading document: {str(e)}")
    
    # Document Management Section
    st.subheader("📋 Document Management")
    
    # Refresh document list button
    col1, col2 = st.columns([1, 5])
    with col1:
        if st.button("🔄 Refresh List"):
            with st.spinner("Fetching available documents..."):
                try:
                    document_details = client.get_document_details()
                    if 'results' in document_details:
                        st.session_state.available_documents = document_details['results']
                        st.success(f"Found {len(st.session_state.available_documents)} documents")
                        st.rerun()
                    else:
                        st.error("No documents found or invalid response format")
                except Exception as e:
                    st.error(f"Error fetching documents: {str(e)}")
    
    # Document processing actions
    extract_col, upload_col = st.columns(2)
    with extract_col:
        extract_button = st.button("1. Extract Document Info", use_container_width=True, 
                                   disabled='selected_doc_id' not in st.session_state)

    with upload_col:
        upload_button = st.button("2. Upload to SAP", use_container_width=True,
                                 disabled=not st.session_state.extraction_data_dict)

    # Display available documents
    if st.session_state.available_documents:
        # Create a responsive document grid with 3 columns
        doc_cols = st.columns(3)
        
        for i, doc in enumerate(st.session_state.available_documents):
            doc_id = doc.get('id')
            doc_name = doc.get('fileName', 'Unknown')
            doc_status = doc.get('status', 'Unknown')
            
            # Determine the status indicator color
            status_class = "status-pending"
            if doc_status.lower() == "done":
                status_class = "status-success"
            elif doc_status.lower() == "failed":
                status_class = "status-error"
            elif doc_status.lower() == "in progress":
                status_class = "status-warning"
            
            # Create a clickable document card
            with doc_cols[i % 3]:
                card_html = f"""
                <div class="document-card" onclick="document.getElementById('select_doc_{doc_id}').click()">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <div style="font-weight: 600; color: var(--sap-text-color);">{doc_name}</div>
                        <div>
                            <span class="status-indicator {status_class}"></span>
                            <span style="font-size: 0.8rem; color: #666;">{doc_status}</span>
                        </div>
                    </div>
                    <div style="font-size: 0.75rem; color: #888; overflow: hidden; text-overflow: ellipsis;">ID: {doc_id}</div>
                </div>
                """
                st.markdown(card_html, unsafe_allow_html=True)
                
                # Hidden button for document selection
                if st.button("Select", key=f"select_doc_{doc_id}", help=f"Select {doc_name}"):
                    st.session_state.selected_doc_id = doc_id
                    st.session_state.selected_doc_name = doc_name
                    st.rerun()
    else:
        st.info("No documents available. Upload a document or refresh the list.")

    # Extract document info
    if extract_button and 'selected_doc_id' in st.session_state:
        doc_id = st.session_state.selected_doc_id
        doc_name = st.session_state.selected_doc_name
        
        try:
            with st.spinner(f"Extracting document {doc_name}..."):
                extraction_data = client.get_extraction_results(doc_id)
                
                st.session_state.extraction_data_dict[doc_id] = extraction_data
                st.session_state.payloads_dict[doc_id] = create_payloads_from_extraction(extraction_data)
                
                # Set as active document
                st.session_state.active_document_id = doc_id
                
                st.success(f"Successfully extracted document: {doc_name}")
                st.rerun()
        except Exception as e:
            st.error(f"Error extracting document {doc_name}: {str(e)}")

    # Upload to SAP
    if upload_button and st.session_state.extraction_data_dict:
        # Create a container to show progress
        upload_container = st.container()
        
        # Show upload options
        upload_all = st.checkbox("Upload all documents at once", value=True)
        
        if upload_all:
            documents_to_upload = list(st.session_state.extraction_data_dict.keys())
        else:
            # Only upload the active document
            if st.session_state.active_document_id:
                documents_to_upload = [st.session_state.active_document_id]
            else:
                documents_to_upload = []
                st.warning("No active document selected. Please select a document from the list.")
        
        # Upload the selected documents
        if documents_to_upload:
            with upload_container:
                total_payloads = sum(len(st.session_state.payloads_dict.get(doc_id, [])) for doc_id in documents_to_upload)
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                processed_count = 0
                
                for doc_id in documents_to_upload:
                    # Find the filename for this document ID
                    doc_name = next((doc.get('fileName', doc_id) for doc in st.session_state.available_documents if doc.get('id') == doc_id), doc_id)
                    
                    payloads = st.session_state.payloads_dict.get(doc_id, [])
                    
                    if not payloads:
                        continue
                    
                    status_text.text(f"Uploading document {doc_name}...")
                    
                    # Initialize results for this document
                    st.session_state.post_results_dict[doc_id] = []
                    
                    for i, payload in enumerate(payloads):
                        status_text.text(f"Document {doc_name}: Posting payload {i+1}/{len(payloads)}")
                        
                        # Actual posting to OData service
                        response = post_to_sap_odata(odata_url, st.session_state.username, st.session_state.password, payload)
                        
                        result = {
                            "payload": payload,
                            "success": response is not None and 200 <= response.status_code < 300,
                            "status_code": response.status_code if response else None,
                            "response": response.text if response else "Failed to post"
                        }
                        
                        st.session_state.post_results_dict[doc_id].append(result)
                        
                        # Update progress
                        processed_count += 1
                        progress_bar.progress(processed_count / total_payloads)
                
                # Count total successes
                total_success_count = sum(sum(1 for r in results if r["success"]) 
                                         for results in st.session_state.post_results_dict.values())
                
                if total_success_count > 0:
                    status_text.success(f"Successfully uploaded {total_success_count} out of {total_payloads} items.")
                else:
                    status_text.error("Failed to upload any items. Check your connection settings.")

    # Display the extraction results
    if st.session_state.active_document_id and st.session_state.active_document_id in st.session_state.extraction_data_dict:
        active_doc_id = st.session_state.active_document_id
        
        # Find the filename for this document ID
        active_doc_name = next((doc.get('fileName', active_doc_id) for doc in st.session_state.available_documents if doc.get('id') == active_doc_id), active_doc_id)
        
        st.subheader(f"Document Information: {active_doc_name}")
        active_extraction = st.session_state.extraction_data_dict[active_doc_id]
        
        # Display header fields
        st.write("Header Fields:")
        header_fields = active_extraction['extraction']['headerFields']
        header_df = pd.DataFrame(header_fields)
        st.dataframe(header_df, hide_index=True)
        
        # Display line items
        st.write("Line Items (Ready for Upload):")
        active_payloads = st.session_state.payloads_dict.get(active_doc_id, [])
        if active_payloads:
            payloads_df = pd.DataFrame(active_payloads)
            st.dataframe(payloads_df, hide_index=True)
        
        # Display post results if available
        active_results = st.session_state.post_results_dict.get(active_doc_id, [])
        if active_results:
            success_count = sum(1 for r in active_results if r["success"])
            
            if success_count == len(active_results):
                st.success(f"All {success_count} items successfully uploaded to SAP system")
            else:
                st.warning(f"{success_count} of {len(active_results)} items successfully uploaded to SAP system")
            
            if st.checkbox("Show detailed upload results"):
                for i, result in enumerate(active_results):
                    st.write(f"Item {i+1}:")
                    
                    if result["success"]:
                        st.success(f"Status: {result['status_code']}")
                    else:
                        st.error(f"Status: {result['status_code']}")
                        st.text(result["response"])
                    
                    with st.expander("Show payload"):
                        st.json(result["payload"])

def render_analysis_tab(impacted_only=False):
    """
    Render the data analysis tab
    
    Args:
        impacted_only (bool): Whether to show only impacted objects
    """
    # Fetch data from OData service
    df = get_data_from_odata(st.session_state.username, st.session_state.password)
    
    if df.empty:
        st.warning("⚠️ No data found or error fetching SAP data.")
        return
    
    # Filter for impacted objects if requested
    if impacted_only:
        df = df[df['impacted'] == 'yes']
        st.subheader("Impact Analysis")
        st.caption("Showing only objects marked as impacted")
    else:
        st.subheader("ProcessVibe Analysis")
        st.caption("Analysis of all mapped SAP custom objects")
    
    # Ignore "not found" objects
    df_without_notfound = df[df["Status"].str.lower() != "not found"]

    # Filter to include only exist and mapped statuses (we want to focus only on objects with processes)
    process_df = df_without_notfound[df_without_notfound["Status"].str.lower().isin(["exist", "mapped"])]

    # Calculate metrics
    total_objects = len(df_without_notfound)
    total_mapped = len(process_df)  # Objects with processes (exist + mapped)
    unmapped = len(df_without_notfound[df_without_notfound["Status"].str.lower() == "unmapped"])
    
    mapping_completion = (total_mapped / total_objects) * 100 if total_objects > 0 else 0

    # Metric Cards in a better layout with custom styling
    col1, col2, col3 = st.columns(3)
    
    # Custom HTML for metric cards
    with col1:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">Total Custom Objects</div>
                <div class="metric-value">{total_objects}</div>
                <div class="metric-subtext">Custom objects in scope</div>
            </div>
        """, unsafe_allow_html=True)
        
    with col2:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">Mapped to Processes</div>
                <div class="metric-value">{total_mapped}</div>
                <div class="metric-subtext">Objects linked to business processes</div>
            </div>
        """, unsafe_allow_html=True)
        
    with col3:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">Mapping Completion</div>
                <div class="metric-value">{mapping_completion:.2f}%</div>
                <div class="metric-subtext">Progress towards complete mapping</div>
            </div>
        """, unsafe_allow_html=True)

    # Process-Object Relationship Analysis
    # Simplified tabs focused only on process relationships
    tab1, tab2, tab3 = st.tabs(["Process Overview", "Objects by Process", "Package Overview"])

    with tab1:
        # Overall process mapping summary
        st.subheader("Process Mapping Overview")
        
        # Create pie chart for mapping status
        status_counts = df_without_notfound['Process'].value_counts().reset_index()
        status_counts.columns = ['Process', 'Count']
        
        # Calculate percentages
        status_counts['Percentage'] = (status_counts['Count'] / total_objects * 100).round(1)
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            # Pie chart
            fig = px.pie(
                status_counts,
                names='Process',
                values='Count',
                title='Object Mapping Status',
                color='Process',
                #color_discrete_map={
                #    'exist': '#28a745',    # Green
                #    'mapped': '#17a2b8',   # Blue
                #    'unmapped': '#ffc107'  # Yellow/orange
                #},
                hole=0.4
            )
            fig.update_traces(textposition='outside', textinfo='percent+label')
            st.plotly_chart(fig, use_container_width=True)
            
        with col2:
            # Process count analysis
            if not process_df.empty:
                # Count unique processes
                process_counts = process_df['Process'].value_counts().reset_index()
                process_counts.columns = ['Process', 'Object Count']
                
                # Top processes by object count
                top_processes = process_counts.head(5)
                
                # Create horizontal bar chart
                fig = px.bar(
                    top_processes,
                    y='Process',
                    x='Object Count',
                    title=f'Top 5 Processes by Object Count',
                    orientation='h',
                    color_discrete_sequence=['#0a6ed1']
                )
                
                fig.update_layout(
                    yaxis={'categoryorder':'total ascending'},
                    xaxis_title="Number of Objects",
                    yaxis_title="",
                )
                
                st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        # Process-centric analysis
        if not process_df.empty:
            # Create a dropdown to select a process
            processes = sorted(process_df['Process'].unique())
            processes.insert(0, "All Processes")
            selected_process = st.selectbox(
                "Select a Process to Analyze",
                options=processes,
                key=f"proc_select_{'impact' if impacted_only else 'main'}"
            )
            
            if selected_process:
                # Filter for selected process
                if selected_process == "All Processes":
                    selected_process_df = process_df
                else:    
                    selected_process_df = process_df[process_df['Process'] == selected_process]
                
                # Count by object type
                type_counts = selected_process_df['Type'].value_counts().reset_index()
                type_counts.columns = ['Object Type', 'Count']
                
                col2, col1 = st.columns([2, 1])
                
                with col1:
                    # Process details card
                    st.markdown(f"""
                        <div style="background-color: white; padding: 20px; border-radius: 8px; border: 1px solid #d1d1d1; margin-bottom: 20px;">
                            <h4 style="color: #0a6ed1; margin-top: 0;">Process: {selected_process}</h4>
                            <p><strong>Total Objects:</strong> {len(selected_process_df)}</p>
                            <p><strong>Object Types:</strong> {len(type_counts)}</p>
                            <p><strong>Development Classes:</strong> {selected_process_df['Dev Class'].nunique()}</p>
                        </div>
                    """, unsafe_allow_html=True)
                
                with col2:
                    # Pie chart by object type
                    fig = px.pie(
                        type_counts,
                        names='Object Type',
                        values='Count',
                        title=f'Object Types in Process',
                        hole=0.4
                    )
                    fig.update_traces(textposition='outside', textinfo='percent+label')
                    st.plotly_chart(fig, use_container_width=True)
                
        else:
            st.info("No objects mapped to processes found.")
    
    with tab3:
        # Package overview with pie chart
        if not process_df.empty:
            # Group by package
            package_counts = process_df['Dev Class'].value_counts().reset_index()
            package_counts.columns = ['Package', 'Count']
            
            # Calculate percentage
            package_counts['Percentage'] = (package_counts['Count'] / len(process_df) * 100).round(1)
            
            col1, col2 = st.columns([3, 2])
            
            with col1:
                # Show top packages as a pie chart
                top_packages = package_counts.head(8)  # Top 8 packages
                other_count = package_counts['Count'].sum() - top_packages['Count'].sum()
                
                if other_count > 0:
                    other_row = pd.DataFrame({'Package': ['Other Packages'], 'Count': [other_count], 
                                             'Percentage': [(other_count / len(process_df) * 100).round(1)]})
                    chart_data = pd.concat([top_packages, other_row])
                else:
                    chart_data = top_packages
                
                fig = px.pie(
                    chart_data,
                    names='Package',
                    values='Count',
                    title=f'Objects by Package {("(Impacted Only)" if impacted_only else "")}',
                    hover_data=['Percentage'],
                    labels={'Percentage': 'Percentage (%)'}
                )
                fig.update_traces(textposition='inside', textinfo='percent+label')
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                # Top packages as table
                st.write("##### Top Packages")
                st.dataframe(
                    package_counts.head(10)[['Package', 'Count', 'Percentage']],
                    use_container_width=True,
                    hide_index=True
                )
                
                # Package count
                st.metric("Total Packages", process_df['Dev Class'].nunique())
        else:
            st.info("No objects mapped to processes found.")
    
    # Data Explorer Section
    st.subheader("Process Object Explorer")
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        selected_processes = st.multiselect(
            "Filter by Process", 
            options=sorted(process_df['Process'].unique()) if not process_df.empty else [],
            key=f"explorer_process_{'impact' if impacted_only else 'main'}"
        )
    
    with col2:
        selected_types = st.multiselect(
            "Filter by Object Type", 
            options=sorted(process_df['Type'].unique()) if not process_df.empty else [],
            key=f"explorer_type_{'impact' if impacted_only else 'main'}"
        )
    
    with col3:
        selected_packages = st.multiselect(
            "Filter by Package", 
            options=sorted(process_df['Dev Class'].unique()) if not process_df.empty else [],
            key=f"explorer_package_{'impact' if impacted_only else 'main'}"
        )
    
    # Apply filters
    filtered_df = process_df.copy()
    
    if selected_processes:
        filtered_df = filtered_df[filtered_df['Process'].isin(selected_processes)]
    
    if selected_types:
        filtered_df = filtered_df[filtered_df['Type'].isin(selected_types)]
    
    if selected_packages:
        filtered_df = filtered_df[filtered_df['Dev Class'].isin(selected_packages)]
    
    # Display filtered data
    st.caption(f"Showing {len(filtered_df)} of {len(process_df)} process-mapped objects")
    
    st.dataframe(
        filtered_df[['Process', 'Type', 'Name', 'Dev Class','Transport']],
        use_container_width=True,
        height=400
    )

    #Remove entire table display here

# --- Admin Page Functions ---
def trigger_mapping_script(username, password):
    """
    Trigger the backend mapping script via SAP API
    
    Args:
        username (str): SAP username
        password (str): SAP password
        
    Returns:
        dict: Result of the mapping operation
    """
    try:
        # This would typically call an SAP API endpoint to trigger the mapping process
        # For demo purposes, we'll simulate this with a delay
        with st.spinner("Running mapping script in the backend..."):
            time.sleep(10)  # Simulate processing time
            
            # Return simulated result
            return {
                "status": "success",
                "message": "Mapping script executed successfully",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "objects_mapped": 42,  # Simulated number
                "job_id": f"MAP_{int(time.time())}"
            }
    except Exception as e:
        st.error(f"Error triggering mapping script: {str(e)}")
        return {
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

def render_admin_page():
    """Render the admin page with advanced features"""
    
    # Fetch data for admin analysis
    df = get_data_from_odata(st.session_state.username, st.session_state.password)
    
    if df.empty:
        st.warning("⚠️ No data found or error fetching SAP data.")
        return
    
    # Admin actions section
    st.write("### System Actions")
    
    col1, col2, col3 = st.columns([1, 1, 1])
    
    with col1:
        if st.button("🔄 Run Mapping Script", key="admin_run_mapping", help="Trigger the backend mapping script to identify object relationships"):
            result = trigger_mapping_script(st.session_state.username, st.session_state.password)
            
            if result["status"] == "success":
                st.success(f"✅ {result['message']}")
                st.info(f"Mapped {result['objects_mapped']} objects. Job ID: {result['job_id']}")
                
                # Store in session state for history
                if "mapping_history" not in st.session_state:
                    st.session_state.mapping_history = []
                
                st.session_state.mapping_history.append(result)
                
                # Refresh data
                st.rerun()
            else:
                st.error(f"❌ {result['message']}")
    
    with col2:
        if st.button("🧹 Clear Extraction Cache", key="admin_clear_cache", help="Clear cached extraction results"):
            st.session_state.extraction_data_dict = {}
            st.session_state.payloads_dict = {}
            st.session_state.post_results_dict = {}
            st.success("Extraction cache cleared successfully")
    
    with col3:
        if st.button("📊 Refresh Analytics Data", key="admin_refresh_data", help="Refresh all analytics data from SAP"):
            # Clear the cached data to force refresh
            st.cache_data.clear()
            st.success("Analytics data refreshed successfully")
            st.rerun()
    
    # Mapping history
    if "mapping_history" in st.session_state and st.session_state.mapping_history:
        with st.expander("Mapping History", expanded=False):
            for i, history in enumerate(reversed(st.session_state.mapping_history)):
                st.markdown(f"""
                    <div style="margin-bottom: 10px; padding: 10px; border-left: 3px solid #0a6ed1; background-color: #f8f9fa;">
                        <div style="font-weight: 600;">{history['timestamp']} - Job ID: {history.get('job_id', 'N/A')}</div>
                        <div>Status: {history['status'].upper()}</div>
                        <div>Objects mapped: {history.get('objects_mapped', 'N/A')}</div>
                    </div>
                """, unsafe_allow_html=True)
    
        # Process Coverage Analysis (Only for exist and mapped)
    st.write("### Process Coverage Analysis")
    
    # Analysis by process
    process_df = df[df['Status'].isin(['exist', 'mapped'])]
    if not process_df.empty:
        # Group by Process and count objects
        process_counts = process_df.groupby('Process').size().reset_index(name='Count')
        process_counts = process_counts.sort_values(by='Count', ascending=False)
        
        # Count the number of unique dev classes per process
        process_devclass_counts = process_df.groupby('Process')['Dev Class'].nunique().reset_index()
        process_devclass_counts.columns = ['Process', 'Unique Dev Classes']
        
        # Count the number of unique object types per process
        process_objtype_counts = process_df.groupby('Process')['Type'].nunique().reset_index()
        process_objtype_counts.columns = ['Process', 'Unique Object Types']
        
        # Merge the counts
        process_analysis = pd.merge(process_counts, process_devclass_counts, on='Process')
        process_analysis = pd.merge(process_analysis, process_objtype_counts, on='Process')
        
        # Add Direct vs Indirect counts
        direct_counts = process_df[process_df['Status'] == 'exist'].groupby('Process').size().reset_index(name='Direct Mapped')
        indirect_counts = process_df[process_df['Status'] == 'mapped'].groupby('Process').size().reset_index(name='Indirect Mapped')
        
        process_analysis = pd.merge(process_analysis, direct_counts, on='Process', how='left')
        process_analysis = pd.merge(process_analysis, indirect_counts, on='Process', how='left')
        
        # Fill NAs with zeros
        process_analysis = process_analysis.fillna(0)
        
        # Add percentage of direct vs indirect
        #process_analysis['Direct %'] = (process_analysis['Direct Mapped'] / process_analysis['Count'] * 100).round(1)
        #process_analysis['Indirect %'] = (process_analysis['Indirect Mapped'] / process_analysis['Count'] * 100).round(1)
        
        # Display process analysis table
        st.dataframe(process_analysis, hide_index=True, use_container_width=True)
    else:
        st.info("No mapped objects with processes found.")


    tab1, tab2, tab3 = st.tabs(["Status Distribution", "Objects Type", "Direct vs Indirect Mapping"])
    with tab1:
        # Status Distribution Analysis
        st.write("### Status Distribution Analysis")
        
        # Create status distribution
        status_counts = df['Status'].value_counts().reset_index()
        status_counts.columns = ['Status', 'Count']
        
        # Calculate percentages
        total_objects = len(df)
        status_counts['Percentage'] = (status_counts['Count'] / total_objects * 100).round(2)
        
        col1, col2 = st.columns([2, 3])
        
        with col1:
            # Status distribution table
            st.dataframe(
                status_counts,
                hide_index=True,
                use_container_width=True
            )
        
        with col2:
            # Status distribution chart
            fig = px.pie(
                status_counts,
                names='Status',
                values='Count',
                title=f'Status Distribution ({total_objects} total objects)',
                color='Status',
                color_discrete_map={
                    'exist': '#28a745',
                    'mapped': '#17a2b8',
                    'unmapped': '#ffc107',
                    'not found': '#dc3545'
                },
                hole=0.4
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2: 
        # Object Type Distribution
        st.write("### Object Type Analysis")
        
        # Get counts by object type and status
        type_status_df = pd.crosstab(df['Type'], df['Status'])
        
        # Add a total column
        type_status_df['Total'] = type_status_df.sum(axis=1)
        
        # Sort by total count descending
        type_status_df = type_status_df.sort_values(by='Total', ascending=False)
        
        # Create a stacked bar chart
        fig = go.Figure()
        
        status_colors = {
            'exist': '#28a745',
            'mapped': '#17a2b8',
            'unmapped': '#ffc107',
            'not found': '#dc3545'
        }
        
        # Add traces for each status
        for status in df['Status'].unique():
            if status in type_status_df.columns:
                fig.add_trace(go.Bar(
                    name=status,
                    x=type_status_df.index,
                    y=type_status_df[status],
                    text=type_status_df[status],
                    marker_color=status_colors.get(status.lower(), '#6c757d')
                ))
        
        fig.update_layout(
            title='Object Type Distribution by Status',
            xaxis_title='Object Type',
            yaxis_title='Count',
            barmode='stack',
            legend_title='Status',
            height=500
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    with tab3: 
        # Direct vs Indirect Mapping Analysis
        st.write("### Direct vs Indirect Mapping Analysis")
        
        # Filter for only exist and mapped objects (those with processes)
        process_df = df[df['Status'].isin(['exist', 'mapped'])]
        
        # Analysis by status
        if not process_df.empty:
            # Create pie chart for direct vs indirect
            status_counts = process_df['Status'].value_counts().reset_index()
            status_counts.columns = ['Status', 'Count']
            
            # Map status to more descriptive names
            status_counts['Mapping Type'] = status_counts['Status'].map({
                'exist': 'Direct (from document)',
                'mapped': 'Indirect (from mapping)'
            })
            
            col1, col2 = st.columns([1, 1])
            
            with col1:
                # Pie chart
                fig = px.pie(
                    status_counts,
                    names='Mapping Type',
                    values='Count',
                    title=f'Direct vs Indirect Mapping ({len(process_df)} objects)',
                    color='Mapping Type',
                    color_discrete_map={
                        'Direct (from document)': '#28a745',
                        'Indirect (from mapping)': '#17a2b8'
                    },
                    hole=0.4
                )
                fig.update_traces(textposition='inside', textinfo='percent+label')
                st.plotly_chart(fig, use_container_width=True)
                
            with col2:
                # Distribution by object type
                type_mapping = pd.crosstab(
                    process_df['Type'], 
                    process_df['Status'],
                    margins=True,
                    margins_name='Total'
                )
                
                # Rename columns for clarity
                type_mapping.columns = ['Direct (exist)', 'Indirect (mapped)', 'Total'] if 'exist' in type_mapping.columns and 'mapped' in type_mapping.columns else type_mapping.columns
                
                # Display table
                st.write("##### Mapping Distribution by Object Type")
                st.dataframe(type_mapping, use_container_width=True)
    

        
        # Create a visualization of direct vs indirect mapping by process
        fig = go.Figure()
        
        fig.add_trace(go.Bar(
            name='Direct Mapped (exist)',
            x=process_analysis['Process'],
            y=process_analysis['Direct Mapped'],
            marker_color='#28a745'
        ))
        
        fig.add_trace(go.Bar(
            name='Indirect Mapped (mapped)',
            x=process_analysis['Process'],
            y=process_analysis['Indirect Mapped'],
            marker_color='#17a2b8'
        ))
        
        fig.update_layout(
            title='Direct vs Indirect Mapping by Process',
            xaxis_title='Process',
            yaxis_title='Count',
            barmode='stack',
            height=500
        )
        
        st.plotly_chart(fig, use_container_width=True)

    
    # Advanced Data Explorer
    st.write("### Advanced Data Explorer")
    
    # Add more sophisticated filters
    with st.expander("Advanced Filters", expanded=True):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            selected_statuses = st.multiselect(
                "Filter by Status",
                options=sorted(df['Status'].unique()),
                default=list(df['Status'].unique()),
                key="admin_status_multiselect"
            )
        
        with col2:
            selected_types = st.multiselect(
                "Filter by Object Type",
                options=sorted(df['Type'].unique()),
                default=[],
                key="admin_type_multiselect"
            )
        
        with col3:
            selected_devclasses = st.multiselect(
                "Filter by Development Class",
                options=sorted(df['Dev Class'].unique()),
                default=[],
                key="admin_devclass_multiselect"
            )
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Add process filter (only for objects with processes)
            mapped_processes = sorted(process_df['Process'].unique())
            selected_processes = st.multiselect(
                "Filter by Process",
                options=mapped_processes,
                default=[],
                key="admin_process_multiselect"
            )
        
        with col2:
            # Add text search for object name
            search_term = st.text_input("Search by Object Name", "", key="admin_search_input")
    
    # Apply filters
    filtered_df = df.copy()
    
    if selected_statuses:
        filtered_df = filtered_df[filtered_df['Status'].isin(selected_statuses)]
    
    if selected_types:
        filtered_df = filtered_df[filtered_df['Type'].isin(selected_types)]
    
    if selected_devclasses:
        filtered_df = filtered_df[filtered_df['Dev Class'].isin(selected_devclasses)]
    
    if selected_processes:
        filtered_df = filtered_df[filtered_df['Process'].isin(selected_processes)]
    
    if search_term:
        filtered_df = filtered_df[filtered_df['Name'].str.contains(search_term, case=False, regex=True)]
    
    # Display the filtered dataframe
    st.dataframe(
        filtered_df,
        use_container_width=True,
        height=500
    )
    

    if st.button("Export Filtered Data to CSV", key="admin_export_csv"):
        csv = filtered_df.to_csv(index=False)
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name=f"sap_processvibe_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            key="admin_download_csv"
        )
    

# --- Main Application Logic ---

def main():
    """Main application entry point"""
    # Initialize session state
    init_session_state()
    
    # Load custom CSS
    load_css()
    
    # If not authenticated, show login page
    if not st.session_state.authenticated:
        render_login_page()
        return
    
    # Create a header with the logo and logout button
    col1, col2 = st.columns([6, 1])
    with col1:
        st.markdown(create_processvibe_logo(), unsafe_allow_html=True)
    with col2:
        if st.button("Logout"):
            st.session_state.authenticated = False
            st.session_state.username = ""
            st.session_state.password = ""
            st.rerun()
    
    # Create tabs for different functionality
    tabs = st.tabs(["Document Processing", "SAP ProcessVibe", "Impact Analysis", "Admin"])
    
    with tabs[0]:
        render_document_tab()
    
    with tabs[1]:
        render_analysis_tab(impacted_only=False)
    
    with tabs[2]:
        render_analysis_tab(impacted_only=True)
        
    with tabs[3]:
        render_admin_page()

# Run the app
if __name__ == "__main__":
    main()