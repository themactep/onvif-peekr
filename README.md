# ONVIF Peekr

A Python GUI application for exploring ONVIF-enabled IP camera capabilities and capturing complete SOAP request/response data.
Built with a custom ONVIF client that provides real XML capture without library serialization issues.

## Key Features

- **Custom ONVIF Client**: Manual WS-Security authentication with complete zeep library elimination.
- **Real SOAP XML Capture**: Direct HTTP requests capture actual XML traffic without serialization issues.
- **Smart Authentication**: Hybrid strategy (WS-Security → HTTP Digest → HTTP Basic fallback).
- **Sequential File Naming**: Clean, organized filenames (001_operation_request.xml format).
- **Flexible File Organization**: Optional raw XML files in organized subdirectory structure.
- **User-Friendly GUI**: Clean tkinter interface with progress tracking and live logging.
- **Comprehensive Coverage**: 18 ONVIF operations across device, media, PTZ, and events services.
- **High Success Rate**: 89% operation success rate with proper error handling.

## Technical Architecture

### Custom ONVIF Client
- **Manual WS-Security Implementation**: Proper username token with password digest, nonce generation, and SHA1 hashing.
- **Multi-Auth Strategy**: Automatically tries WS-Security, falls back to HTTP Digest, then HTTP Basic authentication.
- **Direct SOAP Control**: Manual SOAP envelope creation with all ONVIF namespaces and proper SOAPAction headers.
- **Real XML Capture**: Bypasses all library serialization to capture actual wire-format XML.

### File Organization System
- **Sequential Numbering**: Clean filenames using 001, 002, 003... format instead of timestamps.
- **Smart File Structure**: Formatted XML files by default, optional raw files in `raw/` subdirectory.
- **User Control**: Checkbox to enable/disable raw XML file saving for reduced clutter.

## Supported ONVIF Operations (18 Total)

### Device Management Service ✅
- **GetDeviceInformation** - Basic device details (requires WS-Security).
- **GetCapabilities** - Device capabilities (no auth required).
- **GetServices** - Available services (no auth required).

### Media Service ✅
- **GetProfiles** - Media profiles with automatic ProfileToken extraction.
- **GetVideoSources** - Video source configurations.
- **GetAudioSources** - Audio source configurations.
- **GetStreamUri** - RTSP streaming endpoints (with dynamic ProfileToken).
- **GetSnapshotUri** - Snapshot endpoints (with dynamic ProfileToken).
- **GetVideoEncoderConfigurations** - Video encoding settings.
- **GetAudioEncoderConfigurations** - Audio encoding settings.
- **GetVideoSourceConfigurations** - Video source settings.
- **GetAudioSourceConfigurations** - Audio source settings.
- **GetMetadataConfigurations** - Metadata settings.

### PTZ Service ✅
- **GetConfigurations** - PTZ configurations.
- **GetNodes** - PTZ nodes.
- **GetPresets** - PTZ presets (may fail if PTZ not supported).

### Events Service ⚠️
- **GetEventProperties** - Event properties (may fail if service unavailable).
- **GetServiceCapabilities** - Event service capabilities.

## Installation

### Quick Start (Recommended)
```bash
# Clone the repository
git clone <repository-url>
cd onvif-peekr

# Run automated installation
./install.sh

# Activate virtual environment
source venv/bin/activate

# Run the application
python run_onvif_peekr.py
```

### Manual Installation
```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt install python3-dev libxml2-dev libxslt1-dev

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### Dependencies
- **Python 3.7+**
- **requests** - HTTP library (only required dependency)
- **tkinter** - GUI framework (included with Python)
- **xmllint** - XML formatting (optional, for pretty-printed output)

## Usage

### Running the Application
```bash
# Standard mode
python run_onvif_peekr.py

# Demo mode (for testing interface)
python demo.py

# Direct execution
python src/onvif_peekr.py
```

### Step-by-Step Guide

1. **Launch Application**: Run using one of the methods above

2. **Configure Connection**:
   - **IP Address**: Camera IP (e.g., 192.168.1.126)
   - **Port**: Usually 80 or 8080
   - **Username**: Camera username (e.g., admin, thingino)
   - **Password**: Camera password

3. **Set Save Options**:
   - **Save Location**: Choose directory for XML files
   - **Raw XML Files**: Check to save raw XML in `raw/` subdirectory (optional)

4. **Connect**: Click "Connect" - application will test multiple authentication methods

5. **Explore**: Click "Start Exploration" to execute all 18 ONVIF operations

6. **Monitor**: Watch real-time progress and logging in the GUI

7. **Results**: Find organized XML files in your selected directory

## File Organization

### Directory Structure
```
save_directory/
└── 192.168.1.126_20250828_132347/
    ├── 001_GetDeviceInformation_request.xml      (formatted)
    ├── 001_GetDeviceInformation_response.xml     (formatted)
    ├── 002_GetCapabilities_request.xml           (formatted)
    ├── 002_GetCapabilities_response.xml          (formatted)
    ├── 003_GetServices_request.xml               (formatted)
    ├── 003_GetServices_response.xml              (formatted)
    ├── raw/                                      (optional)
    │   ├── 001_GetDeviceInformation_request.xml  (raw XML)
    │   ├── 001_GetDeviceInformation_response.xml (raw XML)
    │   └── ...
    └── exploration_summary.json
```

### File Naming Convention
- **Sequential Numbers**: 001, 002, 003... (resets each session)
- **Operation Names**: Descriptive ONVIF operation names
- **File Types**: `_request.xml` and `_response.xml` pairs
- **Formatted Files**: Default xmllint-formatted XML (easy to read)
- **Raw Files**: Optional exact wire-format XML (debugging)

## Expected Results

### Success Rates (Tested with Thingino Camera)
- **16/18 operations successful** (89% success rate)
- **All media operations working** including complex ProfileToken operations
- **Complete SOAP XML capture** for every operation
- **Real authentication** with WS-Security working perfectly

### Typical Output
```
✓ GetDeviceInformation - SUCCESS (WS-Security)
✓ GetCapabilities - SUCCESS (No Auth)
✓ GetServices - SUCCESS (No Auth)
✓ GetProfiles - SUCCESS (WS-Security)
✓ GetVideoSources - SUCCESS (WS-Security)
✓ GetStreamUri - SUCCESS (Dynamic ProfileToken)
✓ GetSnapshotUri - SUCCESS (Dynamic ProfileToken)
✗ GetPresets - FAILED (PTZ not supported)
✗ GetEventProperties - FAILED (Service unavailable)
```

## Advanced Features

### Authentication Strategy
1. **WS-Security First**: Proper ONVIF authentication with username tokens
2. **HTTP Digest Fallback**: For cameras requiring HTTP-level auth
3. **HTTP Basic Fallback**: Last resort for basic authentication
4. **Graceful Degradation**: Continues with working authentication method

### Error Handling & Recovery
- **Connection Issues**: Automatic retry with different authentication methods
- **Service Unavailability**: Graceful skipping of unsupported services
- **Parameter Errors**: Intelligent parameter generation for complex operations
- **Network Timeouts**: 10-second timeouts prevent hanging operations
- **File System Errors**: Proper error reporting and recovery

### Logging & Debugging
- **Real-time Logging**: Live operation status in GUI
- **Detailed Error Messages**: Specific guidance for common issues
- **Method Tracking**: Shows whether operation used WS-Security, Digest, or Basic auth
- **XML Validation**: Automatic XML formatting and validation

## Troubleshooting

### Connection Issues
```
✗ Connection failed: HTTP 401
```
**Solutions:**
- Verify camera IP address and port (usually 80 or 8080)
- Check username and password credentials
- Ensure ONVIF is enabled on camera
- Try different authentication (application tries all methods automatically)

### Service Unavailability
```
✗ GetEventProperties failed: Connection closed by camera
```
**Explanation:** Some cameras don't support all ONVIF services (PTZ, Events). This is normal and expected.

### File Permission Issues
```
✗ Error saving SOAP data: Permission denied
```
**Solutions:**
- Ensure write permissions to selected save directory
- Choose a different save location (e.g., user home directory)
- Run with appropriate user privileges

### Camera Compatibility
- **Thingino cameras**: Excellent compatibility (89% success rate)
- **Generic IP cameras**: Variable support depending on ONVIF implementation
- **Enterprise cameras**: Usually full ONVIF compliance

## Project Structure
```
onvif-peekr/
├── src/
│   └── onvif_peekr.py          # Main application with custom ONVIF client
├── venv/                        # Virtual environment
├── README.md                    # Complete documentation (this file)
├── requirements.txt             # Dependencies (just requests!)
├── install.sh                   # Automated installation script
├── run_onvif_peekr.py          # Application launcher
└── demo.py                      # Demo mode for testing
```

## Testing
```bash
# Run in demo mode (no camera required)
python demo.py

# Test with real camera
python run_onvif_peekr.py
```

## Development Status
✅ **Custom ONVIF client implemented** - No more zeep dependency issues
✅ **Real SOAP XML capture working** - Actual wire-format XML saved
✅ **Sequential file naming** - Clean, organized output
✅ **Flexible file organization** - User-controlled raw XML saving
✅ **High success rate** - 89% operation success with Thingino cameras
✅ **Production ready** - Comprehensive error handling and logging

## License
MIT License - See LICENSE file for details.

## Contributing
Contributions welcome! The application uses a custom ONVIF client for maximum compatibility and real XML capture.

## Support
For issues and questions, please create an issue in the project repository.
