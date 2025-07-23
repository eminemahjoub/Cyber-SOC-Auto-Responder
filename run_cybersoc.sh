#!/bin/bash

# ==============================================================================
# Cyber-SOC Auto-Responder Production Runner
# ==============================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Print banner
echo -e "${CYAN}"
echo "🚀 CYBER-SOC AUTO-RESPONDER - PRODUCTION SYSTEM"
echo "=================================================================="
echo -e "${NC}"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check if Python 3 is installed
print_header "Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
    print_status "Python 3 found: $(python3 --version)"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
    print_status "Python found: $(python --version)"
else
    print_error "Python not found! Please install Python 3.9+ and try again."
    exit 1
fi

# Check Python version
print_header "Verifying Python version..."
PYTHON_VERSION=$($PYTHON_CMD -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
if (( $(echo "$PYTHON_VERSION >= 3.9" | bc -l) )); then
    print_status "Python version $PYTHON_VERSION is compatible"
else
    print_warning "Python version $PYTHON_VERSION may not be fully compatible. Python 3.9+ recommended."
fi

# Check if pip is available
print_header "Checking package manager..."
if command -v pip3 &> /dev/null; then
    PIP_CMD="pip3"
elif command -v pip &> /dev/null; then
    PIP_CMD="pip"
else
    print_error "pip not found! Please install pip and try again."
    exit 1
fi
print_status "Package manager found: $PIP_CMD"

# Install dependencies if needed
print_header "Installing required dependencies..."
$PIP_CMD install --quiet --upgrade pip
$PIP_CMD install --quiet pydantic-settings structlog rich python-dotenv click httpx aiohttp pyyaml requests yara-python splunk-sdk crowdstrike-falconpy thehive4py pytest pytest-asyncio
print_status "Dependencies installed successfully"

# Set up environment variables
print_header "Configuring environment..."

# Default configuration - users should update these
export SPLUNK_HOST="${SPLUNK_HOST:-localhost}"
export SPLUNK_PORT="${SPLUNK_PORT:-8089}"
export SPLUNK_USERNAME="${SPLUNK_USERNAME:-admin}"
export SPLUNK_PASSWORD="${SPLUNK_PASSWORD:-changeme}"
export SPLUNK_SCHEME="${SPLUNK_SCHEME:-https}"

export CROWDSTRIKE_CLIENT_ID="${CROWDSTRIKE_CLIENT_ID:-your_client_id}"
export CROWDSTRIKE_CLIENT_SECRET="${CROWDSTRIKE_CLIENT_SECRET:-your_client_secret}"
export CROWDSTRIKE_BASE_URL="${CROWDSTRIKE_BASE_URL:-https://api.crowdstrike.com}"

export THEHIVE_URL="${THEHIVE_URL:-http://localhost:9000}"
export THEHIVE_API_KEY="${THEHIVE_API_KEY:-your_api_key}"
export THEHIVE_ORGANIZATION="${THEHIVE_ORGANIZATION:-your_organization}"

export DEBUG="${DEBUG:-false}"
export LOG_LEVEL="${LOG_LEVEL:-INFO}"
export POLL_INTERVAL="${POLL_INTERVAL:-30}"
export MAX_CONCURRENT_ALERTS="${MAX_CONCURRENT_ALERTS:-5}"
export AUTO_ISOLATION_THRESHOLD="${AUTO_ISOLATION_THRESHOLD:-8.0}"
export AUTO_SCANNING_THRESHOLD="${AUTO_SCANNING_THRESHOLD:-6.0}"
export AUTO_CASE_CREATION_THRESHOLD="${AUTO_CASE_CREATION_THRESHOLD:-5.0}"

print_status "Environment configured with default values"
print_warning "Update environment variables with your real credentials for production use!"

# Create necessary directories
print_header "Setting up directory structure..."
mkdir -p logs quarantine scanners/yara_rules
print_status "Directory structure created"

# Display configuration
print_header "Current Configuration:"
echo -e "${CYAN}Splunk SIEM:${NC} $SPLUNK_HOST:$SPLUNK_PORT"
echo -e "${CYAN}CrowdStrike EDR:${NC} $CROWDSTRIKE_BASE_URL"
echo -e "${CYAN}TheHive SOAR:${NC} $THEHIVE_URL"
echo -e "${CYAN}Poll Interval:${NC} $POLL_INTERVAL seconds"
echo -e "${CYAN}Auto-Isolation Threshold:${NC} $AUTO_ISOLATION_THRESHOLD"
echo -e "${CYAN}Max Concurrent Alerts:${NC} $MAX_CONCURRENT_ALERTS"
echo ""

# Ask for confirmation to start
print_header "Ready to start Cyber-SOC Auto-Responder!"
echo -e "${YELLOW}This will start the production system. Press Ctrl+C to stop.${NC}"
echo ""
read -p "Press ENTER to start the system, or Ctrl+C to cancel..."

# Start the production system
print_header "Starting Cyber-SOC Auto-Responder Production System..."
echo -e "${GREEN}System is now running...${NC}"
echo ""

# Run the working production system
exec $PYTHON_CMD working_production.py

# This line will only be reached if the Python script exits
print_status "Cyber-SOC Auto-Responder has stopped." 