#!/bin/bash

# Installation script for MCP Web Reconnaissance tools (Linux/macOS)

echo "MCP Web Reconnaissance - Tools Installer"
echo "========================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install UV
install_uv() {
    print_info "Checking for UV..."
    
    if command_exists uv; then
        UV_VERSION=$(uv --version 2>/dev/null)
        print_status "UV is already installed: $UV_VERSION"
    else
        print_info "Installing UV..."
        curl -LsSf https://astral.sh/uv/install.sh | sh
        
        # Add to PATH for current session
        export PATH="$HOME/.local/bin:$PATH"
        
        if command_exists uv; then
            UV_VERSION=$(uv --version 2>/dev/null)
            print_status "UV installed successfully: $UV_VERSION"
        else
            print_error "UV installation failed"
            return 1
        fi
    fi
}

# Install Nmap
install_nmap() {
    print_info "Checking for Nmap..."
    
    if command_exists nmap; then
        NMAP_VERSION=$(nmap --version 2>/dev/null | head -n1)
        print_status "Nmap is already installed: $NMAP_VERSION"
        return 0
    fi
    
    print_info "Installing Nmap..."
    
    # Detect OS and install accordingly
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command_exists apt-get; then
            # Debian/Ubuntu
            sudo apt-get update && sudo apt-get install -y nmap
        elif command_exists yum; then
            # RHEL/CentOS
            sudo yum install -y nmap
        elif command_exists dnf; then
            # Fedora
            sudo dnf install -y nmap
        elif command_exists pacman; then
            # Arch Linux
            sudo pacman -S --noconfirm nmap
        else
            print_error "Unsupported Linux distribution. Please install nmap manually."
            return 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command_exists brew; then
            brew install nmap
        else
            print_error "Homebrew not found. Please install Homebrew first or install nmap manually."
            return 1
        fi
    else
        print_error "Unsupported operating system. Please install nmap manually."
        return 1
    fi
    
    # Verify installation
    if command_exists nmap; then
        NMAP_VERSION=$(nmap --version 2>/dev/null | head -n1)
        print_status "Nmap installed successfully: $NMAP_VERSION"
    else
        print_error "Nmap installation failed"
        return 1
    fi
}

# Main installation function
main() {
    echo "This script will install:"
    echo "- UV (Python package manager)"
    echo "- Nmap (network mapping tool)"
    echo "- Python dependencies for web reconnaissance"
    echo ""
    echo "Requirements:"
    echo "- Python 3.10 or higher"
    echo ""
    
    read -p "Do you want to continue? (y/n): " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi
    
    # Install UV
    install_uv || exit 1
    
    # Install Nmap
    install_nmap || exit 1
    
    # Install Python dependencies
    print_info "Installing Python dependencies with UV..."
    if uv sync; then
        print_status "Python dependencies installed"
    else
        print_error "Failed to install Python dependencies"
        print_warning "Try running: uv sync"
        exit 1
    fi
    
    # Verify installations
    print_info "Verifying installations..."
    
    TOOLS=("uv" "nmap")
    
    for tool in "${TOOLS[@]}"; do
        if command_exists "$tool"; then
            print_status "$tool is available"
        else
            print_error "$tool not found in PATH"
        fi
    done
    
    echo ""
    print_status "Installation complete!"
    echo ""
    print_info "Python dependencies installed include:"
    echo "- httpx (HTTP client)"
    echo "- beautifulsoup4 (HTML parsing)"
    echo "- dnspython (DNS resolution)"
    echo "- python-nmap (Nmap interface)"
    echo "- python-whois (WHOIS lookup)"
    echo ""
}

# Run main function
main
