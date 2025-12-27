#!/usr/bin/env python3
"""
AROI Validator Setup Script - Installs dependencies and configures the project
"""

import os
import subprocess
import sys
from pathlib import Path

def create_streamlit_config():
    """Create Streamlit configuration with 1AEO branding"""
    config_dir = Path(".streamlit")
    config_dir.mkdir(exist_ok=True)
    
    config_content = """[server]
headless = true
address = "0.0.0.0"
port = 5000

[theme]
primaryColor = "#00ff7f"
backgroundColor = "#121212"
secondaryBackgroundColor = "#1e1e1e"
textColor = "#ffffff"
font = "sans serif"
"""
    
    config_file = config_dir / "config.toml"
    with open(config_file, "w") as f:
        f.write(config_content)
    
    print("✓ Created Streamlit configuration with 1AEO theme")

def install_dependencies():
    """Install required Python packages"""
    dependencies = [
        "streamlit",
        "dnspython", 
        "pandas",
        "requests",
        "urllib3"
    ]
    
    print("Installing dependencies...")
    try:
        # Try uv (Replit's package manager)
        subprocess.run(["uv", "add"] + dependencies, check=True, capture_output=True)
        print("✓ Installed dependencies")
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback to pip
        subprocess.run([sys.executable, "-m", "pip", "install"] + dependencies, check=True)
        print("✓ Installed dependencies")

def main():
    """Main setup function"""
    print("Setting up AROI Validator...")
    
    # Install dependencies
    try:
        install_dependencies()
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        sys.exit(1)
    
    # Create configuration
    create_streamlit_config()
    
    print("\n✅ Setup complete! Run with: streamlit run app.py --server.port 5000")

if __name__ == "__main__":
    main()