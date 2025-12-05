#!/bin/bash
set -e

echo "=========================================="
echo "  RED TEAM AI AGENT - ENVIRONMENT SETUP  "
echo "=========================================="

cd ~/redteam-ai-agent

# Create virtual environment
echo ""
echo "Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
echo ""
echo "Upgrading pip..."
pip install --upgrade pip wheel setuptools

# Install PyTorch with CUDA 12.1
echo ""
echo "Installing PyTorch with CUDA support..."
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121

# Verify CUDA
echo ""
echo "Verifying PyTorch CUDA..."
python3 -c "import torch; print(torch.__version__); print(torch.cuda.is_available())"

# Install other dependencies
echo ""
echo "Installing ML dependencies..."
pip install transformers datasets accelerate peft bitsandbytes trl sentencepiece protobuf

# Install Unsloth
echo ""
echo "Installing Unsloth for faster training..."
pip install "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"

# Install serving dependencies
echo ""
echo "Installing serving dependencies..."
pip install fastapi uvicorn rich pyyaml typer huggingface_hub

echo ""
echo "=========================================="
echo "         INSTALLATION COMPLETE           "
echo "=========================================="
