#!/bin/bash

# Setup script for log analyzer tool

echo "Setting up Log Analyzer Tool..."

# Backend setup
echo "Setting up backend..."
cd backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Copy environment file
cp .env.example .env

echo "Backend setup complete!"

cd ..

# Frontend setup
echo "Setting up frontend..."
cd frontend

# Install dependencies
npm install

# Copy environment file
cp .env.example .env

echo "Frontend setup complete!"

cd ..

# Create necessary directories
mkdir -p data/duckdb
mkdir -p data/archives
mkdir -p logs
mkdir -p updates

echo "Setup complete!"
echo ""
echo "To start the backend:"
echo "  cd backend"
echo "  source venv/bin/activate"
echo "  uvicorn api.main:app --reload"
echo ""
echo "To start the frontend:"
echo "  cd frontend"
echo "  npm run dev"
