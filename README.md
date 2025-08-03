# KeySplit - Distributed Cryptographic Key Sharing

## Project Overview

KeySplit is a proof-of-concept system designed to enhance authentication security in high-risk transactions by implementing a distributed cryptographic mechanism using Shamir’s Secret Sharing (SSS). Instead of storing the full cryptographic key in a single location, the key is split into multiple parts and distributed across trusted entities. The original key is reconstructed only when a threshold number of valid shares are retrieved.

This approach eliminates single points of failure and protects against attacks such as phishing, SIM-swapping, and man-in-the-middle exploits.

## Features

- Secret sharing and reconstruction using Shamir's Secret Sharing algorithm
- Distributed key storage across trusted entities
- Threshold-based key reconstruction
- Encrypted communication between components
- Transaction authorization using reconstructed keys

## How It Works

1. The system divides a cryptographic key into multiple shares.
2. Each share is securely stored with a different trusted source (e.g., local device, cloud, hardware token).
3. When a user initiates a sensitive operation, the system:
   - Authenticates the user
   - Requests a threshold number of valid key shares
   - Reconstructs the key
   - Authorizes the transaction using the reconstructed key

At no point is the full key stored or exposed in one place.

## Technologies Used

- Python
- Cryptography libraries (e.g., `cryptography`, `pycryptodome`)
- JSON for configuration and communication
- Command-line interface for testing and demonstration


## Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/sasi-1902/KeySplit-Crypto.git
   cd KeySplit-Crypto

2. Install dependencies:

   ```bash
   pip install -r requirements.txt

3. Run the main program:

   ```bash
   python main.py

# Future Improvements
Build a web interface for visualization and usage

Add support for secure cloud-based share storage

Integrate with blockchain smart contracts for audit logging

Extend the tool for multi-party authorization workflows

