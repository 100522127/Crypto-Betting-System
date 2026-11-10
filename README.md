# Crypto-Betting-System

## Overview
This repository contains a Python-based secure betting system that implements core cryptographic principles. It demonstrates the practical application of symmetric and asymmetric encryption, digital signatures, user authentication, and Certificate Authority (CA) infrastructure.

## Features
*   **User Authentication (`autenticacion_de_usuario.py`):** Secure login and identity verification.
*   **Symmetric Encryption (`cifrado_simetrico.py`):** Fast, secure data encryption for standard communications.
*   **Asymmetric Encryption (`cifrado_asimetrico.py`):** Public/private key pair cryptography for secure key exchange.
*   **Digital Signatures (`firma_certificados.py` & `CA/`):** Certificate Authority integration to sign and verify identities and transactions.
*   **Betting Manager (`gestor_de_apuestas.py`):** Core application logic handling the betting operations securely.

## Getting Started

### Prerequisites
*   Python 3.x
*   Required cryptographic libraries (e.g., `cryptography` or `pycryptodome`, depending on implementation).

### Running the Project
1. Clone the repository.
2. Run the main application entry point:
   ```bash
   python main.py
