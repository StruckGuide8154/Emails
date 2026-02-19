# Secure Email Manager

A privacy-focused, quantum-resistant(AES-256-GCM) Email Manager built with Flask and Redis.

## Features
- **Secure Login**: Direct IMAP authentication with Google App Passwords.
- **Glassmorphism UI**: Premium dark mode design.
- **Encrypted Session**: Credentials are encrypted using AES-256-GCM before storage in Redis.
- **Redis Integration**: Fully compatible with Railway Redis via `REDIS_URL`.

## Setup

1.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

2.  **Configure Environment**:
    - The app uses a `.env` file for configuration.
    - If using a remote Redis (e.g., Railway), update `REDIS_URL` in `.env`.
    - Example `.env`:
        ```env
        REDIS_URL=redis://:password@host:port
        SECRET_KEY=your-secure-secret-key
        ENCRYPTION_KEY=hex-encoded-256-bit-key-optional
        ```

3.  **Run the Server**:
    ```bash
    python app.py
    ```
    The app runs on `http://0.0.0.0:80` by default.

## Usage
1.  Open [http://localhost](http://localhost) in your browser.
2.  Enter your **Gmail Address**.
3.  Enter your **Google App Password** (Not your main password).
    - To generate one: Go to Google Account > Security > 2-Step Verification > App passwords.

## Security Note for "Quantum Safe"
While true Post-Quantum Cryptography requires specialized algorithms (like Kyber), this application uses **AES-256-GCM**, which is currently considered resistant to quantum computing attacks (specifically Grover's algorithm) due to its 256-bit key size.
