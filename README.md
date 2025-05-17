# API Security with Kong

This project demonstrates essential API security concepts using **Express** and **Kong Gateway**. It provides a hands-on exploration of modern API protection techniques, helping you understand and visualize secure API flows.

---

## Features Implemented

| Feature                        | Description                                                    | Status      |
|---------------------------------|----------------------------------------------------------------|-------------|
| **CORS Configuration**          | Restricts API access to trusted origins for enhanced security.  | Complete |
| **API Key Authentication**      | Secures endpoints by requiring valid API keys.                  | Compele |
| **JWT Authentication**          | Implements session management using JSON Web Tokens.            |  |
| **Rate Limiting**               | Protects APIs from abuse by limiting request rates.             |  |
| **Input Validation & Sanitization** | Ensures incoming data is safe and well-formed.             |  |
| **API Activity Logging**        | Monitors and analyzes API usage for better observability.       |  |

---

## Getting Started

1.  **Prerequisites:**
    *   Node.js and npm installed.
    *   Docker and Docker Compose installed.
    *   Kong Gateway running (e.g., via the provided `docker-compose.yml` or your own setup). Ensure Kong Admin API is accessible (typically `http://localhost:8001`).

2.  **Clone the repository:**
    ```bash
    git clone <https://github.com/Neit272/API-Security-with-API-Gateway-Management.git>
    cd API-Security-with-API-Gateway-Management
    ```

3.  **Install dependencies for the Node.js server:**
    ```bash
    npm install
    ```

4.  **Configure environment variables for the Node.js server:**
    Copy `.env.example` to `.env`. The default `server_local_port=4000` should work with the Kong setup below.
    ```bash
    cp .env.example .env
    ```

5.  **Start the Node.js API server:**
    ```bash
    npm start
    ```
    Or, for development with hot reload:
    ```bash
    npm run dev
    ```
    Your API server should now be running on `http://localhost:4000`.

---
