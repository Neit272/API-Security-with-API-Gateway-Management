# API Security with Kong

This project demonstrates essential API security concepts using **Express** and **Kong Gateway**. It provides a hands-on exploration of modern API protection techniques, helping you understand and visualize secure API flows.

---

## Features Implemented

| Feature                        | Description                                                    | Status      |
|---------------------------------|----------------------------------------------------------------|-------------|
| **CORS Configuration**          | Restricts API access to trusted origins for enhanced security.  |  |
| **API Key Authentication**      | Secures endpoints by requiring valid API keys.                  |  |
| **JWT Authentication**          | Implements session management using JSON Web Tokens.            |  |
| **Rate Limiting**               | Protects APIs from abuse by limiting request rates.             |  |
| **Input Validation & Sanitization** | Ensures incoming data is safe and well-formed.             |  |
| **API Activity Logging**        | Monitors and analyzes API usage for better observability.       |  |

---

## Getting Started

1. **Install dependencies**
    ```
    npm install
    ```

2. **Configure environment variables**

    Copy `.env.example` to `.env` and update as needed.

3. **Start the server**
    ```
    npm start
    ```
    Or, for development with hot reload:
    ```
    npm run dev
    ```
