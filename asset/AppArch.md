```mermaid
flowchart TD
    style A fill:#9CE8C6,stroke:#218F5D,stroke-width:2px
    style B fill:#ccf2ff,stroke:#0066cc,stroke-width:2px
    style C fill:#ddffdd,stroke:#33cc33,stroke-width:2px

    A[Client/User: App, API Client]

    %% Kong Gateway Layer (Data Plane)
    B[Kong Gateway: Data Plane & Policy Enforcement]
    Bsub1[CORS, JWT, Key Auth, Rate Limiting Plugin]
    Bsub2[Routing: Proxy to Express API Server]

    %% Express API Server Layer
    subgraph ServerLayer [Private Backend Server]
        direction TB
        C[Express API Service: App Logic & API Routing]
        D[SQLite Database: users, refresh_tokens, logs]
    end

    %% Data Store


    %% Kong Admin API & DB (Control Plane)
    E[Kong Admin API: Control Plane]
    F[Kong Database: PostgreSQL]
    G[Splunk: Dashboard, Alert]

    %% Connections: Client to Kong Gateway
    A --> B

    %% Kong Gateway Plugins
    B --> Bsub1
    Bsub1 --> Bsub2

    %% Routing to Express API Server
    Bsub2 --> ServerLayer

    %% Database Interactions
    C --> D

    %% Control Plane: API Server Configures Kong via Admin API
    C -.-> E

    %% Kong Admin API Writes Config to Kong Database
    E -.-> F

    %% Kong Gateway Reads Config from Kong Database
    F -.-> B

    D -.-> G
```
**Chú thích:**
- **Data Plane** (luồng dữ liệu runtime): Client → Kong Gateway (áp dụng policy, xác thực, routing) → Express API Server (thực thi nghiệp vụ, lưu dữ liệu) → SQLite → trả kết quả về cho Client.
- **Control Plane** (quản trị cấu hình): Express API Server tự động gọi Kong Admin API để tạo consumer, cấp JWT credential, cấp API Key...; Kong Admin API ghi cấu hình vào Kong Database (Postgres); Kong Gateway đọc cấu hình này để enforce policy.
- **Các plugin bảo mật** được gắn tại Kong Gateway (CORS, JWT, Key Auth, Rate Limiting).
- **Routing** của Express phân chia rõ các nghiệp vụ (public, jwt, key, auth).

---
