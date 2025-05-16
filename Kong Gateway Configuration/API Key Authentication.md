## Kong Gateway Configuration: API Key Authentication

The following `curl` commands configure Kong Gateway to protect your API using API Key authentication. Ensure your Node.js API server is running and Kong Gateway is running.

**1. Register Your API as a Service in Kong**

This tells Kong where your Node.js API is running. We use `host.docker.internal` so Kong (running in Docker) can reach your Node.js server (running on your host machine).
   ```bash
   curl -i -X POST http://localhost:${kong_admin_port}/services --data name=${api_service_name} --data url='http://host.docker.internal:4000'
   ```
   *(Expected Output: HTTP/1.1 201 Created, and JSON details of the service)*

**2. Create a Route for the Service in Kong**

This defines how requests to Kong's proxy (`http://localhost:8000`) will be mapped to your service. We'll map requests from `/api` on Kong to the root of your service (which internally handles `/api/*`).
   ```bash
   curl -i -X POST http://localhost:${kong_admin_port}/services/${api_service_name}/routes --data 'paths[]=/api' --data name=${api_route_name} --data strip_path=false
   ```
   *(Expected Output: HTTP/1.1 201 Created, and JSON details of the route)*

**3. Enable the API Key Plugin (key-auth) on the Service**

This secures all routes under the `${api_service_name}` service with API key authentication.
   ```bash
   curl -i -X POST http://localhost:${kong_admin_port}/services/${api_service_name}/plugins --data name=key-auth --data config.key_names=apikey
   ```
   * `config.key_names=apikey`: Kong will look for the API key in a request header named `apikey`.
   *(Expected Output: HTTP/1.1 201 Created, and JSON details of the plugin)*

**4. Create a Consumer in Kong**

A consumer represents a client application or user that will access your API.
   ```bash
   curl -i -X POST http://localhost:${kong_admin_port}/consumers --data username=my-client-app
   ```
   *(Expected Output: HTTP/1.1 201 Created, and JSON details of the consumer. Note the `id` or `username`.)*

**5. Provision an API Key for the Consumer**

Replace `my-client-app` with the username (or `id`) of the consumer created above.
   ```bash
   curl -i -X POST http://localhost:${kong_admin_port}/consumers/my-client-app/key-auth --data key=${key}
   ```
   * `key`: This is your API key. Keep it secret! You can omit `--data key=...` and Kong will generate one for you.
   *(Expected Output: HTTP/1.1 201 Created, and JSON details of the API key.)*

---

## Testing API Key Authentication via Kong

Now, all requests to your API through Kong (`http://localhost:8000/api/*`) require the API key.

**1. Test the `/public` endpoint (should still be accessible if not explicitly secured differently, but now requires key due to plugin on service):**

   * **Without API Key (should fail with 401):**
   ```bash
     curl -i http://localhost:8000/api/public
   ```

   *(Expected Output: HTTP/1.1 401 Unauthorized, `{"message":"No API key found in request"}`)*

   * **With API Key (should succeed):**
   ```bash
     curl -i -H "apikey: ${key}" http://localhost:8000/api/public
   ```
   *(Expected Output: HTTP/1.1 200 OK, `{"message":"This is a public API response."}`)*

**2. Test the `/secure` endpoint:**

   * **Without API Key (should fail with 401):**
   ```bash
     curl -i http://localhost:8000/api/secure
   ```
   *(Expected Output: HTTP/1.1 401 Unauthorized, `{"message":"No API key found in request"}`)*

   * **With API Key (should succeed):**
   ```bash
     curl -i -H "apikey: supersecretkey12345" http://localhost:8000/api/secure
   ```
   *(Expected Output: HTTP/1.1 200 OK, JSON like `{"message":"Secure data access granted via Kong.","consumer":"my-client-app", ...}`)*

---