// Global variables
let currentJWT = null;
let currentApiKey = null;
let oldApiKey = null;
let spamRequestCount = 0;

// Base URLs
const KONG_BASE_URL = "http://localhost:8000";
const API_BASE_URL = "http://localhost:4000";

// Initialize
document.addEventListener("DOMContentLoaded", function () {
  checkSystemStatus();
  logActivity("System initialized. Ready for testing.", "success");

  // Setup event listeners
  setupEventListeners();
});

// Logging function với emoji và clean format
function logActivity(message, type = "info") {
  const console = document.getElementById("log-console");
  const timestamp = new Date().toLocaleTimeString();
  const logEntry = document.createElement("div");
  logEntry.className = `log-entry ${type}`;
  logEntry.innerHTML = `<strong>[${timestamp}]</strong></br>${message}`;

  console.appendChild(logEntry);
  console.scrollTop = console.scrollHeight;
}

function clearLogs() {
  document.getElementById("log-console").innerHTML = "";
  logActivity("Logs cleared.", "info");
}

// System status check
async function checkSystemStatus() {
  try {
    // Check Kong Gateway
    const kongResponse = await fetch(`${KONG_BASE_URL}/api/public/info`);
    if (kongResponse.ok) {
      document.getElementById("kong-status").className =
        "status-indicator status-online";
      document.getElementById("kong-text").textContent = "Online";
      logActivity("Kong Gateway is online", "success");
    } else {
      throw new Error("Kong not responding");
    }
  } catch (error) {
    document.getElementById("kong-status").className =
      "status-indicator status-offline";
    document.getElementById("kong-text").textContent = "Offline";
    logActivity("Kong Gateway is offline", "error");
  }

  try {
    // Check API Server
    const apiResponse = await fetch(`${API_BASE_URL}/api/public/info`);
    if (apiResponse.ok) {
      document.getElementById("api-status").className =
        "status-indicator status-online";
      document.getElementById("api-text").textContent = "Online";
      logActivity("API Server is online", "success");
    } else {
      throw new Error("API not responding");
    }
  } catch (error) {
    document.getElementById("api-status").className =
      "status-indicator status-offline";
    document.getElementById("api-text").textContent = "Offline";
    logActivity("API Server is offline", "error");
  }
}

// Zone 1: Injection Tests
function setMaliciousInput(username, password) {
  document.getElementById("test-username").value = username;
  document.getElementById("test-password").value = password;
  logActivity(`Malicious input set: ${username}`, "warning");
}

async function testNormalSignup() {
  const username =
    document.getElementById("test-username").value || "testuser" + Date.now();
  const password =
    document.getElementById("test-password").value || "SecurePass123";

  logActivity(`Testing normal signup with username: ${username}`, "info");

  try {
    const response = await fetch(`${KONG_BASE_URL}/api/public/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    if (!response.ok) {
      const contentType = response.headers.get("content-type");
      if (contentType && contentType.includes("application/json")) {
        const result = await response.json();
        showResult(
          "injection-result",
          `Signup failed: ${result.error || result.message}`,
          "danger"
        );
        logActivity(
          `Normal signup failed: ${result.error || result.message}`,
          "error"
        );
      } else {
        showResult(
          "injection-result",
          `Server error: HTTP ${response.status}`,
          "danger"
        );
        logActivity(`Normal signup server error: ${response.status}`, "error");
      }
      return;
    }

    const result = await response.json();
    showResult(
      "injection-result",
      "Signup successful! Validation passed.",
      "success"
    );
    logActivity(`Normal signup successful for ${username}`, "success");
  } catch (error) {
    if (
      error.name === "SyntaxError" &&
      error.message.includes("Unexpected token '<'")
    ) {
      showResult(
        "injection-result",
        `Server returned HTML instead of JSON`,
        "danger"
      );
      logActivity(`JSON Parse Error: Server returned HTML`, "error");
    } else {
      showResult("injection-result", `Error: ${error.message}`, "danger");
      logActivity(`Normal signup error: ${error.message}`, "error");
    }
  }
}

async function testMaliciousSignup() {
  const username = document.getElementById("test-username").value;
  const password = document.getElementById("test-password").value;

  if (!username || !password) {
    showResult(
      "injection-result",
      "Please enter username and password first!",
      "warning"
    );
    return;
  }

  logActivity(`Testing malicious signup with: ${username}`, "warning");

  try {
    const response = await fetch(`${KONG_BASE_URL}/api/public/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    if (response.ok) {
      showResult(
        "injection-result",
        "UNEXPECTED: Malicious input was accepted!",
        "danger"
      );
      logActivity(`SECURITY ISSUE: Malicious input accepted!`, "error");
    } else {
      const contentType = response.headers.get("content-type");
      if (contentType && contentType.includes("application/json")) {
        const result = await response.json();
        showResult(
          "injection-result",
          `BLOCKED: ${
            result.error || result.errors?.[0]?.msg || result.message
          }`,
          "success"
        );
        logActivity(`Malicious input blocked successfully`, "success");
      } else {
        showResult(
          "injection-result",
          `BLOCKED: Request rejected by validation`,
          "success"
        );
        logActivity(`Malicious input blocked at server level`, "success");
      }
    }
  } catch (error) {
    showResult(
      "injection-result",
      `BLOCKED: Request rejected by validation`,
      "success"
    );
    logActivity(`Malicious input blocked at network level`, "success");
  }
}

// Zone 2: Key Management - Cải thiện với proper error handling
async function getApiKey() {
  const username = document.getElementById("key-username").value;
  const password = document.getElementById("key-password").value;

  if (!username || !password) {
    showResult("key-result", "Please enter username and password!", "warning");
    return;
  }

  logActivity(`Getting API key for ${username}`, "info");

  try {
    const credentials = btoa(`${username}:${password}`);

    const response = await fetch(`${KONG_BASE_URL}/api/auth/getApiKey`, {
      method: "GET",
      headers: {
        Authorization: `Basic ${credentials}`,
        "Content-Type": "application/json",
      },
    });

    console.log(`API Key Response Status: ${response.status}`);

    if (!response.ok) {
      const contentType = response.headers.get("content-type");
      if (contentType && contentType.includes("application/json")) {
        const errorResult = await response.json();
        showResult(
          "key-result",
          `Failed to get API key: ${errorResult.error || errorResult.message}`,
          "danger"
        );
        logActivity(
          `API key error: ${errorResult.error || errorResult.message}`,
          "error"
        );
      } else {
        showResult(
          "key-result",
          `Server error: HTTP ${response.status}`,
          "danger"
        );
        logActivity(`API key server error: ${response.status}`, "error");
      }
      return;
    }

    const result = await response.json();
    console.log("API Key Result:", result);

    const apiKey = result.apiKey || result.api_key || result.key;

    if (apiKey) {
      oldApiKey = currentApiKey;
      currentApiKey = apiKey;

      // Hiển thị full key ở Control Panel
      document.getElementById("api-key-display").textContent = currentApiKey;

      // Hiển thị key rút gọn trong zone result
      showResult(
        "key-result",
        `API Key obtained: ${truncateApiKey(currentApiKey)}`,
        "success"
      );
      logActivity(`API key obtained successfully for ${username}`, "success");
    } else {
      console.error("Unexpected response structure:", result);
      showResult("key-result", `Failed: No API key in response`, "danger");
      logActivity(`No API key found in response`, "error");
    }
  } catch (error) {
    console.error("API Key Fetch Error:", error);

    if (
      error.name === "SyntaxError" &&
      error.message.includes("Unexpected token '<'")
    ) {
      showResult(
        "key-result",
        `Server returned HTML instead of JSON`,
        "danger"
      );
      logActivity(`JSON Parse Error: Server returned HTML`, "error");
    } else if (
      error.name === "TypeError" &&
      error.message.includes("Failed to fetch")
    ) {
      showResult(
        "key-result",
        `Network error: Cannot reach Kong Gateway`,
        "danger"
      );
      logActivity(`Network error: Kong Gateway unreachable`, "error");
    } else {
      showResult("key-result", `Error: ${error.message}`, "danger");
      logActivity(`API key request error: ${error.message}`, "error");
    }
  }
}

// Alternative JWT-based API Key method
async function loginForApiKey() {
  const username = document.getElementById("key-username").value;
  const password = document.getElementById("key-password").value;

  if (!username || !password) {
    showResult("key-result", "Please enter username and password!", "warning");
    return;
  }

  logActivity(`JWT Login to get API key for ${username}`, "info");

  try {
    // Step 1: Login để lấy JWT
    const loginResponse = await fetch(`${KONG_BASE_URL}/api/public/signin`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    console.log(`Login Response Status: ${loginResponse.status}`);

    if (!loginResponse.ok) {
      const contentType = loginResponse.headers.get("content-type");
      if (contentType && contentType.includes("application/json")) {
        const loginError = await loginResponse.json();
        showResult(
          "key-result",
          `Login failed: ${loginError.error || loginError.message}`,
          "danger"
        );
        logActivity(
          `Login failed: ${loginError.error || loginError.message}`,
          "error"
        );
      } else {
        showResult(
          "key-result",
          `Login failed: Server error ${loginResponse.status}`,
          "danger"
        );
        logActivity(`Login server error: ${loginResponse.status}`, "error");
      }
      return;
    }

    const loginResult = await loginResponse.json();
    console.log("Login Result:", loginResult);

    if (!loginResult.access_token) {
      showResult(
        "key-result",
        `Login failed: No access token received`,
        "danger"
      );
      logActivity(`No access token in login response`, "error");
      return;
    }

    logActivity(`Login successful, requesting API key...`, "info");

    // Step 2: Dùng JWT để lấy API key
    const apiKeyResponse = await fetch(`${KONG_BASE_URL}/api/auth/getApiKey`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${loginResult.access_token}`,
        "Content-Type": "application/json",
      },
    });

    console.log(`API Key (JWT) Response Status: ${apiKeyResponse.status}`);

    if (!apiKeyResponse.ok) {
      const contentType = apiKeyResponse.headers.get("content-type");
      if (contentType && contentType.includes("application/json")) {
        const apiKeyError = await apiKeyResponse.json();
        showResult(
          "key-result",
          `Failed to get API key: ${apiKeyError.error || apiKeyError.message}`,
          "danger"
        );
        logActivity(
          `API key error: ${apiKeyError.error || apiKeyError.message}`,
          "error"
        );
      } else {
        showResult(
          "key-result",
          `API key failed: Server error ${apiKeyResponse.status}`,
          "danger"
        );
        logActivity(`API key server error: ${apiKeyResponse.status}`, "error");
      }
      return;
    }

    const apiKeyResult = await apiKeyResponse.json();
    console.log("API Key (JWT) Result:", apiKeyResult);

    // Kiểm tra structure response
    if (apiKeyResult.apiKey || apiKeyResult.api_key || apiKeyResult.key) {
      oldApiKey = currentApiKey;
      currentApiKey =
        apiKeyResult.apiKey || apiKeyResult.api_key || apiKeyResult.key;

      // Hiển thị full key ở Control Panel
      document.getElementById("api-key-display").textContent = currentApiKey;

      // Hiển thị key rút gọn trong zone result
      showResult(
        "key-result",
        `API Key obtained via JWT: ${truncateApiKey(currentApiKey)}`,
        "success"
      );
      logActivity(
        `API key obtained successfully via JWT for ${username}`,
        "success"
      );
    }
  } catch (error) {
    console.error("JWT API Key Error:", error);

    if (
      error.name === "SyntaxError" &&
      error.message.includes("Unexpected token '<'")
    ) {
      showResult(
        "key-result",
        `Server returned HTML instead of JSON`,
        "danger"
      );
      logActivity(`JSON Parse Error: Server returned HTML`, "error");
    } else if (
      error.name === "TypeError" &&
      error.message.includes("Failed to fetch")
    ) {
      showResult(
        "key-result",
        `Network error: Cannot reach Kong Gateway`,
        "danger"
      );
      logActivity(`Network error: Kong Gateway unreachable`, "error");
    } else {
      showResult("key-result", `Error: ${error.message}`, "danger");
      logActivity(`JWT API key request error: ${error.message}`, "error");
    }
  }
}

async function rotateApiKey() {
  if (!currentApiKey) {
    showResult("key-result", "Please get an API key first!", "warning");
    return;
  }

  const username = document.getElementById("key-username").value;
  const password = document.getElementById("key-password").value;

  logActivity(`Rotating API key for ${username}`, "info");

  oldApiKey = currentApiKey;
  await getApiKey();

  if (currentApiKey !== oldApiKey) {
    // Hiển thị cả old và new key đều rút gọn trong zone result
    showResult(
      "key-result",
      `Key rotated!\n• Old: ${truncateApiKey(
        oldApiKey
      )}\n• New: ${truncateApiKey(currentApiKey)}`,
      "success"
    );
    logActivity(
      `API key rotated successfully. Old key should now be invalid.`,
      "success"
    );
  }
}

async function testCurrentKey() {
  if (!currentApiKey) {
    showResult("key-result", "No current API key available!", "warning");
    return;
  }

  logActivity(`Testing current API key`, "info");

  try {
    const response = await fetch(`${KONG_BASE_URL}/api/key/info`, {
      method: "GET",
      headers: { apikey: currentApiKey },
    });

    console.log(`Current Key Test Status: ${response.status}`);

    if (!response.ok) {
      const contentType = response.headers.get("content-type");
      if (contentType && contentType.includes("application/json")) {
        const result = await response.json();
        showResult(
          "key-result",
          `Current key INVALID: ${result.message}`,
          "danger"
        );
        logActivity(`Current API key is invalid`, "error");
      } else {
        showResult(
          "key-result",
          `Current key test failed: HTTP ${response.status}`,
          "danger"
        );
        logActivity(
          `Current key test server error: ${response.status}`,
          "error"
        );
      }
      return;
    }

    const result = await response.json();
    showResult("key-result", `Current key VALID`, "success");
    logActivity(`Current API key is valid`, "success");
  } catch (error) {
    showResult(
      "key-result",
      `Error testing current key: ${error.message}`,
      "danger"
    );
    logActivity(`Error testing current key`, "error");
  }
}

async function testOldKey() {
  if (!oldApiKey) {
    showResult(
      "key-result",
      "No old API key available! Rotate a key first.",
      "warning"
    );
    return;
  }

  logActivity(`Testing old API key`, "info");

  try {
    const response = await fetch(`${KONG_BASE_URL}/api/key/info`, {
      method: "GET",
      headers: { apikey: oldApiKey },
    });

    console.log(`Old Key Test Status: ${response.status}`);

    if (response.ok) {
      showResult(
        "key-result",
        `SECURITY ISSUE: Old key still VALID!`,
        "danger"
      );
      logActivity(`SECURITY ISSUE: Old API key is still valid!`, "error");
    } else {
      showResult("key-result", `Old key INVALID (as expected)`, "success");
      logActivity(`Old API key correctly invalidated`, "success");
    }
  } catch (error) {
    showResult(
      "key-result",
      `Error testing old key: ${error.message}`,
      "danger"
    );
    logActivity(`Error testing old key`, "error");
  }
}

// Zone 3: Auth Inconsistency
async function testPublicEndpoint() {
  logActivity("Testing public endpoint", "info");

  try {
    const response = await fetch(`${KONG_BASE_URL}/api/public/info`);

    if (!response.ok) {
      const contentType = response.headers.get("content-type");
      if (contentType && contentType.includes("application/json")) {
        const result = await response.json();
        showResult(
          "auth-result",
          `PUBLIC endpoint failed: ${result.message}`,
          "danger"
        );
        logActivity(`Public endpoint failed`, "error");
      } else {
        showResult(
          "auth-result",
          `PUBLIC endpoint failed: HTTP ${response.status}`,
          "danger"
        );
        logActivity(
          `Public endpoint server error: ${response.status}`,
          "error"
        );
      }
      return;
    }

    const result = await response.json();
    showResult(
      "auth-result",
      `PUBLIC endpoint accessible: ${result.message}`,
      "success"
    );
    logActivity("Public endpoint accessed successfully", "success");
  } catch (error) {
    showResult("auth-result", `Error: ${error.message}`, "danger");
    logActivity(`Public endpoint error`, "error");
  }
}

async function testKeyEndpoint() {
  logActivity("Testing API key endpoint", "info");

  try {
    const headers = {};
    if (currentApiKey) {
      headers["apikey"] = currentApiKey;
    }

    const response = await fetch(`${KONG_BASE_URL}/api/key/info`, {
      method: "GET",
      headers: headers,
    });

    if (response.ok) {
      showResult("auth-result", `API KEY endpoint accessible`, "success");
      logActivity("API key endpoint accessed successfully", "success");
    } else {
      const contentType = response.headers.get("content-type");
      if (contentType && contentType.includes("application/json")) {
        const result = await response.json();
        showResult(
          "auth-result",
          `API KEY endpoint blocked: ${
            result.message || "No API key provided"
          }`,
          "warning"
        );
        logActivity(`API key endpoint blocked`, "warning");
      } else {
        showResult(
          "auth-result",
          `API KEY endpoint blocked: HTTP ${response.status}`,
          "warning"
        );
        logActivity(`API key endpoint blocked`, "warning");
      }
    }
  } catch (error) {
    showResult(
      "auth-result",
      `API KEY endpoint blocked: ${error.message}`,
      "warning"
    );
    logActivity(`API key endpoint blocked`, "warning");
  }
}

async function testJwtEndpoint() {
  logActivity("🎫 Testing JWT endpoint", "info");

  try {
    const headers = {};
    if (currentJWT) {
      headers["Authorization"] = `Bearer ${currentJWT}`;
    }

    const response = await fetch(`${KONG_BASE_URL}/api/jwt/info`, {
      method: "GET",
      headers: headers,
    });

    if (response.ok) {
      showResult("auth-result", `JWT endpoint accessible`, "success");
      logActivity("JWT endpoint accessed successfully", "success");
    } else {
      const contentType = response.headers.get("content-type");
      if (contentType && contentType.includes("application/json")) {
        const result = await response.json();
        showResult(
          "auth-result",
          `JWT endpoint blocked: ${result.message || "No JWT token provided"}`,
          "warning"
        );
        logActivity(`JWT endpoint blocked`, "warning");
      } else {
        showResult(
          "auth-result",
          `JWT endpoint blocked: HTTP ${response.status}`,
          "warning"
        );
        logActivity(`JWT endpoint blocked`, "warning");
      }
    }
  } catch (error) {
    showResult(
      "auth-result",
      `JWT endpoint blocked: ${error.message}`,
      "warning"
    );
    logActivity(`JWT endpoint blocked`, "warning");
  }
}

async function quickJwtLogin() {
  const username = document.getElementById("jwt-username").value;
  const password = document.getElementById("jwt-password").value;

  if (!username || !password) {
    showResult("auth-result", "Please enter username and password!", "warning");
    return;
  }

  logActivity(`Quick JWT login for ${username}`, "info");

  try {
    const response = await fetch(`${KONG_BASE_URL}/api/public/signin`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    if (!response.ok) {
      const contentType = response.headers.get("content-type");
      if (contentType && contentType.includes("application/json")) {
        const result = await response.json();
        showResult(
          "auth-result",
          `JWT login failed: ${result.error || result.message}`,
          "danger"
        );
        logActivity(`JWT login failed for ${username}`, "error");
      } else {
        showResult(
          "auth-result",
          `JWT login failed: HTTP ${response.status}`,
          "danger"
        );
        logActivity(`JWT login server error: ${response.status}`, "error");
      }
      return;
    }

    const result = await response.json();

    if (result.access_token) {
      currentJWT = result.access_token;

      // Hiển thị JWT FULL ở Control Panel (không truncate)
      document.getElementById("jwt-token-display").textContent = currentJWT;

      // Hiển thị JWT rút gọn trong zone result
      showResult(
        "auth-result",
        `JWT obtained: ${truncateJWT(currentJWT)}`,
        "success"
      );
      logActivity(`JWT login successful for ${username}`, "success");
    }
  } catch (error) {
    showResult("auth-result", `Error: ${error.message}`, "danger");
    logActivity(`JWT login error for ${username}`, "error");
  }
}

// Zone 4: Rate Limiting
async function spamRequests() {
  const count = parseInt(document.getElementById("spam-count").value);
  const progressBar = document.getElementById("spam-progress");

  showResult("rate-limit-result", "", "");
  logActivity(`Starting spam test with ${count} requests`, "warning");

  let successCount = 0;
  let rateLimitedCount = 0;
  let errorCount = 0;

  for (let i = 0; i < count; i++) {
    const progress = ((i + 1) / count) * 100;
    progressBar.style.width = `${progress}%`;

    try {
      const headers = {};
      if (currentJWT) {
        headers["Authorization"] = `Bearer ${currentJWT}`;
      }

      const response = await fetch(`${KONG_BASE_URL}/api/jwt/info`, {
        method: "GET",
        headers: headers,
      });

      if (response.status === 429) {
        rateLimitedCount++;
        if (i % 10 === 0) {
          // Log mỗi 10 requests để tránh spam log
          logActivity(`Request ${i + 1}: Rate limited (429)`, "warning");
        }
      } else if (response.ok) {
        successCount++;
        if (i < 5) {
          // Chỉ log 5 request đầu tiên
          logActivity(`Request ${i + 1}: Success (200)`, "success");
        }
      } else {
        errorCount++;
        logActivity(`Request ${i + 1}: Error (${response.status})`, "error");
      }
    } catch (error) {
      errorCount++;
      logActivity(`Request ${i + 1}: Network error`, "error");
    }

    await new Promise((resolve) => setTimeout(resolve, 50)); // Giảm delay để test nhanh hơn
  }

  const summary = `Spam test completed!\nSuccess: ${successCount}\nRate limited: ${rateLimitedCount}\nErrors: ${errorCount}`;
  showResult(
    "rate-limit-result",
    summary,
    rateLimitedCount > 0 ? "success" : "warning"
  );
  logActivity(
    `Spam test completed: ${successCount} success, ${rateLimitedCount} rate limited, ${errorCount} errors`,
    "info"
  );
}

async function checkRateLimit() {
  logActivity("Checking rate limit status", "info");

  try {
    const headers = {};
    if (currentJWT) {
      headers["Authorization"] = `Bearer ${currentJWT}`;
    }

    const response = await fetch(`${KONG_BASE_URL}/api/jwt/info`, {
      method: "GET",
      headers: headers,
    });

    const rateLimitRemaining = response.headers.get(
      "X-RateLimit-Remaining-minute"
    );
    const rateLimitLimit = response.headers.get("X-RateLimit-Limit-minute");

    if (rateLimitRemaining !== null && rateLimitLimit !== null) {
      showResult(
        "rate-limit-result",
        `Rate Limit Status:\nRemaining: ${rateLimitRemaining}/${rateLimitLimit} requests per minute`,
        "info"
      );
      logActivity(
        `Rate limit: ${rateLimitRemaining}/${rateLimitLimit} remaining`,
        "info"
      );
    } else {
      showResult(
        "rate-limit-result",
        `Status: ${response.status} - ${response.statusText}`,
        response.status === 429 ? "warning" : "info"
      );
      logActivity(
        `Rate limit check: HTTP ${response.status}`,
        response.status === 429 ? "warning" : "info"
      );
    }
  } catch (error) {
    showResult(
      "rate-limit-result",
      `Error checking rate limit: ${error.message}`,
      "danger"
    );
    logActivity(`Rate limit check error`, "error");
  }
}

// Session Management - Signout & Clear All
async function signoutAndClearAll() {
  logActivity("Starting signout and clear all process...", "warning");

  let signoutSuccess = false;

  // Step 1: Attempt to signout if we have JWT token
  if (currentJWT) {
    try {
      // Decode JWT để lấy refresh token (nếu có)
      const payload = JSON.parse(atob(currentJWT.split(".")[1]));
      logActivity(`Found JWT for user: ${payload.username}`, "info");

      // Tạo mock refresh token hoặc call signout endpoint
      const signoutResponse = await fetch(
        `${KONG_BASE_URL}/api/public/signout`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${currentJWT}`,
          },
          body: JSON.stringify({
            refresh_token: "mock_refresh_token", // Hoặc lấy từ localStorage nếu có
          }),
        }
      );

      if (signoutResponse.ok) {
        const result = await signoutResponse.json();
        logActivity(
          `Server signout successful for ${payload.username}`,
          "success"
        );
        signoutSuccess = true;
      } else {
        const errorResult = await signoutResponse.json();
        logActivity(
          `Server signout failed: ${errorResult.error || "Unknown error"}`,
          "warning"
        );
      }
    } catch (error) {
      logActivity(`Signout attempt failed: ${error.message}`, "warning");
    }
  }

  // Step 2: Clear all local session data regardless of server response
  clearAllSessionData();

  // Step 3: Reset UI displays
  resetUIDisplays();

  // Step 4: Show final result
  const message = signoutSuccess
    ? "Successfully signed out from server and cleared all local data"
    : "Cleared all local data (server signout may have failed)";

  showGlobalResult(message, signoutSuccess ? "success" : "warning");
  logActivity("Signout and clear all process completed", "success");
}

// Helper function to clear all session data
function clearAllSessionData() {
  // Clear global variables
  currentJWT = null;
  currentApiKey = null;
  oldApiKey = null;
  spamRequestCount = 0;

  // Clear localStorage if used
  localStorage.removeItem("jwt_token");
  localStorage.removeItem("refresh_token");
  localStorage.removeItem("api_key");

  // Clear sessionStorage if used
  sessionStorage.clear();

  logActivity("All session data cleared", "info");
}

// Helper function to reset UI displays
function resetUIDisplays() {
  // Reset token displays in Control Panel
  document.getElementById("jwt-token-display").textContent = "Not logged in";
  document.getElementById("api-key-display").textContent = "No API key";

  // Clear all result containers
  const resultContainers = [
    "injection-result",
    "key-result",
    "auth-result",
    "rate-limit-result",
  ];

  resultContainers.forEach((containerId) => {
    const container = document.getElementById(containerId);
    if (container) {
      container.innerHTML = "";
    }
  });

  // Reset form inputs (optional)
  const formInputs = [
    "test-username",
    "test-password",
    "key-username",
    "key-password",
    "jwt-username",
    "jwt-password",
  ];

  formInputs.forEach((inputId) => {
    const input = document.getElementById(inputId);
    if (input) {
      input.value = "";
    }
  });

  // Reset progress bar
  const progressBar = document.getElementById("spam-progress");
  if (progressBar) {
    progressBar.style.width = "0%";
  }

  logActivity("UI displays reset", "info");
}

// Helper function to show global result (appears in all zones)
function showGlobalResult(message, type) {
  const resultContainers = [
    "injection-result",
    "key-result",
    "auth-result",
    "rate-limit-result",
  ];

  resultContainers.forEach((containerId) => {
    showResult(containerId, message, type);
  });
}

// Helper functions để format display
function truncateApiKey(apiKey, showLength = 8) {
  if (!apiKey) return "None";
  if (apiKey.length <= showLength * 2) return apiKey;
  return `${apiKey.substring(0, showLength)}...${apiKey.substring(
    apiKey.length - showLength
  )}`;
}

function truncateJWT(jwt, showLength = 20) {
  if (!jwt) return "None";
  if (jwt.length <= showLength * 2) return jwt;
  return `${jwt.substring(0, showLength)}...${jwt.substring(
    jwt.length - showLength
  )}`;
}

// Utility function to show results
function showResult(containerId, message, type) {
  const container = document.getElementById(containerId);

  // Xử lý message với format đặc biệt cho API key
  let formattedMessage = message;

  // Detect API key patterns và wrap với styling
  if (message.includes("API Key obtained") || message.includes("Key rotated")) {
    // Wrap tất cả API key patterns (bao gồm hex keys)
    formattedMessage = message
      .replace(
        /([a-f0-9]{8,})\.\.\.([a-f0-9]{8,})/g,
        '<code class="truncated-key">$1...$2</code>'
      )
      .replace(
        /• Old: ([a-f0-9]{8,}\.\.\.[a-f0-9]{8,})/g,
        '• <span class="token-comparison old-key">Old: <code class="truncated-key">$1</code></span>'
      )
      .replace(
        /• New: ([a-f0-9]{8,}\.\.\.[a-f0-9]{8,})/g,
        '• <span class="token-comparison new-key">New: <code class="truncated-key">$1</code></span>'
      );
  }

  // Detect JWT patterns với flexible length
  if (message.includes("JWT obtained:")) {
    formattedMessage = message.replace(
      /(eyJ[A-Za-z0-9-_]{15,})\.\.\.([A-Za-z0-9-_]{15,})/g,
      '<code class="truncated-key">$1...$2</code>'
    );
  }

  container.innerHTML = `<div class="alert alert-${type} token-comparison">${formattedMessage.replace(
    /\n/g,
    "<br>"
  )}</div>`;
}

// Debug function để test tất cả endpoints
async function debugEndpoints() {
  logActivity("Debugging all endpoints...", "info");

  const endpoints = [
    { url: `${KONG_BASE_URL}/api/public/info`, name: "Kong Public Info" },
    { url: `${API_BASE_URL}/api/public/info`, name: "API Server Public Info" },
    {
      url: `${KONG_BASE_URL}/api/auth/getApiKey`,
      name: "Kong API Key Endpoint",
    },
    { url: `${KONG_BASE_URL}/api/key/info`, name: "Kong Key Test Endpoint" },
    { url: `${KONG_BASE_URL}/api/jwt/info`, name: "Kong JWT Test Endpoint" },
  ];

  for (const endpoint of endpoints) {
    try {
      const response = await fetch(endpoint.url, { method: "GET" });
      const contentType = response.headers.get("content-type");

      logActivity(
        `📡 ${endpoint.name}: ${response.status} (${contentType})`,
        response.ok ? "success" : "warning"
      );
    } catch (error) {
      logActivity(`${endpoint.name}: ${error.message}`, "error");
    }
  }
}

// Setup event listeners
function setupEventListeners() {
  // Zone 1: Injection Test buttons
  document
    .getElementById("btn-normal-signup")
    ?.addEventListener("click", testNormalSignup);
  document
    .getElementById("btn-malicious-signup")
    ?.addEventListener("click", testMaliciousSignup);

  // Zone 2: Key Management buttons
  document
    .getElementById("btn-get-api-key")
    ?.addEventListener("click", getApiKey);
  document
    .getElementById("btn-rotate-api-key")
    ?.addEventListener("click", rotateApiKey);
  document
    .getElementById("btn-test-current-key")
    ?.addEventListener("click", testCurrentKey);
  document
    .getElementById("btn-test-old-key")
    ?.addEventListener("click", testOldKey);

  // Zone 3: Auth Inconsistency buttons
  document
    .getElementById("btn-test-public")
    ?.addEventListener("click", testPublicEndpoint);
  document
    .getElementById("btn-test-key")
    ?.addEventListener("click", testKeyEndpoint);
  document
    .getElementById("btn-test-jwt")
    ?.addEventListener("click", testJwtEndpoint);
  document
    .getElementById("btn-quick-jwt-login")
    ?.addEventListener("click", quickJwtLogin);

  // Zone 4: Rate Limiting buttons
  document
    .getElementById("btn-spam-requests")
    ?.addEventListener("click", spamRequests);
  document
    .getElementById("btn-check-rate-limit")
    ?.addEventListener("click", checkRateLimit);

  // Sidebar buttons
  document
    .getElementById("btn-clear-logs")
    ?.addEventListener("click", clearLogs);

  // Session Management button
  document
    .getElementById("btn-signout-all")
    ?.addEventListener("click", signoutAndClearAll);

  // Malicious examples
  document
    .querySelectorAll(".malicious-examples .example")
    .forEach((example) => {
      example.addEventListener("click", function () {
        const username = this.getAttribute("data-username");
        const password = this.getAttribute("data-password");
        setMaliciousInput(username, password);
      });
    });

  // Add debug button
  const debugBtn = document.createElement("button");
  debugBtn.textContent = "Debug Endpoints";
  debugBtn.className = "btn btn-info";
  debugBtn.onclick = debugEndpoints;
  debugBtn.style.marginTop = "10px";
  document.querySelector(".sidebar")?.appendChild(debugBtn);

  // Add JWT API Key button
  const jwtApiKeyBtn = document.createElement("button");
  jwtApiKeyBtn.textContent = "Get API Key (JWT)";
  jwtApiKeyBtn.className = "btn btn-secondary";
  jwtApiKeyBtn.onclick = loginForApiKey;
  jwtApiKeyBtn.style.marginTop = "5px";
  jwtApiKeyBtn.style.width = "100%";

  const keySection = document.querySelector("#btn-get-api-key")?.parentNode;
  if (keySection) {
    keySection.appendChild(jwtApiKeyBtn);
  }
}
