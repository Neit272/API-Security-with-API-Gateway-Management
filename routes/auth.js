import express from "express";
import {
  getApiKeyViaBasicAuth,
  getApiKeyViaJWT,
} from "../controllers/authControllers.js";

const router = express.Router();

// Support both Basic Auth and JWT for getting API key
router.get("/getApiKey", async (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      success: false,
      error: "Authorization header required. Use Basic auth or Bearer token.",
    });
  }

  if (authHeader.toLowerCase().startsWith("basic")) {
    return getApiKeyViaBasicAuth(req, res);
  } else if (authHeader.toLowerCase().startsWith("bearer")) {
    return getApiKeyViaJWT(req, res);
  } else {
    return res.status(401).json({
      success: false,
      error: "Invalid authorization type. Use Basic auth or Bearer token.",
    });
  }
});

export default router;
