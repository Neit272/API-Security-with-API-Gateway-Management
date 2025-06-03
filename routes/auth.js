import express from "express";
import { getApiKeyViaBasicAuth } from "../controllers/authControllers.js";

const router = express.Router();
router.get("/info", (req, res) => {
  res.json({
    message:
      "This is a secure endpoint, accessible only with a valid BasicAuth.",
  });
});
router.post("/apikey", getApiKeyViaBasicAuth);

export default router;
