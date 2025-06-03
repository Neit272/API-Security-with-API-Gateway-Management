import express from "express";
import publicRoutes from "./public.js";
const router = express.Router();

router.use("/public", publicRoutes);

router.get("/secure", (req, res) => {
  const consumerUsername = req.headers["x-consumer-username"];
  const consumerId = req.headers["x-consumer-id"];

  res.json({
    message: "Secure data access granted via Kong.",
    consumerUsername: consumerUsername || "N/A",
    consumerId: consumerId || "N/A",
  });
});

router.get("/generate-api-key", async (req, res) => {
  res.json({
    message: "API key generation endpoint is not implemented yet.",
    status: "success",
  });
});

export default router;
