import express from 'express';

const router = express.Router();

router.get("/info", (req, res) => {
  const consumerUsername = req.headers["x-consumer-username"];

  res.json({
    message: "This is a secure endpoint, accessible only with a valid apikey.",
    consumerUsername: consumerUsername || "N/A",
  });
});

export default router;