import express from "express";
import {
  signup,
  signin,
  refreshAccessToken,
} from "../controllers/publicControllers.js";

const router = express.Router();

router.get("/info", (req, res) => {
  console.log("Public endpoint accessed");
  res.json({
    message: "This is a public endpoint, accessible without authentication.",
  });
});
router.post("/signup", signup);
router.post("/signin", signin);
router.post("/refresh", refreshAccessToken);

export default router;
