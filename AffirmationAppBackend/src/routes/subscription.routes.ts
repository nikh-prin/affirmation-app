import express from "express";
import { getUserSubscription } from "../controllers/subscription.controller"; // Import controller function
import { protect } from "../middleware/auth.middleware"; // Import the auth middleware

const router = express.Router();

// Protected route to get the logged-in user's subscription details
router.get("/", protect, getUserSubscription);

export default router;
