import express from "express";
import {
  createPaymentOrder,
  handlePhonePeWebhook,
} from "../controllers/payment.controller"; // Import controller functions
import { protect } from "../middleware/auth.middleware"; // Import the auth middleware

const router = express.Router();

// Protected route for authenticated users to create a payment order
router.post("/create-order", protect, createPaymentOrder);

// Public route for PhonePe webhooks (does NOT need 'protect' middleware)
// This endpoint must be accessible by PhonePe's servers
// The actual webhook URL would be something like https://your-backend-url.com/api/payments/webhook
router.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  handlePhonePeWebhook
); // Use express.raw to get the raw body for signature verification

export default router;
