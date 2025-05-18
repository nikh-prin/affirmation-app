import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import prisma from "./prisma"; // Import the centralized Prisma client

// Load environment variables from .env file
dotenv.config();

const app = express();
const port = process.env.PORT || 3001; // Use port from environment or default to 3001

// Middleware
app.use(cors()); // Enable CORS for cross-origin requests
// Use express.json() for most routes
app.use(express.json());
// Use express.raw() specifically for the webhook route BEFORE it's defined
// This is needed to verify the raw body signature from payment gateways
// The payment routes file will handle applying this middleware to the webhook route
// app.use('/api/payments/webhook', express.raw({ type: 'application/json' })); // Alternative: apply specifically here if needed

// Basic route to check if the server is running
app.get("/", (req, res) => {
  res.send("Affirmation App Backend is running!");
});

// Import and use authentication routes
import authRoutes from "./routes/auth.routes";
app.use("/api/auth", authRoutes);

// Import and use user routes
import userRoutes from "./routes/user.routes";
app.use("/api/users", userRoutes);

// Import and use favorite routes
import favoriteRoutes from "./routes/favorite.routes";
app.use("/api/favorites", favoriteRoutes);

// Import and use subscription routes
import subscriptionRoutes from "./routes/subscription.routes";
app.use("/api/subscriptions", subscriptionRoutes);

// Import and use payment routes (includes webhook)
import paymentRoutes from "./routes/payment.routes";
app.use("/api/payments", paymentRoutes);

// Start the server
const server = app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

// Handle server shutdown
process.on("SIGTERM", async () => {
  console.log("SIGTERM signal received: closing HTTP server");
  server.close(async () => {
    console.log("HTTP server closed");
    await prisma.$disconnect(); // Disconnect Prisma Client
    console.log("Prisma client disconnected");
    process.exit(0);
  });
});

process.on("SIGINT", async () => {
  console.log("SIGINT signal received: closing HTTP server");
  server.close(async () => {
    console.log("HTTP server closed");
    await prisma.$disconnect(); // Disconnect Prisma Client
    console.log("Prisma client disconnected");
    process.exit(0);
  });
});

// Disconnect Prisma Client when the application exits
process.on("beforeExit", async () => {
  await prisma.$disconnect();
  console.log("Prisma client disconnected on beforeExit");
});
