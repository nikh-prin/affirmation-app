import { Request, Response } from "express";
import prisma from "../prisma"; // Import the centralized Prisma client

// Define a custom interface to add user property to Request, matching auth.middleware
interface AuthRequest extends Request {
  user?: { id: string };
}

// @desc    Get user subscription details
// @route   GET /api/subscriptions/
// @access  Private (requires authentication)
const getUserSubscription = async (req: AuthRequest, res: Response) => {
  const userId = req.user?.id;

  if (!userId) {
    return res
      .status(401)
      .json({ message: "Not authorized, user ID not found" });
  }

  try {
    // Find the subscription for the logged-in user
    const subscription = await prisma.subscription.findUnique({
      where: { userId: userId }, // Subscription is linked by userId
      select: {
        // Select fields to return
        id: true,
        status: true,
        plan: true,
        startDate: true,
        endDate: true,
        renewalDate: true,
        createdAt: true,
      },
    });

    if (subscription) {
      res.json(subscription); // 200 OK
    } else {
      // Return null or a specific status if no subscription is found
      res.status(200).json(null); // Or res.status(404).json({ message: 'No active subscription found' }); depending on desired behavior
    }
  } catch (error) {
    console.error("Error fetching user subscription:", error);
    res.status(500).json({ message: "Server error" });
  }
};

export { getUserSubscription };
