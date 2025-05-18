import { Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import prisma from "../prisma"; // Import the centralized Prisma client
import { OAuth2Client } from "google-auth-library"; // Added import

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID); // Added: Initialize Google Auth Client

// Helper function to generate JWT
const generateToken = (id: string): string => {
  // Sign the token with the user ID and JWT secret from environment variables
  // Set an expiration time (e.e., 30 days)
  return jwt.sign({ id }, process.env.JWT_SECRET as string, {
    expiresIn: "30d",
  });
};

// Helper function to determine if user is premium
const getSubscriptionInfo = async (userId: string) => {
  const subscription = await prisma.subscription.findFirst({
    where: {
      userId: userId,
      status: "active", // Consider other statuses like "trialing" as premium
    },
  });

  if (subscription) {
    return {
      isPremium: true,
      plan: subscription.plan,
      endDate: subscription.endDate,
      status: subscription.status,
    };
  }
  return {
    isPremium: false,
    plan: null,
    endDate: null,
    status: null,
  };
};

// @desc    Register a new user
// @route   POST /api/auth/register
// @access  Public
const registerUser = async (req: Request, res: Response) => {
  console.log("Register request received:", { email: req.body.email });
  const { email, password, name } = req.body; // Added name for potential manual registration

  // Basic validation for email and password
  if (!email || !password) {
    return res.status(400).json({ message: "Please enter email and password" });
  }

  try {
    const userExists = await prisma.user.findUnique({ where: { email } });

    if (userExists) {
      // If user exists and signed up with Google, prevent email/password registration for this email
      if (userExists.authProvider === "google") {
        return res.status(400).json({
          message:
            "This email is registered with Google Sign-In. Please use Google Sign-In.",
        });
      }
      return res
        .status(400)
        .json({ message: "User already exists with this email." });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name: name || email.split("@")[0], // Use provided name or derive from email
        authProvider: "email", // Explicitly set authProvider
      },
      select: {
        id: true,
        email: true,
        name: true,
        profileImageUrl: true,
        authProvider: true,
        createdAt: true,
      },
    });

    if (user) {
      const subscriptionInfo = {
        isPremium: false,
        plan: null,
        endDate: null,
        status: null,
      };
      res.status(201).json({
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          profileImageUrl: user.profileImageUrl,
          authProvider: user.authProvider,
          ...subscriptionInfo,
        },
        token: generateToken(user.id),
      });
    } else {
      res.status(400).json({ message: "Invalid user data" });
    }
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).json({ message: "Server error" });
  }
};

// @desc    Authenticate user & get token
// @route   POST /api/auth/login
// @access  Public
const loginUser = async (req: Request, res: Response) => {
  console.log("Login request received:", { email: req.body.email });
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Please enter all fields" });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // If user signed up with Google, they should use Google Sign-In
    if (user.authProvider === "google" && !user.password) {
      // Check if password field is null for Google users
      return res.status(401).json({
        message:
          "This account is linked with Google Sign-In. Please use Google to log in.",
      });
    }

    // Ensure password exists before comparing (it's optional in schema)
    if (!user.password) {
      return res.status(401).json({
        message: "Invalid credentials - password not set for this user.",
      });
    }

    if (await bcrypt.compare(password, user.password)) {
      const subscriptionInfo = await getSubscriptionInfo(user.id);
      res.json({
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          profileImageUrl: user.profileImageUrl,
          authProvider: user.authProvider,
          ...subscriptionInfo,
        },
        token: generateToken(user.id),
      });
    } else {
      res.status(401).json({ message: "Invalid credentials" });
    }
  } catch (error) {
    console.error("Error logging in user:", error);
    res.status(500).json({ message: "Server error" });
  }
};

// @desc    Authenticate user with Google & get token
// @route   POST /api/auth/google
// @access  Public
const googleSignIn = async (req: Request, res: Response) => {
  const { tokenId } = req.body;
  if (!tokenId) {
    return res.status(400).json({ message: "Google token ID is required" });
  }

  if (!process.env.GOOGLE_CLIENT_ID) {
    console.error("GOOGLE_CLIENT_ID is not set in .env file");
    return res.status(500).json({
      message: "Server configuration error: Google Client ID missing.",
    });
  }

  try {
    const ticket = await client.verifyIdToken({
      idToken: tokenId,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();

    if (!payload || !payload.email || !payload.sub) {
      return res.status(400).json({ message: "Invalid Google token" });
    }

    const { sub: googleId, email, name, picture: profileImageUrl } = payload;

    let user = await prisma.user.findUnique({
      where: { googleId }, // Check if user already signed in with this Google ID
    });

    if (!user) {
      // No user with this googleId. Check if an email user exists to link.
      const existingEmailUser = await prisma.user.findUnique({
        where: { email },
      });

      if (existingEmailUser) {
        // User with this email exists. Link Google account.
        if (
          existingEmailUser.googleId &&
          existingEmailUser.googleId !== googleId
        ) {
          // Safety check: email is linked to a DIFFERENT Google account.
          return res.status(400).json({
            message:
              "This email is already linked to a different Google account.",
          });
        }

        // If they are an email user or not yet linked to this specific googleId, update them.
        if (
          existingEmailUser.authProvider === "email" ||
          !existingEmailUser.googleId
        ) {
          user = await prisma.user.update({
            where: { email: existingEmailUser.email },
            data: {
              googleId,
              name: existingEmailUser.name || name,
              profileImageUrl:
                existingEmailUser.profileImageUrl || profileImageUrl,
              authProvider: "google",
              // Password remains as is, as it's mandatory by schema for email users.
              // No change to password field here.
            },
          });
        } else {
          // User exists, authProvider is already google, and googleId matches. This is a login.
          user = existingEmailUser;
        }
      } else {
        // No user with this googleId AND no existing email user to link.
        // Since password is required by schema, we cannot create a new user via Google Sign-In
        // without a password. Instruct them to register normally first.
        console.log(
          "Google Sign-In: New user attempt (email not found), but password is required. User needs to register with email/password first."
        );
        return res.status(403).json({
          message:
            "User not found. Please register with email and password. You can link your Google account later.",
        });
      }
    }

    if (!user) {
      // This case should ideally not be reached if logic above is correct
      console.error(
        "Google Sign-In: User object is null after linking/checking logic."
      );
      return res.status(500).json({
        message: "An unexpected error occurred during Google Sign-In.",
      });
    }

    // At this point, user is either found or linked
    const subscriptionInfo = await getSubscriptionInfo(user.id);
    res.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        profileImageUrl: user.profileImageUrl,
        authProvider: user.authProvider,
        ...subscriptionInfo,
      },
      token: generateToken(user.id),
    });
  } catch (error) {
    console.error("Error during Google Sign-In:", error);
    // Differentiate between token verification error and other errors
    if (error instanceof Error) {
      // Type check for error
      if (
        error.message.includes("Token used too late") ||
        error.message.includes("Invalid token signature") ||
        error.message.includes("Invalid Google token") // Added another common message
      ) {
        return res
          .status(401)
          .json({ message: "Invalid or expired Google token." });
      }
    }
    res.status(500).json({ message: "Server error during Google Sign-In" });
  }
};

export { registerUser, loginUser, googleSignIn }; // Added googleSignIn to exports
