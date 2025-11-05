import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import userRoutes from "./routes/UserRoutes.js";
import { verifyToken } from "./auth.js";
import nodemailer from "nodemailer";
import crypto from "crypto";
import User from "./models/user.js"; // ✅ fixed path

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// ✅ Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// ✅ User routes
app.use("/api/users", userRoutes);

// ✅ Root route
app.get("/", (req, res) => {
  res.send("Eden backend is running successfully 🚀");
});

// ✅ PASSWORD RESET SYSTEM
app.post("/api/reset-password", async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const resetToken = crypto.randomBytes(20).toString("hex");
    user.resetToken = resetToken;
    user.resetTokenExpire = Date.now() + 3600000;
    await user.save();

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.STATIC_EMAIL,
        pass: process.env.EMAIL_APP_PASSWORD,
      },
    });

    const resetLink = `https://your-frontend-url.com/reset-password/${resetToken}`;

    await transporter.sendMail({
      from: process.env.STATIC_EMAIL,
      to: email,
      subject: "Password Reset Request",
      html: `
        <h2>Password Reset</h2>
        <p>You requested to reset your password. Click below to reset it:</p>
        <a href="${resetLink}" target="_blank">${resetLink}</a>
        <p>This link will expire in 1 hour.</p>
      `,
    });

    res.json({ message: "Password reset link sent to your email" });
  } catch (err) {
    console.error("❌ Reset request error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Step 2 — Reset password
app.post("/api/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  try {
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpire: { $gt: Date.now() },
    });

    if (!user) return res.status(400).json({ message: "Invalid or expired token" });

    user.password = newPassword;
    user.resetToken = undefined;
    user.resetTokenExpire = undefined;
    await user.save();

    res.json({ message: "Password reset successful" });
  } catch (err) {
    console.error("❌ Reset error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ Example protected route
app.get("/api/protected", verifyToken, (req, res) => {
  res.json({ message: `Welcome, user ID: ${req.user.id}` });
});

// ✅ Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🌍 Server running on port ${PORT}`));