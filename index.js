const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { MongoClient } = require("mongodb");
require("dotenv").config();
const jwt = require("jsonwebtoken");
const { z } = require("zod");

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection URL
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

async function run() {
  try {
    // Connect to MongoDB
    await client.connect();
    console.log("Connected to MongoDB");

    const db = client.db("midwife");
    const collection = db.collection("users");
    const reportsCollection = db.collection("reports");

    //! USERS API START
    // User Registration

    // Zod schema for validation
    const registerSchema = z.object({
      name: z.string().min(1),
      email: z.string().email(),
      password: z.string().min(6),
      confirmPassword: z.string().min(6),
      location: z.object({
        lat: z.number(),
        lng: z.number(),
      }),
      designation: z.string(),
      institution: z.string(),
      mobileNumber: z
        .string()
        .regex(/^\d{11}$/, "Mobile number must be 11 digits"),
    });

    // Zod schema for report validation
    const reportSchema = z.object({
      name: z.string().min(1, "Name is required"),
      mobileNumber: z
        .string()
        .regex(/^\d{11}$/, "Mobile number must be 11 digits"),
      address: z.string().min(1, "Address is required"),
      location: z.object({
        lat: z.number(),
        lng: z.number(),
      }),
      cause: z.string().min(1, "Please select a cause"),
      otherCause: z.string().optional(),
      createdAt: z.date().default(() => new Date()),
    });

    app.post("/api/v1/register", async (req, res) => {
      try {
        // Validate incoming data using Zod
        const validatedData = registerSchema.parse(req.body);

        const {
          name,
          email,
          password,
          confirmPassword,
          location,
          designation,
          institution,
          mobileNumber,
        } = validatedData;

        // Validate password & confirmPassword match
        if (password !== confirmPassword) {
          return res
            .status(400)
            .json({ success: false, message: "Passwords do not match" });
        }

        // Check if email already exists
        const existingUser = await collection.findOne({ email });
        if (existingUser) {
          return res
            .status(400)
            .json({ success: false, message: "User already exists" });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user object
        const newUser = {
          name,
          email,
          password: hashedPassword,
          location,
          designation,
          institution,
          mobileNumber,
          role: "user", // Default role
          isVerified: false, // Hidden from the user, used for admin approval
          createdAt: new Date(),
        };

        // Insert user into database
        await collection.insertOne(newUser);

        res.status(201).json({
          success: true,
          message:
            "User registered successfully. Please verify your email or phone number.",
        });
      } catch (err) {
        res.status(400).json({ success: false, message: err.message });
      }
    });

    app.post("/api/v1/login", async (req, res) => {
      const { email, password } = req.body;
      const user = await collection.findOne({ email });

      if (!user) {
        return res.status(401).json({ message: "Invalid email or password" });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ message: "Invalid email or password" });
      }

      // 🔴 Prevent blocked users from logging in
      if (user.isBlocked) {
        return res.status(403).json({ message: "Your account is on hold" });
      }

      // Generate token including role, isVerified, and isBlocked status
      const token = jwt.sign(
        {
          email: user.email,
          role: user.role,
          isVerified: user.isVerified,
          isBlocked: user.isBlocked, // 🔥 Store isBlocked in token
        },
        process.env.JWT_SECRET,
        { expiresIn: "1d" }
      );

      res.json({
        success: true,
        message: "Login successful",
        token,
        role: user.role,
        isVerified: user.isVerified,
        isBlocked: user.isBlocked, // 🔥 Send isBlocked in response
      });
    });

    //! USERS API END

    // ! Reports API
    // POST: Create a new report
    app.post("/api/v1/reports", async (req, res) => {
      try {
        const validatedData = reportSchema.parse(req.body);

        // Add isSolved property as false by default
        const reportWithStatus = {
          ...validatedData,
          isSolved: false, // Default status
        };

        await reportsCollection.insertOne(reportWithStatus);

        res.status(201).json({
          success: true,
          message: "Report submitted successfully.",
          report: reportWithStatus,
        });
      } catch (err) {
        res.status(400).json({ success: false, message: err.message });
      }
    });

    // GET: Fetch all reports
    app.get("/api/v1/reports", async (req, res) => {
      try {
        const now = new Date();
        const last24Hours = new Date(now.getTime() - 24 * 60 * 60 * 1000); // 24 hours ago

        const allReports = await reportsCollection
          .find()
          .sort({ createdAt: -1 })
          .toArray();

        const last24HoursReports = allReports.filter(
          (report) => new Date(report.createdAt) >= last24Hours
        );

        res.json({
          success: true,
          allReportsCount: allReports.length,
          allReports,
          last24HoursReports,
        });
      } catch (err) {
        res
          .status(500)
          .json({ success: false, message: "Internal server error" });
      }
    });

    // PATCH: Update report status
    app.patch("/api/v1/reports/:reportId", async (req, res) => {
      try {
        const { reportId } = req.params;
        const { isSolved, solution, solverName } = req.body;

        if (!isSolved || !solution || !solverName) {
          return res.status(400).json({
            success: false,
            message: "isSolved, solution, and solverName are required",
          });
        }

        const result = await reportsCollection.updateOne(
          { _id: require("mongodb").ObjectId(reportId) },
          {
            $set: {
              isSolved,
              solution,
              solverName,
              solvedAt: new Date(),
            },
          }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({
            success: false,
            message: "Report not found",
          });
        }

        const updatedReport = await reportsCollection.findOne({
          _id: require("mongodb").ObjectId(reportId),
        });

        res.status(200).json({
          success: true,
          message: "Report updated successfully",
          report: updatedReport,
        });
      } catch (err) {
        console.error("Error updating report:", err);
        res.status(500).json({
          success: false,
          message: "Internal server error",
        });
      }
    });
    // ! Reports API

    //! Admin Dashboard

    // ! super admin api
    app.patch("/api/v1/admin/verify-user/:email", async (req, res) => {
      const { email } = req.params;

      // Find user by email
      const user = await collection.findOne({ email });
      if (!user) {
        return res
          .status(404)
          .json({ success: false, message: "User not found" });
      }

      // Update user's verification status
      await collection.updateOne({ email }, { $set: { isVerified: true } });

      res.json({ success: true, message: "User verified successfully" });
    });

    // ! Blocked user
    app.patch("/api/v1/admin/block-user/:email", async (req, res) => {
      try {
        const { email } = req.params;
        const { isBlocked, isVerified } = req.body;

        // Check if user exists
        const user = await collection.findOne({ email });
        if (!user) {
          return res
            .status(404)
            .json({ success: false, message: "User not found" });
        }

        // Update user's blocked and verified status
        await collection.updateOne(
          { email },
          { $set: { isBlocked, isVerified } }
        );

        res.json({
          success: true,
          message: "User status updated successfully",
        });
      } catch (error) {
        console.error("Error updating user status:", error);
        res
          .status(500)
          .json({ success: false, message: "Internal server error" });
      }
    });

    // !Admin Dashboard - Get All Users (/api/v1/admin/users)
    app.get("/api/v1/admin/users", async (req, res) => {
      const users = await collection
        .find()
        .sort({ createdAt: -1 }) // Sort by creation time (latest first)
        .toArray();

      // Hide passwords from the response
      const sanitizedUsers = users.map(({ password, ...user }) => user);

      res.json({ success: true, users: sanitizedUsers });
    });

    //! Delete User
    app.delete("/api/v1/admin/users", async (req, res) => {
      try {
        const { email } = req.body;

        if (!email) {
          return res
            .status(400)
            .json({ success: false, message: "Email is required" });
        }

        const result = await collection.deleteOne({ email });

        if (result.deletedCount === 0) {
          return res
            .status(404)
            .json({ success: false, message: "User not found" });
        }

        res.json({ success: true, message: "User deleted successfully" });
      } catch (error) {
        console.error("Error deleting user:", error);
        res
          .status(500)
          .json({ success: false, message: "Internal server error" });
      }
    });

    //! recent-users
    app.get("/api/v1/admin/recent-users", async (req, res) => {
      try {
        const now = new Date();
        const thirtyMinutesAgo = new Date(now.getTime() - 30 * 60 * 1000);
        const twentyFourHoursAgo = new Date(
          now.getTime() - 24 * 60 * 60 * 1000
        );

        const last30MinutesUsers = await collection
          .find({ createdAt: { $gte: thirtyMinutesAgo } })
          .toArray();

        const last24HoursUsers = await collection
          .find({ createdAt: { $gte: twentyFourHoursAgo } })
          .toArray();

        res.json({
          success: true,
          last30MinutesUsers,
          last24HoursUsers,
        });
      } catch (error) {
        res.status(500).json({ success: false, message: error.message });
      }
    });

    // ! Report

    // ! Report

    //
    // Start the server
    app.listen(port, () => {
      console.log(`Server is running on http://localhost:${port}`);
    });
  } finally {
  }
}

run().catch(console.dir);

// Test route
app.get("/", (req, res) => {
  const serverStatus = {
    message: "Server is running smoothly",
    timestamp: new Date(),
  };
  res.json(serverStatus);
});
