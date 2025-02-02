const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { MongoClient } = require("mongodb");
require("dotenv").config();
const jwt = require("jsonwebtoken");

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

    //! USERS API START
    // User Registration
    app.post("/api/v1/register", async (req, res) => {
      const {
        email,
        password,
        confirmPassword,
        location,
        institution,
        mobileNumber,
      } = req.body;

      // Validate all fields are provided
      if (
        !email ||
        !password ||
        !confirmPassword ||
        !location ||
        !institution ||
        !mobileNumber
      ) {
        return res
          .status(400)
          .json({ success: false, message: "All fields are required" });
      }

      // Check if password & confirmPassword match
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
        email,
        password: hashedPassword,
        location,
        institution,
        mobileNumber,
        role: "user", // Default role
        isVerified: false, // Hidden from the user, used for admin approval
      };

      // Insert user into database
      await collection.insertOne(newUser);

      res.status(201).json({
        success: true,
        message:
          "User registered successfully. Please verify your email or phone number.",
      });
    });

    // User Login
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

      // Generate token including role and isVerified status
      const token = jwt.sign(
        { email: user.email, role: user.role, isVerified: user.isVerified },
        process.env.JWT_SECRET,
        { expiresIn: "1d" }
      );

      res.json({
        success: true,
        message: "Login successful",
        token,
        role: user.role,
        isVerified: user.isVerified,
      });
    });

    //! USERS API END

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

    // !Admin Dashboard - Get All Users (/api/v1/admin/users)
    app.get("/api/v1/admin/users", async (req, res) => {
      const users = await collection.find().toArray();

      // Hide passwords from the response
      const sanitizedUsers = users.map(({ password, ...user }) => user);

      res.json({ success: true, users: sanitizedUsers });
    });

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
