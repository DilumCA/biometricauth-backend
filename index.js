import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import { connectMongo } from "./utils/db.js";


import authRoutes from "./routes/auth.js";

dotenv.config();
const app = express();

// DB Connection
connectMongo();

// Middleware
app.use(express.json());
app.use(cors({ 
  origin: [
    "http://localhost:5173", 
    "http://192.168.1.6:5173",
    "https://biometricauth-frontend.vercel.app" 
  ], 
  credentials: true 
}));



// Test route
app.get("/", (req, res) => {
  res.send("Biometric authentication API is running...");
});




app.use("/auth", authRoutes);

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

