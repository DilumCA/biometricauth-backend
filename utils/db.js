import mongoose from "mongoose";

export const connectMongo = () => {
  mongoose
    .connect(process.env.MONGO_URI)
    .then(() => console.log("Connected to MongoDB successfully"))
    .catch((err) => console.error("MongoDB connection error:", err));
};