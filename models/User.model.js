import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  firstname: { type: String, required: true },
  lastname: { type: String, required: true },
  username: { type: String, required: true, unique: true }, // This creates an index
  userId: { type: String, required: true, unique: true }, // This creates an index
  
  // Simplified credentials array - only essential WebAuthn fields
  credentials: [{
    credentialID: { type: Buffer, required: true },
    credentialPublicKey: { type: Buffer, required: true },
    counter: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
  }],
  
  // Optional fallback password
  password: { type: String },
  
  // Basic challenge storage for WebAuthn
  currentChallenge: String
  
}, {
  timestamps: true // Adds createdAt and updatedAt automatically
});



const User = mongoose.model("User", userSchema);

export default User;