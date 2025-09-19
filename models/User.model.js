import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  firstname: { type: String, required: true },
  lastname: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  userId: { type: String, required: true, unique: true },
   email: { type: String, required: true, unique: true },
  
  credentials: [{
    credentialID: { type: Buffer, required: true },
    credentialPublicKey: { type: Buffer, required: true },
    counter: { type: Number, default: 0 },
    deviceName: { type: String, default: 'Unknown Device' },
    deviceType: { type: String, default: 'unknown' }, // 'mobile', 'desktop', 'tablet'
    authenticatorType: { type: String, default: 'unknown' }, // 'platform', 'cross-platform'
    browser: { type: String }, // Optional: Chrome, Firefox, Safari, etc.
    userAgent: { type: String }, // Optional: Full user agent string
    createdAt: { type: Date, default: Date.now },
    lastUsed: { type: Date, default: null }
  }],
  
  password: { type: String },
  currentChallenge: String,

lastLogin: {
    date: { type: Date },
    ip: { type: String },
    userAgent: { type: String },
    device: { type: String },
    // Add these fields:
    location: {
      city: { type: String },
      region: { type: String },
      country: { type: String },
      latitude: { type: Number },
      longitude: { type: Number }
    }
  },
 
    knownIPs: [{ 
    ip: String, 
    firstSeen: Date, 
    lastSeen: Date,
    // Add these fields:
    location: {
      city: { type: String },
      region: { type: String },
      country: { type: String },
      latitude: { type: Number },
      longitude: { type: Number }
    }
  }],
   trustedLocations: [{
    latitude: Number,
    longitude: Number,
    city: String,
    region: String,
    country_name: String,
    lastUsed: Date,
    visitCount: { type: Number, default: 1 }
  }],
  lastTrustedLogin: {
    date: Date,
    location: {
      city: String,
      region: String, 
      country_name: String,
      latitude: Number,
      longitude: Number
    }
  }
  
}, {
  timestamps: true
});

const User = mongoose.model("User", userSchema);

export default User;