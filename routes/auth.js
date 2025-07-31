import express from "express";
import User from "../models/User.model.js";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import crypto from 'crypto';

const router = express.Router();

// Dynamic configuration based on environment
const rpName = 'Biometric Auth App';
const isDevelopment = process.env.NODE_ENV !== 'production';

// Helper function to get current domain configuration
const getDomainConfig = (req) => {
  const origin = req.headers.origin || req.headers.referer;
  
  if (origin && origin.includes('biometricauth-frontend.vercel.app')) {
    return {
      rpID: 'biometricauth-frontend.vercel.app',
      expectedOrigin: 'https://biometricauth-frontend.vercel.app'
    };
  } else {
    return {
      rpID: 'localhost',
      expectedOrigin: 'http://localhost:5173'
    };
  }
};

// ========== TRADITIONAL AUTHENTICATION ==========

// Traditional Signup
router.post("/signup", async (req, res) => {
  try {
    const { firstname, lastname, username, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        message: "Username already exists" 
      });
    }

    // Generate unique userId for WebAuthn
    const userId = crypto.randomUUID();

    // Create new user
    const newUser = new User({
      firstname,
      lastname,
      username,
      userId,
      password, // In production, hash this password
      credentials: [],
      currentChallenge: null
    });

    await newUser.save();

    res.status(201).json({
      success: true,
      message: "User created successfully",
      user: {
        id: newUser._id,
        username: newUser.username,
        firstname: newUser.firstname,
        lastname: newUser.lastname,
        userId: newUser.userId
      }
    });

  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Internal server error" 
    });
  }
});

// Traditional Login
router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find user
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: "Invalid credentials" 
      });
    }

    // Check password (in production, compare hashed passwords)
    if (user.password !== password) {
      return res.status(401).json({ 
        success: false, 
        message: "Invalid credentials" 
      });
    }

    res.json({
      success: true,
      message: "Login successful",
      user: {
        id: user._id,
        username: user.username,
        firstname: user.firstname,
        lastname: user.lastname,
        userId: user.userId,
        hasPasskeys: user.credentials.length > 0
      }
    });

  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Internal server error" 
    });
  }
});

// ========== WEBAUTHN/BIOMETRIC AUTHENTICATION ==========

// Step 1: Generate registration options for biometric setup
router.post("/webauthn/register/begin", async (req, res) => {
  try {
    const { username } = req.body;
    const { rpID } = getDomainConfig(req);

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: "User not found" 
      });
    }

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: Buffer.from(user.userId, 'utf8'),
      userName: user.username,
      userDisplayName: `${user.firstname} ${user.lastname}`,
      attestationType: 'none',
      excludeCredentials: user.credentials.map(cred => ({
        id: cred.credentialID,
        type: 'public-key',
      })),
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
        // Remove authenticatorAttachment to allow all types
      },
      timeout: 60000,
    });

    user.currentChallenge = options.challenge;
    await user.save();

    res.json({
      success: true,
      options
    });

  } catch (error) {
    console.error("WebAuthn registration begin error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Failed to generate registration options" 
    });
  }
});

router.post("/webauthn/register/finish", async (req, res) => {
  try {
    const { username, credential } = req.body;
    const { rpID, expectedOrigin } = getDomainConfig(req);

    const user = await User.findOne({ username });
    if (!user || !user.currentChallenge) {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid registration attempt" 
      });
    }

    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: user.currentChallenge,
      expectedOrigin,
      expectedRPID: rpID,
    });

    if (verification.verified) {
      const registrationInfo = verification.registrationInfo;
      
      console.log('Registration info:', registrationInfo);
      console.log('credentialID:', registrationInfo.credentialID, typeof registrationInfo.credentialID);
      console.log('credentialPublicKey:', registrationInfo.credentialPublicKey, typeof registrationInfo.credentialPublicKey);

      // FIXED: Handle both string and Uint8Array cases properly
      let credentialID, credentialPublicKey;

      if (typeof registrationInfo.credentialID === 'string') {
        // If it's already a string (base64url), convert to Buffer
        credentialID = Buffer.from(registrationInfo.credentialID, 'base64url');
      } else {
        // If it's Uint8Array, convert directly to Buffer
        credentialID = Buffer.from(registrationInfo.credentialID);
      }

      if (registrationInfo.credentialPublicKey instanceof Uint8Array) {
        credentialPublicKey = Buffer.from(registrationInfo.credentialPublicKey);
      } else {
        credentialPublicKey = Buffer.from(registrationInfo.credentialPublicKey);
      }
      
      console.log('Storing credentialID as base64url:', credentialID.toString('base64url'));
      console.log('Original credential from frontend:', credential.rawId || credential.id);

      user.credentials.push({
        credentialID: credentialID,
        credentialPublicKey: credentialPublicKey,
        counter: registrationInfo.counter,
        createdAt: new Date()
      });

      user.currentChallenge = null;
      await user.save();

      console.log('Successfully stored credential with ID:', credentialID.toString('base64url'));

      res.json({
        success: true,
        message: "Biometric authentication setup successful!"
      });
    } else {
      res.status(400).json({ 
        success: false, 
        message: "Registration verification failed" 
      });
    }

  } catch (error) {
    console.error("WebAuthn registration finish error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Registration verification failed" 
    });
  }
});
router.post("/webauthn/authenticate/begin", async (req, res) => {
  try {
    const { username } = req.body;
    const { rpID } = getDomainConfig(req);

    const user = await User.findOne({ username });
    if (!user || user.credentials.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: "No biometric credentials found for this user" 
      });
    }

    // Add debugging
    console.log('User credentials in DB:', user.credentials.map(c => ({
      id: c.credentialID.toString('base64url'),
      createdAt: c.createdAt
    })));

    const allowCredentials = user.credentials.map(cred => ({
      id: cred.credentialID.toString('base64url'),
      type: 'public-key',
    }));

    console.log('Sending allowCredentials:', allowCredentials);

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials,
      userVerification: 'preferred',
      timeout: 60000,
    });

    user.currentChallenge = options.challenge;
    await user.save();

    res.json({
      success: true,
      options
    });

  } catch (error) {
    console.error("WebAuthn authentication begin error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Failed to generate authentication options" 
    });
  }
});

router.post("/webauthn/authenticate/finish", async (req, res) => {
  try {
    const { username, credential } = req.body;
    const { rpID, expectedOrigin } = getDomainConfig(req);

    const user = await User.findOne({ username });
    if (!user || !user.currentChallenge) {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid authentication attempt" 
      });
    }

    // Use rawId instead of id for credential matching
    const credentialIdBuffer = Buffer.from(credential.rawId, 'base64url');
    
    console.log('Credential received:', JSON.stringify(credential, null, 2));
    console.log('credential.rawId from frontend:', credential.rawId);
    console.log('credentialID in DB:', user.credentials.map(c => c.credentialID.toString('base64url')));
    
    // Debug: Also log raw buffer comparison
    console.log('Frontend credential buffer:', credentialIdBuffer.toString('base64url'));
    console.log('DB credential buffers:', user.credentials.map(c => c.credentialID.toString('base64url')));

    const userCredential = user.credentials.find(cred => 
      cred.credentialID.equals(credentialIdBuffer)
    );

    if (!userCredential) {
      console.error('Credential not found for user:', username);
      console.error('Available credentials count:', user.credentials.length);
      return res.status(400).json({ 
        success: false, 
        message: "Credential not found. Please re-register your biometric authentication." 
      });
    }

    // Rest of your authentication logic...
    console.log('userCredential found:', userCredential);

    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: user.currentChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: userCredential.credentialID,
        credentialPublicKey: userCredential.credentialPublicKey,
        counter: userCredential.counter,
      },
    });

    console.log('Verification result:', verification);

    if (verification.verified) {
      userCredential.counter = verification.authenticationInfo.newCounter;
      user.currentChallenge = null;
      await user.save();

      res.json({
        success: true,
        message: "Biometric authentication successful!",
        user: {
          id: user._id,
          username: user.username,
          firstname: user.firstname,
          lastname: user.lastname
        }
      });
    } else {
      res.status(400).json({ 
        success: false, 
        message: "Authentication verification failed" 
      });
    }

  } catch (error) {
    console.error("WebAuthn authentication finish error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Authentication verification failed" 
    });
  }
});

// Get user info (check if user has biometric setup)
router.get("/user/:username", async (req, res) => {
  try {
    const { username } = req.params;
    
    const user = await User.findOne({ username }).select('-password -currentChallenge');
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: "User not found" 
      });
    }

    res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        firstname: user.firstname,
        lastname: user.lastname,
        hasPasskeys: user.credentials.length > 0,
        credentialCount: user.credentials.length
      }
    });

  } catch (error) {
    console.error("Get user error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Internal server error" 
    });
  }
});
// Add this temporarily for cleanup
router.delete("/webauthn/clear/:username", async (req, res) => {
  try {
    const { username } = req.params;
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: "User not found" 
      });
    }

    // Clear all credentials and challenges
    user.credentials = [];
    user.currentChallenge = null;
    await user.save();

    res.json({
      success: true,
      message: "All biometric credentials cleared"
    });

  } catch (error) {
    console.error("Clear credentials error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Failed to clear credentials" 
    });
  }
});

export default router;