import express from "express";
import User from "../models/User.model.js";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import crypto from 'crypto';
import bcrypt from 'bcrypt'; 

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
// Helper function to detect device info
const getDeviceInfo = () => {
  const userAgent = navigator.userAgent;
  let deviceName = 'Unknown Device';
  let deviceType = 'unknown';
  
  // Detect operating system
  if (/iPhone|iPad|iPod/i.test(userAgent)) {
    const match = userAgent.match(/iPhone OS (\d+_\d+)/);
    const version = match ? match[1].replace('_', '.') : '';
    deviceName = /iPad/i.test(userAgent) ? `iPad ${version}` : `iPhone ${version}`;
    deviceType = 'mobile';
  } else if (/Android/i.test(userAgent)) {
    const match = userAgent.match(/Android (\d+\.?\d*)/);
    const version = match ? match[1] : '';
    deviceName = `Android ${version}`;
    deviceType = 'mobile';
  } else if (/Windows NT/i.test(userAgent)) {
    const match = userAgent.match(/Windows NT (\d+\.?\d*)/);
    const version = match ? match[1] : '';
    deviceName = `Windows ${version}`;
    deviceType = 'desktop';
  } else if (/Mac OS X/i.test(userAgent)) {
    const match = userAgent.match(/Mac OS X (\d+_\d+)/);
    const version = match ? match[1].replace('_', '.') : '';
    deviceName = `macOS ${version}`;
    deviceType = 'desktop';
  } else if (/Linux/i.test(userAgent)) {
    deviceName = 'Linux';
    deviceType = 'desktop';
  }
  
  // Add browser info
  let browser = 'Unknown Browser';
  if (/Chrome/i.test(userAgent) && !/Edge/i.test(userAgent)) {
    browser = 'Chrome';
  } else if (/Firefox/i.test(userAgent)) {
    browser = 'Firefox';
  } else if (/Safari/i.test(userAgent) && !/Chrome/i.test(userAgent)) {
    browser = 'Safari';
  } else if (/Edge/i.test(userAgent)) {
    browser = 'Edge';
  }
  
  return {
    name: `${deviceName} (${browser})`,
    type: deviceType,
    browser: browser,
    userAgent: userAgent
  };
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

    // Hash the password before storing
    const saltRounds = 12; // Recommended: 10-12 rounds
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create new user
    const newUser = new User({
      firstname,
      lastname,
      username,
      userId,
      password: hashedPassword, // ← Store hashed password
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

    // Compare password with hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
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
        id: cred.credentialID.toString('base64url'),
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
    const { username, credential, deviceInfo } = req.body; // deviceInfo from frontend
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
      
      // Handle credential ID conversion
      let credentialID, credentialPublicKey;

      if (typeof registrationInfo.credentialID === 'string') {
        credentialID = Buffer.from(registrationInfo.credentialID, 'base64url');
      } else {
        credentialID = Buffer.from(registrationInfo.credentialID);
      }

      if (registrationInfo.credentialPublicKey instanceof Uint8Array) {
        credentialPublicKey = Buffer.from(registrationInfo.credentialPublicKey);
      } else {
        credentialPublicKey = Buffer.from(registrationInfo.credentialPublicKey);
      }

      // Check if this credential already exists
      const existingCredential = user.credentials.find(cred => 
        cred.credentialID.equals(credentialID)
      );

      if (existingCredential) {
        return res.status(400).json({ 
          success: false, 
          message: "This device is already registered" 
        });
      }

      // Auto-generate device name with fallback options
      let deviceName = 'Unknown Device';
      let detectedType = 'unknown';
      
      if (deviceInfo) {
        deviceName = deviceInfo.name || deviceInfo.deviceName;
        detectedType = deviceInfo.type || 'unknown';
      }
      
      // Fallback: Use authenticator attachment info
      if (!deviceInfo && credential.authenticatorAttachment) {
        if (credential.authenticatorAttachment === 'platform') {
          deviceName = 'Built-in Authenticator';
          detectedType = 'platform';
        } else if (credential.authenticatorAttachment === 'cross-platform') {
          deviceName = 'External Authenticator';
          detectedType = 'cross-platform';
        }
      }
      
      // Add device count suffix to avoid duplicates
      const deviceNumber = user.credentials.length + 1;
      if (deviceName === 'Unknown Device') {
        deviceName = `Device ${deviceNumber}`;
      }

      // Check for duplicate names and add suffix
      const existingNames = user.credentials.map(c => c.deviceName);
      let finalDeviceName = deviceName;
      let suffix = 1;
      while (existingNames.includes(finalDeviceName)) {
        finalDeviceName = `${deviceName} (${suffix})`;
        suffix++;
      }

      const newCredential = {
        credentialID: credentialID,
        credentialPublicKey: credentialPublicKey,
        counter: registrationInfo.counter,
        deviceName: finalDeviceName,
        deviceType: detectedType,
        authenticatorType: credential.authenticatorAttachment || 'unknown',
        createdAt: new Date(),
        lastUsed: null,
        // Store additional device info if provided
        ...(deviceInfo && {
          browser: deviceInfo.browser,
          userAgent: deviceInfo.userAgent
        })
      };

      user.credentials.push(newCredential);
      user.currentChallenge = null;
      await user.save();

      console.log(`Successfully registered device "${finalDeviceName}" for user ${username}`);

      res.json({
        success: true,
        message: "Biometric authentication setup successful!",
        device: {
          name: newCredential.deviceName,
          type: newCredential.deviceType,
          authenticatorType: newCredential.authenticatorType,
          credentialId: credentialID.toString('base64url')
        }
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

// Get user's registered devices with detailed info
router.get("/user/:username/devices", async (req, res) => {
  try {
    const { username } = req.params;
    
    const user = await User.findOne({ username }).select('credentials');
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: "User not found" 
      });
    }

    const devices = user.credentials.map(cred => ({
      id: cred.credentialID.toString('base64url'),
      name: cred.deviceName || 'Unknown Device',
      type: cred.deviceType || 'unknown',
      authenticatorType: cred.authenticatorType || 'unknown',
      browser: cred.browser,
      createdAt: cred.createdAt,
      lastUsed: cred.lastUsed,
      // Don't send full userAgent for privacy
      hasUserAgent: !!cred.userAgent
    }));

    res.json({
      success: true,
      devices,
      count: devices.length
    });

  } catch (error) {
    console.error("Get devices error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Internal server error" 
    });
  }
});

// Remove a specific device
router.delete("/webauthn/device/:username/:credentialId", async (req, res) => {
  try {
    const { username, credentialId } = req.params;
    
    console.log(`Attempting to delete device for user: ${username}, credentialId: ${credentialId}`);
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: "User not found" 
      });
    }

    // Convert base64url string to Buffer for comparison
    const credentialBuffer = Buffer.from(credentialId, 'base64url');
    const credentialIndex = user.credentials.findIndex(cred => 
      cred.credentialID.equals(credentialBuffer)
    );

    if (credentialIndex === -1) {
      console.log(`Device not found. Available devices:`, user.credentials.map(c => ({
        id: c.credentialID.toString('base64url'),
        name: c.deviceName
      })));
      return res.status(404).json({ 
        success: false, 
        message: "Device not found" 
      });
    }

    const removedDevice = user.credentials[credentialIndex];
    user.credentials.splice(credentialIndex, 1);
    await user.save();

    console.log(`Successfully removed device: ${removedDevice.deviceName}`);

    res.json({
      success: true,
      message: "Device removed successfully",
      removedDevice: {
        name: removedDevice.deviceName,
        type: removedDevice.deviceType
      }
    });

  } catch (error) {
    console.error("Remove device error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Failed to remove device" 
    });
  }
});

export default router;