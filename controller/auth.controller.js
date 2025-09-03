import User from "../models/User.model.js";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import { sendSuspiciousLoginAlert } from '../utils/emailService.js';
import { getLocationFromIP } from '../utils/ipService.js';
import { isTravelPlausible } from '../utils/securityUtils.js';

// Constants
const rpName = 'Biometric Auth App';

// Helper function to get current domain configuration
export const getDomainConfig = (req) => {
  const origin = req.headers.origin || req.headers.referer || '';
  
  if (origin.includes('biometricauth-frontend.vercel.app')) {
    return {
      rpID: 'biometricauth-frontend.vercel.app',
      expectedOrigin: 'https://biometricauth-frontend.vercel.app'
    };
  } else if (origin.includes('railway.app')) {
    return {
      rpID: 'biometricauth-backend-production.up.railway.app',
      expectedOrigin: 'https://biometricauth-backend-production.up.railway.app'
    };
  } else {
    return {
      rpID: 'localhost',
      expectedOrigin: 'http://localhost:5173'
    };
  }
};

// Helper function to detect device info
export const getDeviceInfo = () => {
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

// ========== TRADITIONAL AUTHENTICATION CONTROLLERS ==========

// Traditional Signup
// In the signup function
export const signup = async (req, res) => {
  try {
    const { firstname, lastname, username, password, email } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        message: "Username already exists" 
      });
    }
    
    // Check if email already exists
    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({ 
        success: false, 
        message: "Email already in use" 
      });
    }
    
    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid email format" 
      });
    }

    // Generate unique userId for WebAuthn
    const userId = crypto.randomUUID();

    // Hash the password before storing
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create new user
    const newUser = new User({
      firstname,
      lastname,
      username,
      email,  // Store the email
      userId,
      password: hashedPassword,
      credentials: [],
      currentChallenge: null,
      knownIPs: []  // Initialize empty known IPs array
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
        email: newUser.email,
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
};

// Traditional Login
export const login = async (req, res) => {
  try {
      const { username, password, browserLocation } = req.body;
    
    // Get client IP address
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'];
    
    // Extract device info from user agent
    const deviceInfo = extractDeviceInfo(userAgent);

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

    // Get location data - prioritize browser location if available
    let locationInfo = null;
    let ipLocationInfo = null;
    
    // Get IP-based location as fallback
    try {
      ipLocationInfo = await getLocationFromIP(ip);
    } catch (err) {
      console.error('Failed to get location from IP:', err);
    }
    
    // Use browser location if available, otherwise use IP location
    locationInfo = browserLocation || ipLocationInfo;
    
    console.log('Using location data:', {
      fromBrowser: !!browserLocation,
      fromIP: !!ipLocationInfo,
      final: locationInfo
    });

    let isSuspiciousLogin = false;
    let travelAlert = false;
    let travelDetails = null;
    
   
    
    const currentTime = new Date();
    
    // Check if this is a new IP address
const knownIP = user.knownIPs.find(knownIP => knownIP.ip === ip);

// Always check travel plausibility regardless of known IP
if (user.lastLogin?.date && user.lastLogin?.location?.latitude && locationInfo) {
  const travelPlausibility = isTravelPlausible(
    user.lastLogin.location,
    {
      latitude: locationInfo.latitude || 0,
      longitude: locationInfo.longitude || 0
    },
    new Date(user.lastLogin.date),
    currentTime
  );
  
  if (!travelPlausibility.plausible) {
    travelAlert = true;
    travelDetails = travelPlausibility;
    console.log(`SECURITY ALERT: Impossible travel detected for user ${username}`);
  }
}

// Then handle the IP based on whether it's known
if (!knownIP) {
  // This is a new IP - flag as suspicious and add to known IPs
  isSuspiciousLogin = true;
  
  user.knownIPs.push({
    ip,
    firstSeen: currentTime,
    lastSeen: currentTime,
    location: locationInfo ? {
      city: locationInfo.city,
      region: locationInfo.region,
      country_name: locationInfo.country_name,
      latitude: locationInfo.latitude,
      longitude: locationInfo.longitude
    } : null
  });
} else {
      // Update last seen timestamp for this IP
      knownIP.lastSeen = currentTime;
    }
    
    // Update last login info with detailed location
    user.lastLogin = {
      date: currentTime,
      ip,
      userAgent,
      device: deviceInfo.name,
      location: locationInfo ? {
        city: locationInfo.city,
        region: locationInfo.region,
        country: locationInfo.country_name,
        latitude: locationInfo.latitude,
        longitude: locationInfo.longitude
      } : null
    };
    
    await user.save();
    
    // If suspicious login detected, send email alert
    if (isSuspiciousLogin || travelAlert) {
      const location = locationInfo ? 
        `${locationInfo.city}, ${locationInfo.region}, ${locationInfo.country_name}` : 
        'Unknown location';
      
      // Include travel alert info if applicable
      const alertInfo = {
        ip,
        location,
        device: deviceInfo.name,
        browser: deviceInfo.browser,
        date: currentTime,
    impossibleTravel: travelAlert ? {
  previousLocation: `${user.lastLogin.location.city}, ${user.lastLogin.location.country_name}`, // Fixed: was "country"
  distance: travelDetails?.distance.toFixed(0) + " km",
  timeElapsed: travelDetails?.timeElapsed.toFixed(1) + " hours",
  requiredSpeed: travelDetails?.requiredSpeed.toFixed(0) + " km/h"
} : null
      };
      
      // Send alert email asynchronously (don't await)
sendSuspiciousLoginAlert(user, alertInfo)
  .then(result => console.log(`Email alert ${result ? 'sent successfully' : 'failed'} to ${user.email}`))
  .catch(err => console.error('Error sending security alert:', err));
    }

    res.json({
      success: true,
      message: "Login successful",
      user: {
        id: user._id,
        username: user.username,
        firstname: user.firstname,
        lastname: user.lastname,
        email: user.email,
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
};

// Helper function to extract device info from user agent
const extractDeviceInfo = (userAgent) => {
  let deviceName = 'Unknown Device';
  let deviceType = 'unknown';
  let browser = 'Unknown Browser';
  
  if (!userAgent) return { name: deviceName, type: deviceType, browser };
  
  // Detect OS
  if (/iPhone|iPad|iPod/i.test(userAgent)) {
    deviceName = /iPad/i.test(userAgent) ? 'iPad' : 'iPhone';
    deviceType = 'mobile';
  } else if (/Android/i.test(userAgent)) {
    deviceName = 'Android Device';
    deviceType = 'mobile';
  } else if (/Windows/i.test(userAgent)) {
    deviceName = 'Windows Device';
    deviceType = 'desktop';
  } else if (/Mac/i.test(userAgent)) {
    deviceName = 'Mac Device';
    deviceType = 'desktop';
  } else if (/Linux/i.test(userAgent)) {
    deviceName = 'Linux Device';
    deviceType = 'desktop';
  }
  
  // Detect browser
  if (/Chrome/i.test(userAgent) && !/Edg|Edge/i.test(userAgent)) {
    browser = 'Chrome';
  } else if (/Firefox/i.test(userAgent)) {
    browser = 'Firefox';
  } else if (/Safari/i.test(userAgent) && !/Chrome/i.test(userAgent)) {
    browser = 'Safari';
  } else if (/Edg|Edge/i.test(userAgent)) {
    browser = 'Edge';
  }
  
  return {
    name: `${deviceName} (${browser})`,
    type: deviceType,
    browser
  };
};

// ========== WEBAUTHN/BIOMETRIC AUTHENTICATION CONTROLLERS ==========

// Generate registration options for biometric setup
export const webAuthnRegisterBegin = async (req, res) => {
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
};

export const webAuthnRegisterFinish = async (req, res) => {
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
};

export const webAuthnAuthenticateBegin = async (req, res) => {
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
};

// In the webAuthnAuthenticateFinish function
// In the webAuthnAuthenticateFinish function
export const webAuthnAuthenticateFinish = async (req, res) => {
  try {
    const { username, credential, browserLocation } = req.body;
    const { rpID, expectedOrigin } = getDomainConfig(req);
    
    // Get client IP address
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'];
    
    // Extract device info from user agent
    const deviceInfo = extractDeviceInfo(userAgent);

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
      userCredential.lastUsed = new Date();
      
      // Get location data - prioritize browser location if available
      let locationInfo = null;
      let ipLocationInfo = null;
      
      // Get IP-based location as fallback
      try {
        ipLocationInfo = await getLocationFromIP(ip);
      } catch (err) {
        console.error('Failed to get location from IP:', err);
      }
      
      // Use browser location if available, otherwise use IP location
      locationInfo = browserLocation || ipLocationInfo;
      
      console.log('Using location data:', {
        fromBrowser: !!browserLocation,
        fromIP: !!ipLocationInfo,
        final: locationInfo
      });

      let isSuspiciousLogin = false;
      let travelAlert = false;
      let travelDetails = null;
      
      const currentTime = new Date();
      
      // Check if this is a new IP address
      const knownIP = user.knownIPs.find(knownIP => knownIP.ip === ip);
      
      if (!knownIP) {
        // This is a new IP address - flag as potentially suspicious
        isSuspiciousLogin = true;
        
        // Check if travel is plausible if we have previous login data
// In the webAuthnAuthenticateFinish function, uncomment these lines:
if (user.lastLogin?.date && user.lastLogin?.location?.latitude && locationInfo) {
  // FORCE SHORT TIME DIFFERENCE FOR TESTING
  const fakeLastLoginTime = new Date();
  fakeLastLoginTime.setMinutes(fakeLastLoginTime.getMinutes() - 5); // Only 5 minutes ago
  
  const travelPlausibility = isTravelPlausible(
    user.lastLogin.location,
    {
      latitude: locationInfo.latitude || 0,
      longitude: locationInfo.longitude || 0
    },
    fakeLastLoginTime, // Use fake time instead of actual login time
    currentTime
  );
  
  console.log("Travel plausibility check:", {
    from: `${user.lastLogin.location.city}, ${user.lastLogin.location.country_name}`,
    to: `${locationInfo.city}, ${locationInfo.country_name}`,
    distance: travelPlausibility.distance,
    timeElapsed: travelPlausibility.timeElapsed,
    requiredSpeed: travelPlausibility.requiredSpeed,
    plausible: travelPlausibility.plausible
  });
  
  if (!travelPlausibility.plausible) {
    travelAlert = true;
    travelDetails = travelPlausibility;
    console.log(`SECURITY ALERT: Impossible travel detected for user ${username}`);
    console.log(travelPlausibility);
  }
}
        
        // Add this IP to known IPs with location data
        user.knownIPs.push({
          ip,
          firstSeen: currentTime,
          lastSeen: currentTime,
          location: locationInfo ? {
            city: locationInfo.city,
            region: locationInfo.region,
            country: locationInfo.country_name,
            latitude: locationInfo.latitude,
            longitude: locationInfo.longitude
          } : null
        });
      } else {
        // Update last seen timestamp for this IP
        knownIP.lastSeen = currentTime;
      }
      
      // Update last login info with detailed location
      user.lastLogin = {
        date: currentTime,
        ip,
        userAgent,
        device: deviceInfo.name,
        location: locationInfo ? {
          city: locationInfo.city,
          region: locationInfo.region,
          country: locationInfo.country_name,
          latitude: locationInfo.latitude,
          longitude: locationInfo.longitude
        } : null
      };
      
      user.currentChallenge = null;
      await user.save();
      
      // If suspicious login detected, send email alert
      if (isSuspiciousLogin || travelAlert) {
        const location = locationInfo ? 
          `${locationInfo.city}, ${locationInfo.region}, ${locationInfo.country_name}` : 
          'Unknown location';
        
        // Include travel alert info if applicable
        const alertInfo = {
          ip,
          location,
          device: deviceInfo.name,
          browser: deviceInfo.browser,
          date: currentTime,
       impossibleTravel: travelAlert ? {
  previousLocation: `${user.lastLogin.location.city}, ${user.lastLogin.location.country_name}`, // Fixed: was "country"
  distance: travelDetails?.distance.toFixed(0) + " km",
  timeElapsed: travelDetails?.timeElapsed.toFixed(1) + " hours",
  requiredSpeed: travelDetails?.requiredSpeed.toFixed(0) + " km/h"
} : null
        };
        
        // Send alert email asynchronously (don't await)
   sendSuspiciousLoginAlert(user, alertInfo)
  .then(result => console.log(`Email alert ${result ? 'sent successfully' : 'failed'} to ${user.email}`))
  .catch(err => console.error('Error sending security alert:', err));
      }

      res.json({
        success: true,
        message: "Biometric authentication successful!",
        user: {
          id: user._id,
          username: user.username,
          firstname: user.firstname,
          lastname: user.lastname,
          email: user.email
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
};

// Get user info
export const getUserInfo = async (req, res) => {
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
};

// Get user's registered devices
export const getUserDevices = async (req, res) => {
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
};

// Remove a specific device
export const removeDevice = async (req, res) => {
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
};

// Add this new testing endpoint
export const testSuspiciousLogin = async (req, res) => {
  try {
    const { username } = req.params;
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: "User not found" 
      });
    }
    
    // Create a simulated suspicious login
    const alertInfo = {
      ip: '192.168.1.1',
      location: 'New York, NY, United States',
      device: 'Unknown Device',
      browser: 'Chrome',
      date: new Date(),
      impossibleTravel: {
        previousLocation: 'Tokyo, Japan',
        distance: '10,934 km',
        timeElapsed: '2.5 hours',
        requiredSpeed: '4,373 km/h'
      }
    };
    
    // Send test email alert
    const emailResult = await sendSuspiciousLoginAlert(user, alertInfo);
    
    res.json({
      success: true,
      message: `Test suspicious login alert ${emailResult ? 'sent' : 'failed'}`,
      emailSent: emailResult,
      sentTo: user.email
    });
    
  } catch (error) {
    console.error("Test suspicious login error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Failed to send test alert" 
    });
  }
};


// Add this to controller/auth.controller.js
export const testEmailService = async (req, res) => {
  try {
    const { username } = req.params;
    
    console.log(`🔍 TEST EMAIL REQUEST for user: ${username}`);
    
    const user = await User.findOne({ username });
    if (!user) {
      console.log(`❌ User not found: ${username}`);
      return res.status(404).json({ 
        success: false, 
        message: "User not found" 
      });
    }
    
    console.log(`✓ User found: ${username} (${user.email})`);
    
    // Create a simple test email
    const testInfo = {
      ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
      location: 'Test Location',
      device: 'Test Device',
      browser: 'Test Browser',
      date: new Date(),
      impossibleTravel: {
        previousLocation: 'Test Previous Location',
        distance: '1000 km',
        timeElapsed: '1 hour',
        requiredSpeed: '1000 km/h'
      }
    };
    
    console.log('⌛ Calling email service...');
    
    const emailResult = await sendSuspiciousLoginAlert(user, testInfo);
    
    console.log(`📧 Email test result: ${emailResult ? 'SUCCESS' : 'FAILED'}`);
    
    return res.json({
      success: true,
      message: `Test email ${emailResult ? 'sent' : 'failed'}`,
      emailSent: emailResult,
      sentTo: user.email,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ TEST EMAIL ERROR:', error);
    return res.status(500).json({
      success: false,
      message: "Test email failed",
      error: error.message
    });
  }
};