import User from "../models/User.model.js";
import { ethers } from "ethers";
import crypto from 'crypto';

// Generate a nonce (challenge) for the wallet to sign
export const walletAuthBegin = async (req, res) => {
  try {
    const { address } = req.body;
    
    if (!address || !ethers.isAddress(address)) {
      return res.status(400).json({
        success: false,
        message: "Invalid wallet address"
      });
    }
    
    // Create a random nonce/challenge
    const nonce = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes expiry
    
    // Check if user with this wallet exists
    let user = await User.findOne({ 'wallets.address': address.toLowerCase() });
    
    if (user) {
      // Update existing user's challenge
      user.walletChallenge = { nonce, expires };
      await user.save();
      
      return res.json({
        success: true,
        message: "Sign this message to authenticate",
        challenge: {
          nonce,
          message: `Sign this unique message to authenticate with Biometric Auth App: ${nonce}`
        },
        isRegistered: true,
        username: user.username
      });
    }
    
    // This is a new wallet address
    return res.json({
      success: true,
      message: "New wallet detected. Sign to register or link to existing account",
      challenge: {
        nonce,
        message: `Sign this unique message to register with Biometric Auth App: ${nonce}`
      },
      isRegistered: false
    });
  } catch (error) {
    console.error("Wallet auth begin error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Failed to generate challenge" 
    });
  }
};

// Verify a signed message and authenticate/register the user
export const walletAuthFinish = async (req, res) => {
  try {
    const { address, signature, nonce, username, isNewAccount, accountDetails } = req.body;
    
    if (!address || !signature || !nonce) {
      return res.status(400).json({
        success: false,
        message: "Missing required fields"
      });
    }
    
    // Verify wallet address format
    if (!ethers.isAddress(address)) {
      return res.status(400).json({
        success: false,
        message: "Invalid wallet address"
      });
    }
    
    const normalizedAddress = address.toLowerCase();
    
    // Find existing user with this wallet
    let user = await User.findOne({ 'wallets.address': normalizedAddress });
    
    // Check for existing username if trying to create new account
    if (isNewAccount && username) {
      const existingUser = await User.findOne({ username });
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: "Username already exists"
        });
      }
    }
    
    // Verify the signature
    try {
      const message = `Sign this unique message to ${user ? 'authenticate with' : 'register with'} Biometric Auth App: ${nonce}`;
      const recoveredAddress = ethers.verifyMessage(message, signature);
      
      if (recoveredAddress.toLowerCase() !== normalizedAddress) {
        return res.status(401).json({
          success: false,
          message: "Invalid signature"
        });
      }
    } catch (error) {
      return res.status(401).json({
        success: false,
        message: "Signature verification failed"
      });
    }
    
    // Handle authentication based on whether user exists
    if (user) {
      // Existing user - update wallet info
      const walletIndex = user.wallets.findIndex(w => w.address === normalizedAddress);
      if (walletIndex >= 0) {
        user.wallets[walletIndex].lastUsed = new Date();
      }
      
      user.walletChallenge = null; // Clear the challenge
      await user.save();
      
      return res.json({
        success: true,
        message: "Authentication successful",
        user: {
          id: user._id,
          username: user.username,
          firstname: user.firstname,
          lastname: user.lastname,
          email: user.email,
          walletAddress: normalizedAddress
        }
      });
    } else {
      // New user or link to existing account
      if (!username) {
        return res.status(400).json({
          success: false,
          message: "Username required for new account or linking"
        });
      }
      
      // Check if username exists for linking to existing account
      user = await User.findOne({ username });
      
      if (user) {
        // Link wallet to existing account
        user.wallets.push({
          address: normalizedAddress,
          chain: 'ethereum',
          firstUsed: new Date(),
          lastUsed: new Date()
        });
        
        user.walletChallenge = null;
        await user.save();
        
        return res.json({
          success: true,
          message: "Wallet linked to existing account",
          user: {
            id: user._id,
            username: user.username,
            firstname: user.firstname,
            lastname: user.lastname,
            email: user.email,
            walletAddress: normalizedAddress
          }
        });
      } else if (isNewAccount && accountDetails) {
        // Create new account with wallet
        const { firstname, lastname, email } = accountDetails;
        
        // Validate required fields
        if (!firstname || !lastname || !email) {
          return res.status(400).json({
            success: false,
            message: "Missing required account details"
          });
        }
        
        // Create a unique userId for WebAuthn
        const userId = crypto.randomUUID();
        
        // Create new user
        const newUser = new User({
          firstname,
          lastname,
          username,
          email,
          userId,
          credentials: [],
          currentChallenge: null,
          knownIPs: [],
          wallets: [{
            address: normalizedAddress,
            chain: 'ethereum',
            firstUsed: new Date(),
            lastUsed: new Date()
          }]
        });
        
        await newUser.save();
        
        return res.status(201).json({
          success: true,
          message: "Account created with wallet",
          user: {
            id: newUser._id,
            username: newUser.username,
            firstname: newUser.firstname,
            lastname: newUser.lastname,
            email: newUser.email,
            walletAddress: normalizedAddress
          }
        });
      } else {
        return res.status(400).json({
          success: false,
          message: "Account details required for new account"
        });
      }
    }
  } catch (error) {
    console.error("Wallet auth finish error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Authentication failed" 
    });
  }
};

// Get user's linked wallets
export const getUserWallets = async (req, res) => {
  try {
    const { username } = req.params;
    
    const user = await User.findOne({ username }).select('wallets');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }
    
    const wallets = user.wallets.map(wallet => ({
      address: wallet.address,
      chain: wallet.chain,
      firstUsed: wallet.firstUsed,
      lastUsed: wallet.lastUsed
    }));
    
    return res.json({
      success: true,
      wallets,
      count: wallets.length
    });
  } catch (error) {
    console.error("Get user wallets error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to retrieve wallets"
    });
  }
};

// Remove a wallet from user account
export const removeWallet = async (req, res) => {
  try {
    const { username, address } = req.params;
    
    if (!ethers.isAddress(address)) {
      return res.status(400).json({
        success: false,
        message: "Invalid wallet address"
      });
    }
    
    const normalizedAddress = address.toLowerCase();
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }
    
    const walletIndex = user.wallets.findIndex(w => w.address === normalizedAddress);
    if (walletIndex === -1) {
      return res.status(404).json({
        success: false,
        message: "Wallet not found for this user"
      });
    }
    
    const removedWallet = user.wallets[walletIndex];
    user.wallets.splice(walletIndex, 1);
    await user.save();
    
    return res.json({
      success: true,
      message: "Wallet removed successfully",
      removed: {
        address: removedWallet.address,
        chain: removedWallet.chain
      }
    });
  } catch (error) {
    console.error("Remove wallet error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to remove wallet"
    });
  }
};