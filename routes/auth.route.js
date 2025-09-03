import express from "express";
import * as authController from "../controller/auth.controller.js";

const router = express.Router();

// ========== TRADITIONAL AUTHENTICATION ==========
router.post("/signup", authController.signup);
router.post("/login", authController.login);

// ========== WEBAUTHN/BIOMETRIC AUTHENTICATION ==========
router.post("/webauthn/register/begin", authController.webAuthnRegisterBegin);
router.post("/webauthn/register/finish", authController.webAuthnRegisterFinish);
router.post("/webauthn/authenticate/begin", authController.webAuthnAuthenticateBegin);
router.post("/webauthn/authenticate/finish", authController.webAuthnAuthenticateFinish);

// ========== USER & DEVICE MANAGEMENT ==========
router.get("/user/:username", authController.getUserInfo);
router.get("/user/:username/devices", authController.getUserDevices);
router.delete("/webauthn/device/:username/:credentialId", authController.removeDevice);
// Add this line to your routes
router.get("/test-suspicious-login/:username", authController.testSuspiciousLogin);
router.get("/test-email/:username", authController.testEmailService);
export default router;