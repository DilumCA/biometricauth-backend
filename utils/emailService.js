import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config();

// Hard-code the email user but use environment variable for password
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASSWORD;

console.log('Email configuration:', {
  user: EMAIL_USER,
  passwordLength: EMAIL_PASS ? EMAIL_PASS.length : 0,
  // Check if .env variables are loading at all
  nodeEnv: process.env.NODE_ENV
});

// Create the transporter with direct options rather than using service
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS
  }
});


// Test the connection
transporter.verify(function(error, success) {
  if (error) {
    console.log('Email server connection error:', error);
  } else {
    console.log('Email server connection verified - ready to send messages');
  }
});


export const sendSuspiciousLoginAlert = async (user, loginInfo) => {
try {
  console.log("DEBUG - Email Alert Triggered:");
    console.log("- User email:", user.email);
    console.log("- Alert type:", loginInfo.impossibleTravel ? "Impossible Travel" : "New IP");
    console.log("- From location:", loginInfo.impossibleTravel?.previousLocation);
    console.log("- To location:", loginInfo.location);
    
    const { email, firstname, lastname } = user;
    const { ip, location, device, browser, date, impossibleTravel } = loginInfo;
    
    let travelWarningHtml = '';
    
    // Add impossible travel warning if applicable
    if (impossibleTravel) {
      travelWarningHtml = `
        <div style="background-color: #FFEBEE; border-left: 4px solid #F44336; padding: 15px; margin: 20px 0;">
          <h3 style="color: #D32F2F; margin-top: 0;">⚠️ Suspicious Travel Pattern Detected!</h3>
          <p>This login occurred from a location that would be <strong>physically impossible</strong> to reach in the time since your last login:</p>
          <ul>
            <li>Previous location: ${impossibleTravel.previousLocation}</li>
            <li>Distance: ${impossibleTravel.distance}</li>
            <li>Time between logins: ${impossibleTravel.timeElapsed}</li>
            <li>Required travel speed: ${impossibleTravel.requiredSpeed}</li>
          </ul>
          <p><strong>If this wasn't you, your account may be compromised.</strong></p>
        </div>
      `;
    }
    
    const mailOptions = {
      from: `"Biometric Auth Security" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: impossibleTravel ? 
        '🚨 URGENT SECURITY ALERT: Suspicious Login Detected' : 
        'Security Alert: New Login Detected',
      html: `
        <h2>Hello ${firstname} ${lastname},</h2>
        <p>We detected a new login to your Biometric Auth account.</p>
        ${travelWarningHtml}
        <h3>Login Details:</h3>
        <ul>
          <li><strong>Time:</strong> ${new Date(date).toLocaleString()}</li>
          <li><strong>IP Address:</strong> ${ip}</li>
          ${location ? `<li><strong>Location:</strong> ${location}</li>` : ''}
          <li><strong>Device:</strong> ${device}</li>
          <li><strong>Browser:</strong> ${browser}</li>
        </ul>
        <p>If this was you, you can ignore this email.</p>
        <p>If you don't recognize this activity, please:</p>
        <ol>
          <li>Change your password immediately</li>
          <li>Enable biometric authentication if not already done</li>
          <li>Contact support if you need assistance securing your account</li>
        </ol>
        <p>Thank you,<br>The Biometric Auth Security Team</p>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log(`Security alert email sent to ${email}`);
    return true;
  } catch (error) {
    console.error('Failed to send security alert email:', error);
    return false;
  }
};