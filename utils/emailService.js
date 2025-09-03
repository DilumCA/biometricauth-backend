import SibApiV3Sdk from 'sib-api-v3-sdk';
import dotenv from 'dotenv';
dotenv.config();

// Configure Brevo API client
const apiKey = process.env.BREVO_API_KEY;
const EMAIL_USER = process.env.EMAIL_USER ;

// Set up the API client
const defaultClient = SibApiV3Sdk.ApiClient.instance;
const apiKeyAuth = defaultClient.authentications['api-key'];
apiKeyAuth.apiKey = apiKey;

// Create API instance
const apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();

// More detailed startup logging
console.log('====== EMAIL SERVICE CONFIGURATION ======');
console.log('- Email Service: Brevo API');
console.log('- From Email:', EMAIL_USER);
console.log('- API Key Set:', !!apiKey);
console.log('- API Key Length:', apiKey ? apiKey.length : 0);
console.log('- Node Environment:', process.env.NODE_ENV);
console.log('========================================');

// Test the connection on startup
const testConnection = async () => {
  try {
    console.log('⌛ Testing Brevo API connection...');
    
    // There's no direct "verify" method, but we can check if the API key is valid
    if (apiKey && apiKey.startsWith('xkeysib-')) {
      console.log('✅ BREVO API CONFIGURED - Ready to send messages');
    } else {
      console.log('❌ BREVO API CONFIGURATION ERROR: Invalid API key format');
    }
  } catch (error) {
    console.log('❌ BREVO API CONFIGURATION ERROR:');
    console.log('- Error Name:', error.name);
    console.log('- Error Message:', error.message);
  }
};

// Run the connection test
testConnection();

/**
 * Send a suspicious login alert email to a user
 * @param {Object} user - The user object with email, firstname, lastname
 * @param {Object} loginInfo - Information about the suspicious login
 * @returns {Promise<boolean>} - Whether the email was sent successfully
 */
export const sendSuspiciousLoginAlert = async (user, loginInfo) => {
  try {
    console.log("📧 STARTING EMAIL SEND PROCESS");
    console.log("- User email:", user.email);
    console.log("- Alert type:", loginInfo.impossibleTravel ? "Impossible Travel" : "New IP");
    console.log("- To location:", loginInfo.location);
    
    const { email, firstname, lastname } = user;
    const { ip, location, device, browser, date, impossibleTravel } = loginInfo;
    
    let travelWarningHtml = '';
    
    if (impossibleTravel) {
      console.log('- Travel Details:');
      console.log('  - Previous Location:', impossibleTravel.previousLocation);
      console.log('  - Distance:', impossibleTravel.distance);
      console.log('  - Time Elapsed:', impossibleTravel.timeElapsed);
      console.log('  - Required Speed:', impossibleTravel.requiredSpeed);
      
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
    
    console.log('⌛ Preparing email content...');
    
    const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
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
      </div>
    `;
    
    // Create an email object for Brevo
    const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
    
    sendSmtpEmail.sender = {
      name: 'Biometric Auth Security',
      email: EMAIL_USER
    };
    
    sendSmtpEmail.to = [{
      email: email,
      name: `${firstname} ${lastname}`
    }];
    
    sendSmtpEmail.subject = impossibleTravel ? 
      '🚨 URGENT SECURITY ALERT: Suspicious Login Detected' : 
      'Security Alert: New Login Detected';
    
    sendSmtpEmail.htmlContent = htmlContent;
    
    // Log mail options (redact sensitive parts)
    console.log('✉️ Mail options prepared:');
    console.log('- From:', `Biometric Auth Security <${EMAIL_USER}>`);
    console.log('- To:', email);
    console.log('- Subject:', sendSmtpEmail.subject);
    console.log('- HTML Length:', htmlContent.length);
    
    console.log('⌛ Attempting to send email via Brevo API...');
    
    // Send the email with Brevo
    const result = await apiInstance.sendTransacEmail(sendSmtpEmail);
    
    console.log('✅ EMAIL SENT SUCCESSFULLY:');
    console.log('- Message ID:', result.messageId);
    
    return true;
  } catch (error) {
    console.error('❌ EMAIL SEND FAILURE:');
    console.error('- Error Name:', error.name);
    console.error('- Error Message:', error.message);
    
    // Detailed API error information if available
    if (error.response) {
      console.error('- Status Code:', error.response.statusCode);
      console.error('- Response Body:', JSON.stringify(error.response.body, null, 2));
    }
    
    return false;
  }
};

/**
 * Send a test email to verify email configuration
 * @param {string} toEmail - Email address to send test to
 * @returns {Promise<boolean>} - Whether the email was sent successfully
 */
export const sendTestEmail = async (toEmail) => {
  try {
    console.log(`⌛ Sending test email to ${toEmail}...`);
    
    // Create an email object for Brevo
    const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
    
    sendSmtpEmail.sender = {
      name: 'Biometric Auth Test',
      email: EMAIL_USER
    };
    
    sendSmtpEmail.to = [{
      email: toEmail
    }];
    
    sendSmtpEmail.subject = 'Email Configuration Test';
    
    sendSmtpEmail.htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Email Configuration Test</h2>
        <p>This is a test email to verify that your email configuration is working correctly.</p>
        <p>If you received this email, your email service is configured correctly!</p>
        <p>Sent at: ${new Date().toLocaleString()}</p>
      </div>
    `;
    
    const result = await apiInstance.sendTransacEmail(sendSmtpEmail);
    console.log('✅ TEST EMAIL SENT SUCCESSFULLY:', result.messageId);
    return true;
  } catch (error) {
    console.error('❌ TEST EMAIL FAILED:', error);
    
    // Detailed API error information if available
    if (error.response) {
      console.error('- Status Code:', error.response.statusCode);
      console.error('- Response Body:', JSON.stringify(error.response.body, null, 2));
    }
    
    return false;
  }
};