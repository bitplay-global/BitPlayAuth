const nodemailer = require('nodemailer');

const sendEmail = async (options) => {
  try {
    // There is deliberately no fallback password. A literal here -- twice
    // leaked into git history under two different values -- meant EMAIL_PASS
    // rotation didn't actually stop mail going out under the old password.
    if (!process.env.EMAIL_PASS) {
      console.error('[Email] EMAIL_PASS is not set -- refusing to send.');
      return { success: false, error: 'Email is not configured.' };
    }

    // Create transporter
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST || "smtp.gmail.com",
      port: process.env.EMAIL_PORT || 587,
      secure: false, // true for 465, false for other ports
      auth: {
        user: process.env.EMAIL_USER || "bitplay.global@gmail.com",
        pass: process.env.EMAIL_PASS
      }
    });

    // Define email options
    const mailOptions = {
      from: `<${process.env.EMAIL_FROM}>`,
      to: options.email,
      subject: options.subject,
      text: options.message,
      html: options.html
    };

    // Send email
    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent: ', info.messageId);
    
    return {
      success: true,
      messageId: info.messageId
    };
  } catch (error) {
    console.error('Email sending error:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

module.exports = sendEmail;
