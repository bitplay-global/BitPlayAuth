const nodemailer = require('nodemailer');

const sendEmail = async (options) => {
  try {

    // console.log("SMTPDetails");
    // console.log("USER: ", process.env.EMAIL_USER);
    // console.log("UserPassword: ", process.env.EMAIL_PASS);

    // Create transporter
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST || "smtp.gmail.com",
      port: process.env.EMAIL_PORT || 587,
      secure: false, // true for 465, false for other ports
      auth: {
        user: process.env.EMAIL_USER || "bitplay.global@gmail.com",
        pass: process.env.EMAIL_PASS || "elwtmfjrhgchbkpf"
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
