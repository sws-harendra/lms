const nodemailer = require("nodemailer");
const fs = require("fs");
const path = require("path");
const handlebars = require("handlebars");
require("dotenv").config();

// Setup transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

/**
 * Email template map
 * key = template name
 * value = relative filename inside templates folder
 */
const templateMap = {
  verifyEmail: "verifyMail.hbs",
  feedback: "feedback.hbs",
  welcome: "welcome.hbs",
  // add more mappings as needed
};

/**
 * Sends an email using a Handlebars template
 * @param {string} to - Recipient's email
 * @param {string} subject - Email subject
 * @param {string} templateName - Name of the template to use (from templateMap)
 * @param {Object} templateData - Data to inject into the template
 */
const sendMail = async (to, subject, templateName, templateData = {}) => {
  try {
    const templateFile = templateMap[templateName];
    if (!templateFile) {
      throw new Error(`Template '${templateName}' not found in templateMap`);
    }

    const templatePath = path.join(__dirname, "../templates", templateFile);
    const source = fs.readFileSync(templatePath, "utf8");
    const compiledTemplate = handlebars.compile(source);
    const html = compiledTemplate(templateData);

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to,
      subject,
      html,
    };

    await transporter.sendMail(mailOptions);
    console.log(`Email sent to ${to} using template: ${templateName}`);
    return true;
  } catch (error) {
    console.error("Error sending email:", error);
    throw new Error("Email could not be sent");
  }
};

module.exports = sendMail;
