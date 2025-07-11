const sendOtp = async (phone, otp) => {
  // Send OTP using SMS gateway
  console.log(`Sending OTP ${otp} to ${phone}`);
  // e.g., await twilio.messages.create({ to: phone, body: `Your OTP: ${otp}` });
};

moodule.exports = { sendOtp };
