const express = require("express");
const router = express.Router();
const auth = require("../../controllers/users/auth.controller");
const { authenticateToken } = require("../../middlewares/user.auth");

router.post("/loginwithemail", auth.emailloginController);

router.post("/registerwithemail", auth.emailsignup);
router.post("/verifyEmail", auth.verifyEmail);
router.post("/sendEmailForVerification", auth.resendEmailVerification);
router.post("/resendOtp", auth.resendOtpToPhone);
router.post("/userdetails", authenticateToken, auth.userdetail);

module.exports = router;
