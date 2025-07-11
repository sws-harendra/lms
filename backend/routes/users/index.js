const express = require("express");
const router = express.Router();
router.use("/", require("../users/auth.route")); // /api/user/login

module.exports = router;
