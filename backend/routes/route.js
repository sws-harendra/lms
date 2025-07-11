const express = require("express");
const router = express.Router();
router.use("/user", require("./users/index")); // /api/user/login
// router.use("/instructor", require("./instructor/auth.route")); // /api/instructor/login
// router.use("/admin", require("./admin/dashboard.route")); // /api/admin/...

module.exports = router;
