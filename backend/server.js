require("dotenv").config();
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const morgan = require("morgan");

const routes = require("./routes/route");
const seedSettings = require("./config/seedSettings");

const express = require("express");
const cors = require("cors");
const seedRoles = require("./config/seedRole");
const seedCourseCategory = require("./config/seedCategory");
const app = express();
const path = require("path");
app.use(
  cors({
    origin: process.env.CLIENT_URL, // or your frontend URL
    credentials: true, // allow sending cookies/headers
  })
);
app.use(express.json());
app.use(cookieParser());
const mongoURI = process.env.MONGO_URI;

mongoose
  .connect(mongoURI)
  .then(() => {
    // seedRoles();
    seedCourseCategory();
    seedSettings();

    console.log("✅ MongoDB connected to local instance.");
  })
  .catch((error) => {
    console.error("❌ Connection error:", error.message);
  });

//run this for the first time to seed roles and permissions
app.use(morgan("dev")); // Shows :method :url :status :response-time ms

// all routs in route folder
app.use("/api", routes); // All routes prefixed with /api
app.use("/api/uploads", express.static(path.join(__dirname, "uploads")));

app.get("/", (req, res) => {
  res.json("hello from lms backend");
});

let port = process.env.PORT || 8000;
app.listen(port, () => {
  console.log(`Server is running on ${port}`);
});

module.exports = app;
