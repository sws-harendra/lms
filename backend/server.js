require("dotenv").config();
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");

const routes = require("./routes/route");

const express = require("express");
const cors = require("cors");
const app = express();

app.use(cors());
app.use(express.json());
app.use(cookieParser());
const mongoURI = process.env.MONGO_URI;

mongoose
  .connect(mongoURI)
  .then(() => {
    console.log("✅ MongoDB connected to local instance.");
  })
  .catch((error) => {
    console.error("❌ Connection error:", error.message);
  });

// all routs in route folder
app.use("/api", routes); // All routes prefixed with /api

app.get("/", (req, res) => {
  res.json("hello from backend");
});

let port = process.env.PORT || 8000;
app.listen(port, () => {
  console.log(`Server is running on ${port}`);
});

module.exports = app;
