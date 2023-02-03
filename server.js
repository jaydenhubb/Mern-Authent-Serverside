require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const userRoute = require("./Routes/userRoute");
const errorHandler = require("./Middleware/errorMiddleware");

const app = express();

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(bodyParser.json());

app.use(
  cors({
    origin: ["http://localhost:3000", "https://jay-authent.vercel.app"],
    credentials: true,
  })
);
app.use("/api/users", userRoute);

// app.get("/", (req, res) => {
//   res.send("Home Page");
// });

// Error middleware
app.use(errorHandler);

mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    app.listen(process.env.PORT, () => {
      console.log(
        "server running on port",
        process.env.PORT + " and connected to database",
      );
    });
  })
  .catch((err) => console.log(err));

// console.log(process.env.MONGO_URI);
