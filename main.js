require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");

const { userRouter } = require("./routes/user");
const { adminRouter } = require("./routes/admin");
const { courseRouter } = require("./routes/courses");

const app = express();
app.use(express.json());

app.use("/api/v1/user", userRouter);
app.use("/api/v1/courses", courseRouter);
app.use("/api/v1/admin", adminRouter);

async function main() {
  await mongoose.connect(process.env.MONGO_URL);
  app.listen(3000, () => {
    console.log("server listening on 3000...");
  });
}

main();
