const { Router } = require("express");
const { userMiddleware } = require("../middlewares/user");
const { purchaseModel, courseModel } = require("../db");
const courseRouter = Router();

courseRouter.get("/purchase", async (req, res) => {
  const userId = req.userId;
  const courseId = req.body.courseId;

  // Add check for the user has actually paid the price
  await purchaseModel.create({
    userId,
    courseId,
  });

  res.json({
    message: "You Have Successfully Bought The Course",
  });
});

courseRouter.get("/course", async (req, res) => {
  const course = await courseModel.find({});

  res.json({
    course,
  });
});

module.exports = {
  courseRouter: courseRouter,
};
