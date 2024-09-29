const { Router } = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { z } = require("zod");
const { userModel, purchaseModel, courseModel } = require("../db");
const { JWT_USER_PASSWORD } = require("../config");
const { userMiddleware } = require("../middlewares/user");

const userRouter = Router();

userRouter.post("/signup", async (req, res) => {
  try {
    // Add validation for at least 1 uppercase char, 1 lowercase char, and 1 special char.
    const passwordValidateRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*(),.?":{}|<>]).{3,100}$/;

    const requiredBody = z.object({
      email: z.string().min(3).max(100).email(),
      password: z.string().min(3).max(100),
      firstName: z.string().min(1).max(100),
      lastName: z.string().min(1).max(100),
    });

    const parsedDataWithSuccess = requiredBody.safeParse(req.body);

    if (!parsedDataWithSuccess.success) {
      res.json({
        message: "Incorrect Format",
      });
    }

    const { email, password, firstName, lastName } = req.body;

    if (!passwordValidateRegex.test(password)) {
      res.status(400).json({
        message:
          "Password must contain at least one uppercase letter, one lowercase letter, and one special character.",
      });
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await userModel.create({
      email,
      password: hashedPassword,
      firstName,
      lastName,
    });

    res.json({
      message: "User Signed Up",
    });
  } catch (error) {
    res.status(500).json({
      message: "error while signing up",
    });
  }
});

userRouter.post("/signin", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await userModel.findOne({ email: email });

    if (!user) {
      res.status(403).json({
        message: "Incorrect creds",
      });
      return;
    }

    // comparing the password with the hashed password in th database.
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
      const token = jwt.sign(
        {
          id: user._id.toString(),
        },
        JWT_USER_PASSWORD
      );

      // do cokkie logic if want

      res.json({
        token: token,
      });
    } else {
      res.status(403).json({
        message: "Invalid Credentials",
      });
    }
  } catch (error) {
    res.status(500).json({
      message: "An error occurred during sign-in",
    });
  }
});

userRouter.get("/purchases", userMiddleware, async (req, res) => {
  const userId = req.userId;

  const purchases = await purchaseModel.find({
    userId,
  });

  let purchasedCourseIds = [];

  for (let i = 0; i < purchases.length; i++) {
    purchasedCourseIds.push(purchases[i].courseId);
  }

  const courseData = await courseModel.findOne({
    _id: { $in: purchasedCourseIds },
  });

  res.json({
    purchases,
    courseData,
  });
});

module.exports = {
  userRouter: userRouter,
};
