const { Router } = require("express");
const adminRouter = Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { adminModel, courseModel } = require("../db");
const { JWT_ADMIN_PASSWORD } = require("../config");
const { adminMiddleware } = require("../middlewares/admin");
const { z } = require("zod");

//SIGN UP
adminRouter.post("/signup", async function (req, res) {
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
      return;
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

    await adminModel.create({
      email,
      password: hashedPassword,
      firstName,
      lastName,
    });

    res.json({
      message: "Admin Signed Up",
    });
  } catch (error) {
    res.status(500).json({
      message: "Error while signing up",
    });
  }
});

//SIGN-IN
adminRouter.post("/signin", async function (req, res) {
  try {
    const { email, password } = req.body;
    const admin = await adminModel.findOne({ email: email });

    if (!admin) {
      res.status(403).json({
        message: "Incorrect credentials",
      });
      return;
    }

    // comparing the password with the hashed password in the database.
    const passwordMatch = await bcrypt.compare(password, admin.password);

    if (passwordMatch) {
      const token = jwt.sign(
        {
          id: admin._id.toString(),
        },
        JWT_ADMIN_PASSWORD
      );

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

// Course Create Endpoints
adminRouter.post("/course", adminMiddleware, async function (req, res) {
  const adminId = req.userId;

  const { title, description, imageUrl, price, creatorId } = req.body;

  const course = await courseModel.create({
    title,
    description,
    imageUrl,
    price,
    creatorId: adminId,
  });

  res.json({
    message: "Course Created",
    courseId: course._id,
  });
});

// Course Update Endpoint
adminRouter.put("/course", adminMiddleware, async function (req, res) {
  const adminId = req.userId;

  const { title, description, imageUrl, price, courseId } = req.body;

  const course = await courseModel.updateOne(
    {
      _id: courseId,
      creatorId: adminId,
    },
    {
      title,
      description,
      imageUrl,
      price,
    }
  );

  res.json({
    message: "Course Updated",
    courseId: course._id,
  });
});

// view all course endpoint
adminRouter.get("/course/bulk", adminMiddleware, async function (req, res) {
  const adminId = req.userId;

  const course = await courseModel.find({
    creatorId: adminId,
  });

  res.json({
    message: "Courses Found",
    course,
  });
});

module.exports = {
  adminRouter: adminRouter,
};
