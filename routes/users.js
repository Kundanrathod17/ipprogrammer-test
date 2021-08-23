const router = require("express").Router();
let User = require("../models/user.model");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

router.route("/").get((req, res) => {
  User.find()
    .then((users) => res.json(users))
    .catch((err) => res.json(err));
});

router.route("/login").post((req, res) => {
  User.findOne({
    email: req.query.email,
  }).then((user) => {
    // res.json(user);
    if (!user) {
      return res.status(404).send({ message: "Email Not found." });
    }
    var passwordIsValid = bcrypt.compareSync(req.query.password, user.password);

    if (!passwordIsValid) {
      return res.status(401).send({
        accessToken: null,
        message: "Invalid Password!",
      });
    }
    var token = jwt.sign({ id: user.id }, process.env.ACCESS_SECRET_TOKEN, {
      expiresIn: 86400, // 24 hours
    });
    res.status(200).send({
      id: user._id,
      username: user.username,
      email: user.email,
      accessToken: token,
    });
  });
});

router.route("/add").post((req, res) => {
  const initials = req.body.initials;
  const firstName = req.body.firstName;
  const middleName = req.body.middleName;
  const lastName = req.body.lastName;
  const mobile = req.body.mobile;
  const email = req.body.email;
  const password = bcrypt.hashSync(req.body.password, 8);

  const newUser = new User({
    initials,
    firstName,
    middleName,
    lastName,
    mobile,
    email,
    password,
  });

  newUser
    .save()
    .then(() => res.json("User Added Successfully!"))
    .catch((err) => res.status(400).json("Error: " + err));
});

router.route("/delete").delete(authenticateToken, (req, res) => {
  User.findByIdAndDelete(req.user.id)
    .then(() => res.json("User deleted."))
    .catch((err) => res.status(400).json("Error: " + err));
});

router.route("/update").post(authenticateToken, (req, res) => {
  User.findById(req.user.id)
    .then((user) => {
      user.initials = req.body.initials;
      user.firstName = req.body.firstName;
      user.middleName = req.body.middleName;
      user.lastName = req.body.lastName;
      user.mobile = req.body.mobile;
      user.email = req.body.email;
      user.password = bcrypt.hashSync(req.body.password, 8);

      user
        .save()
        .then(() => res.json("Updated Successfully!"))
        .catch((err) => res.status(400).json("Error: " + err));
    })
    .catch((err) => res.json({ message: "User Not Found" }));
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_SECRET_TOKEN, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

module.exports = router;
