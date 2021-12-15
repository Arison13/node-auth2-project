const router = require("express").Router();
const { checkUsernameExists, validateRoleName, checkPasswordCorrect } = require('./auth-middleware');
const bcrypt = require('bcryptjs')
const User = require('../users/users-model')

router.post("/register", validateRoleName, (req, res, next) => {
    let user = req.body
    const hashPassword = bcrypt.hashSync(user.password, 8)
    user.password = hashPassword
    User.add(user)
      .then(saved => {
        res.status(201).json(saved)
      }).catch(next)
});


router.post("/login", checkUsernameExists, checkPasswordCorrect, (req, res, next) => {
  try {
    res.status(201).json({
      message:`${req.body.username} is back!`,
      token: req.token
    });
  }catch (err){
    next(err)
  }
});

module.exports = router;
