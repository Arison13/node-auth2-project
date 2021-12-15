const router = require("express").Router();
const { checkUsernameExists, validateRoleName, checkPasswordCorrect } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require('bcryptjs')
const User = require('../users/users-model')
const { tokenBuilder} = require('./tokenbuilder')

router.post("/register", validateRoleName, (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
    let user = req.body
    const hashPassword = bcrypt.hashSync(user.password, 8)
    user.password = hashPassword
    User.add(user)
      .then(saved => {
        res.status(201).json(saved)
      })
});


router.post("/login", checkUsernameExists, checkPasswordCorrect, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  try {
    res.status(201).json({
      message:`${req.body.username} is back!`,
      token: req.token
    });
  }catch (err){
    next(err)
  }
   
    // .then(([user]) => {
    //   if (user && bcrypt.compareSync(password, user.password)) {
    //     const token = tokenBuilder(user)
    //     res.status(200).json({ 
    //       message: `Welcome back ${user.username}...`,
    //       token 
    //     })
    //   } else {
    //     next({ status: 401, message: 'Invalid Credentials' })
    //   }
    // })
    // .catch(next)
});

module.exports = router;
