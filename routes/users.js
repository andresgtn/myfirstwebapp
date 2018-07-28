const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const gravatar = require('gravatar');
const bodyParser = require('body-parser');
const User = require('../models/User'); // include the user schema and DB
const keys = require('../config/keys');
const passport = require('passport');
const jwt = require('jsonwebtoken');

// test line only
router.get('/test', (req,res) => res.json({msg:"test"}));

router.post('/register', (req, res) => {
    // check if username already exists, its a standard mongoose function
    // these calls can be found in the mongoose documentation and API
    User.findOne({email: req.body.email}).then(user=> {
        if(user) {
            return res.status(400).json({email: 'Email already exists'});
        } else {
            const avatar = gravatar.url(req.body.email, {
                s: '200', // Size
                r: 'pg', // Rating
                d: 'mm' // Default
              });
            const newUser = new User ({
                name: req.body.name,
                email:req.body.email,
                password:req.body.password,
                avatar //equivalent to calling  avatar:avatar
            });
            // password hash generator and saving new user to database
            bcrypt.genSalt(10, (err, salt) => {
                bcrypt.hash(newUser.password, salt, (err, hash) => {
                  if (err) throw err;
                  newUser.password = hash;
                  newUser
                    .save()
                    .then(user => res.json(user))
                    .catch(err => console.log(err));
                });
            });
        }
    })
});

// login router
router.post('/login', (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
    //Find user by email
    User.findOne({email}).then(user => {
        // check for user
        if (!user) {
            return res.status(400).json({email: "User not found"});
        }
        bcrypt.compare(password, user.password).then(isMatch => {
            if(isMatch) {
                //this section logs users in
                // define token contents
                const payload = { id: user.id, name: user.name, avatar: user.avatar }; // Create JWT Payload
                // Sign Token
                jwt.sign(payload, keys.secret, {expiresIn: 3600}, (err, token) => {
                    res.json({success: true, token: 'Bearer ' + token});
                }); 
            } else {
                return res.status(400).json({email:"Incorrect password"});
            }
        })      
    })
});

// export this file to be accesible by the rest
module.exports = router;