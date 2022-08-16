const bcrypt = require('bcrypt');
const saltRounds = 10; 
const router = require("express").Router();
const User = require('../models/User.model');

//GET /signup
router.get('/signup', (req, res) => {
    res.render('auth/signup');
});

//POST /signup
router.post('/signup', (req, res) => {
    const { username, password } = req.body;
    bcrypt
        .genSalt(saltRounds)
        .then(salt => bcrypt.hash(password, salt))
        .then(hashedPassword => {
            return User.create({
                username,
                password: hashedPassword
            });
        })
        .then(userFromDB => {
            console.log(`New user created: ${userFromDB}`);
            res.redirect('/auth/login');
        })
        .catch(err => console.log(err));
});

//GET /login 
router.get('/login', (req, res) => {
    res.render('auth/login');
});

module.exports = router; 