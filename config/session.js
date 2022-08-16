const session = require('express-session');
const MongoStore = require('connect-mongo');

module.exports = app => {
    app.use(
        session({
            secret: process.env.SESS_SECRET,
            resave: false,
            saveUninitialized: false,
            cookie: {
                maxAge: 1000 * 60 * 60 * 24
            },
            store: new MongoStore({
                mongoUrl: 'mongodb://localhost/lab-express-basic-auth'
            })
        })
    )
}