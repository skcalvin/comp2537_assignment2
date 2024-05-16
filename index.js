require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const Joi = require('joi');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

const expireTime = 60 * 60 * 1000;

/* secret stuff */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* secret stuff */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({
    secret: node_session_secret,
        store: mongoStore,
        saveUninitialized: false,
        resave: true
}
));

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}


function isAdmin(req) {
    if (req.session.userType == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}

app.get('/', (req, res) => {
    res.render("home", {session: req.session});
});

app.route('/signup')
    .get((req, res) => {
        res.render("signup");
    })
    .post((req, res) => {
        res.render("signup");
    });


app.post('/signupSubmit', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    console.log(name, email, password);

    const schema = Joi.object(
		{
			name: Joi.string().alphanum().max(20).required(),
            email: Joi.string().max(20).required(),
			password: Joi.string().max(20).required()
		});
	
	const validationResult = schema.validate({name, email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.render("signup");
	   return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({name: name, email: email, password: hashedPassword, userType: "user"});
	console.log("Inserted user");

    req.session.authenticated = true;
    req.session.username = name;
    req.session.userType = "user"; 
    req.session.cookie.maxAge = expireTime;

    if (!name || !email || !password){
        res.render("signupSubmit");
    } else {
        res.redirect('/members');
    }
    
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    console.log(email, password);

    const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(email, password);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}
    const result = await userCollection.find({email: email}).project({email: 1, password: 1, name: 1, userType: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		console.log("user not found");
        res.render('loginSubmit');
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
        // console.log(result[0].name);
		req.session.username = result[0].name;
        req.session.userType = result[0].userType;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
		return;
	}
	else {
		console.log("incorrect password");
        res.render('loginSubmit');
		return;
	}
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/members', (req, res) => {
    console.log(req.session.authenticated);
    if(!req.session.authenticated){
        res.redirect('/');
        return;
    }
    res.render('member');
});

app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    const result = await userCollection.find().project({name: 1}).toArray();
 
    res.render("admin", {users: result});
});

app.post('/updateUserType/:name', async (req, res) => {
    const name = req.params.name;
    const userType = req.body.userType;

    // Update userType in the database
    await userCollection.updateOne({ name: name }, { $set: { userType } });

    res.redirect('/admin'); 
});

app.use(express.static(__dirname + "/public"));

app.get('*', (req, res) => {
    res.status(404);
    res.render("404");
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`)
});