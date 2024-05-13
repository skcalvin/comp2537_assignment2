require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const Joi = require('joi');

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

app.get('/', (req, res) => {
    if(!req.session.authenticated){
        var html = `
        <form action='/signup' method='get'>
            <button>Sign Up</button>
        </form>
        <form action='/login' method='get'>
            <button>Log In</button>
        </form>
        `;
        res.send(html);
    } else {
        let html = `
        <p>Hello, ${req.session.username}</p>
        <p><form action='/members' method='get'><button>Go to members area</button></form></p>
        <p><form action='/logout' method='get'><button>Log out</button></form></p>
        `;
        res.send(html);
    }
});

app.get('/signup', (req, res) => {
    var html = `
    create user
    <form action='/signupSubmit' method='post'> 
        <input name='name' type='text' placeholder='name'>
        <br>
        <input name='email' type='text' placeholder='email'>
        <br>
        <input name='password' type='password' placeholder='password'>
        <br>
        <button>submit</button>
    </form>    
    `;
    res.send(html);
});

app.post('/signupSubmit', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    if(!name){
        var html = `
        Name is required.
        <form action='/signup' method='post'>
            <button>Try again</button>
        </form>
        `;
        return res.send(html);
    }
    if(!email){
        var html = `
        Email is required.
        <form action='/signup' method='post'>
            <button>Try again</button>
        </form>
        `;
        return res.send(html);
    }
    if(!password){
        var html = `
        Password is required.
        <form action='/signup' method='post'>
            <button>Try again</button>
        </form>
        `;
        return res.send(html);
    }

    const schema = Joi.object(
		{
			name: Joi.string().alphanum().max(20).required(),
            email: Joi.string().max(20).required(),
			password: Joi.string().max(20).required()
		});
	
	const validationResult = schema.validate({name, email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/signup");
	   return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({name: name, email: email, password: hashedPassword});
	console.log("Inserted user");

    req.session.authenticated = true;
    req.session.username = name; 
    req.session.cookie.maxAge = expireTime;
    
    res.redirect('/members');
});

app.get('/login', (req, res) => {
    var html = `
    log in
    <form action='/loginSubmit' method='post'>
        <input name='email' type='text' placeholder='email'>
        <br>
        <input name='password' type='password' placeholder='password'>
        <br>
        <button>log in</button>
    </form>
    `;
    res.send(html);
});

app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(email, password);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}
    const result = await userCollection.find({email: email}).project({email: 1, password: 1, name: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		var html = `
        Invalid email or password
        <a href='/login'>Try again</a>
        `;
        res.send(html);
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
        // console.log(result[0].name);
		req.session.username = result[0].name;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
		return;
	}
	else {
		console.log("incorrect password");
		var html = `
        Invalid email or password
        <a href='/login'>Try again</a>
        `;
        res.send(html);
		return;
	}
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/members', (req, res) => {
    if(!req.session.authenticated){
        res.redirect('/');
        return;
    }
    const randomPenguin = Math.floor(Math.random() * 3) + 1;
    let html = `
    <p>Hello, ${req.session.username}</p>
    `;
    if (randomPenguin === 1) {
        html += "<p><img src='/penguin1.gif' style='width:250px;'></p>";
    } else if (randomPenguin === 2) {
        html += "<p><img src='/penguin2.gif' style='width:250px;'></p>";
    } else if (randomPenguin === 3) {
        html += "<p><img src='/penguin3.gif' style='width:250px;'></p>";
    }
    html += "<form action='/logout' method='get'><button>Log out</button></form>";
    res.send(html);
});

app.use(express.static(__dirname + "/public"));

app.get('*', (req, res) => {
    res.status(404);
    res.send('Page not found - 404');
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`)
});