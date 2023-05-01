
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");


const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

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
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

app.get('/', (req, res) => {
    if (req.session.name === undefined) { // user is not logged in
      var html = `
        <form action='/signup' method='get'>
          <button>Sign Up</button>
        </form>
        <form action='/login' method='get'>
          <button>Log In</button>
        </form>
      `;
      res.send(html);
    } else { // user is logged in
      var html = `
        <p>Hello, ${req.session.name}!</p>
        <form action='/members' method='get'>
          <button>Go to Members Area</button>
        </form>
        <form action='/logout' method='get'>
          <button>Log Out</button>
        </form>
      `;
      res.send(html);
    }
  });
  

app.get('/nosql-injection', async (req,res) => {
	var name = req.query.user;

	if (!name) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+name);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(name);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({name: name}).project({name: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${name}</h1>`);
});

app.post('/submitEmail', (req,res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: "+email);
    }
});


app.get('/signup', (req,res) => {
    var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='name' type='text' placeholder='name'>
    <input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});


app.get('/login', (req,res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/submitUser', async (req,res) => {
    var name = req.body.name;
    var password = req.body.password;
    var email = req.body.email;

    if (!name || !email || !password) {
      var errorMessage = '';
      if (!name) {
        errorMessage += 'Please provide a name.';
      }
      if (!email) {
        errorMessage += 'Please provide an email address.';
      }
      if (!password) {
        errorMessage += 'Please provide a password.';
      }
      var html = `
        <p>${errorMessage}</p>
        <a href="/signup">Try again</a>
      `;
      res.send(html);
      return;
    }

	const schema = Joi.object(
		{
			name: Joi.string().alphanum().max(20).required(),
      email: Joi.string().email().required(),
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
  req.session.name = name;
  req.session.cookie.maxAge = expireTime;
  res.redirect('/members');
});

app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required()
  });
	const validationResult = schema.validate({email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({email: email}).project({name: 1, password: 1, _id: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		var html = `
      <p>User not found.</p>
      <a href="/login">Try again</a>
      `;
    res.send(html);
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.name = result[0].name;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/loggedIn');
		return;
	}
	else {
		console.log("incorrect password");
		var html = `
            <p>Invalid email/password combination.</p>
            <a href="/login">Try again</a>
        `;
        res.send(html);
		return;
	}
});

app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    } else {
        res.redirect('/members');
    }
});

app.get('/members', (req, res) => {
  if (!req.session.authenticated) {
    res.redirect('/');
  } else {
    var name = req.session.name;
    var html = `
      <p>Hello, ${name}.</p>
      <a href="/logout">Log out</a>
      <img src='/image${Math.floor(Math.random() * 3) + 1}.jpg' style='width:250px;'>
    `;
    res.send(html);
  }
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect("/");
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 