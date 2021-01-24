const passport=require('passport');
const LocalStrategy=require('passport-local').Strategy;
const express = require('express');
const app = express();
const bodyParser = require("body-parser");
const mysql = require('mysql');
const crypto=require('crypto');
var session = require('express-session');
var MySQLStore = require('express-mysql-session')(session);


/*Mysql Express Session*/

app.use(session({
	key: 'session_cookie_name',
	secret: 'session_cookie_secret',
	store: new MySQLStore({
        host:'localhost',
        port:3306,
        user:'root',
        database:'cookie_user'
    }),
	resave: false,
    saveUninitialized: false,
    cookie:{
        maxAge:1000*60*60*24,
       
    }
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static('public'));
app.set("view engine", "ejs");


/*Mysql Connection*/

var connection = mysql.createConnection({
    host: "localhost",
    user: "root",
    database: "user",
    multipleStatements: true
  });
  connection.connect((err) => {
    if (!err) {
      console.log("Connected");
    } else {
      console.log("Conection Failed");
    }
  });
 

const customFields={
    usernameField:'uname',
    passwordField:'pw',
};


/*Passport JS*/
const verifyCallback=(username,password,done)=>{
   
     connection.query('SELECT * FROM users WHERE username = ? ', [username], function(error, results, fields) {
        if (error) 
            return done(error);

        if(results.length==0)
        {
            return done(null,false);
        }
        const isValid=validPassword(password,results[0].hash,results[0].salt);
        user={id:results[0].id,username:results[0].username,hash:results[0].hash,salt:results[0].salt};
        if(isValid)
        {
            return done(null,user);
        }
        else{
            return done(null,false);
        }
    });
}

const strategy=new LocalStrategy(customFields,verifyCallback);
passport.use(strategy);


passport.serializeUser((user,done)=>{
    console.log("inside serialize");
    done(null,user.id)
});

passport.deserializeUser(function(userId,done){
    console.log('deserializeUser'+ userId);
    connection.query('SELECT * FROM users where id = ?',[userId], function(error, results) {
            done(null, results[0]);    
    });
});



/*middleware*/
function validPassword(password,hash,salt)
{
    var hashVerify=crypto.pbkdf2Sync(password,salt,10000,60,'sha512').toString('hex');
    return hash === hashVerify;
}

function genPassword(password)
{
    var salt=crypto.randomBytes(32).toString('hex');
    var genhash=crypto.pbkdf2Sync(password,salt,10000,60,'sha512').toString('hex');
    return {salt:salt,hash:genhash};
}


 function isAuth(req,res,next)
{
    if(req.isAuthenticated())
    {
        next();
    }
    else
    {
        res.redirect('/notAuthorized');
    }
}


function isAdmin(req,res,next)
{
    if(req.isAuthenticated() && req.user.isAdmin==1)
    {
        next();
    }
    else
    {
        res.redirect('/notAuthorizedAdmin');
    }   
}

function userExists(req,res,next)
{
    connection.query('Select * from users where username=? ', [req.body.uname], function(error, results, fields) {
        if (error) 
            {
                console.log("Error");
            }
       else if(results.length>0)
         {
            res.redirect('/userAlreadyExists')
        }
        else
        {
            next();
        }
       
    });
}


app.use((req,res,next)=>{
    console.log(req.session);
    console.log(req.user);
    next();
});

/*routes*/
app.get('/', (req, res, next) => {
    res.send('<h1>Home</h1><p>Please <a href="/register">register</a></p>');
});

app.get('/login', (req, res, next) => {
        res.render('login')
});
app.get('/logout', (req, res, next) => {
    req.logout(); //delets the user from the session
    res.redirect('/protected-route');
});
app.get('/login-success', (req, res, next) => {
    res.send('<p>You successfully logged in. --> <a href="/protected-route">Go to protected route</a></p>');
});

app.get('/login-failure', (req, res, next) => {
    res.send('You entered the wrong password.');
});


app.get('/register', (req, res, next) => {
    console.log("Inside get");
    res.render('register')
    
});

app.post('/register',userExists,(req,res,next)=>{
    console.log("Inside post");
    console.log(req.body.pw);
    const saltHash=genPassword(req.body.pw);
    console.log(saltHash);
    const salt=saltHash.salt;
    const hash=saltHash.hash;

    connection.query('Insert into users(username,hash,salt,isAdmin) values(?,?,?,0) ', [req.body.uname,hash,salt], function(error, results, fields) {
        if (error) 
            {
                console.log("Error");
            }
        else
        {
            console.log("Successfully Entered");
        }
       
    });

    res.redirect('/login');
});

app.post('/login',passport.authenticate('local',{failureRedirect:'/login-failure',successRedirect:'/login-success'}));

app.get('/protected-route',isAuth,(req, res, next) => {
 
    res.send('<h1>You are authenticated</h1><p><a href="/logout">Logout and reload</a></p>');
});

app.get('/admin-route',isAdmin,(req, res, next) => {
 
    res.send('<h1>You are admin</h1><p><a href="/logout">Logout and reload</a></p>');

});

app.listen(3000, function() {
    console.log('App listening on port 8080!')
  });


  app.get('/notAuthorized', (req, res, next) => {
    console.log("Inside get");
    res.send('<h1>You are not authorized to view the resource </h1><p><a href="/login">Retry Login</a></p>');
    
});
app.get('/notAuthorizedAdmin', (req, res, next) => {
    console.log("Inside get");
    res.send('<h1>You are not authorized to view the resource as you are not the admin of the page  </h1><p><a href="/login">Retry to Login as admin</a></p>');
    
});
app.get('/userAlreadyExists', (req, res, next) => {
    console.log("Inside get");
    res.send('<h1>Sorry This username is taken </h1><p><a href="/register">Register with different username</a></p>');
    
});