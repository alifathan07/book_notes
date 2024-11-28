import express from 'express';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import session from 'express-session';
import flash from 'connect-flash';
import passport from 'passport';
import LocalStrategy from 'passport-local';
import pg from "pg";
import path from "path";
import { fileURLToPath } from 'url';
import { Strategy as GoogleStrategy } from "passport-google-oauth2";


const app = express();
const port = 3000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// إعدادات القوالب والمجلدات
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/', express.static(path.join(__dirname, 'public')));

// إعداد الجلسات
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false
}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

// إعداد قاعدة البيانات
const db = new pg.Client({
    user: 'postgres',
    host: 'localhost',
    database: 'book_notes',
    password: 'root',
    port: 5000 // تأكد من استخدام المنفذ الصحيح
});
db.connect();

const isLoggedIn = (req, res, next) => {
    if (req.session.user) {
        // User is logged in, redirect to home
        return res.redirect('/');
    }
   else{
    next();
   } // User is not logged in, proceed to the login route
  };
passport.use(new LocalStrategy(async (username, password, done) => {
    try {
        const user = await db.query("SELECT * FROM users WHERE username = $1", [username]);
        if (user.rows.length === 0) {
            return done(null, false, { message: 'Incorrect username.' });
        }
        const validPassword = await bcrypt.compare(password, user.rows[0].password);
        if (!validPassword) {
            return done(null, false, { message: 'Incorrect password.' });
        }
        return done(null, user.rows[0]);
    } catch (err) {
        return done(err);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await db.query("SELECT * FROM users WHERE id = $1", [id]);
        done(null, user.rows[0]);
    } catch (err) {
        done(err, null);
    }
});

const GOOGLE_CLIENT_ID = '358313498074-nkc7bafg3j3fliqvq63m65q3vqlko9df.apps.googleusercontent.com';
const GOOGLE_CLIENT_SECRET = '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';
passport.use(new GoogleStrategy({
    clientID:     GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/google/callback",
    passReqToCallback   : true
  },
  async (request, accessToken, refreshToken, profile, done) => {
    try {
      // Check if the user exists in the database
      let userResult = await db.query("SELECT * FROM users WHERE google_id = $1", [profile.id]);
      
      if (userResult.rows.length === 0) {
        // If user doesn't exist, create a new one
        const newUser = await db.query(
          "INSERT INTO users (username, email, google_id) VALUES ($1, $2, $3) RETURNING *",
          [profile.displayName, profile.emails[0].value, profile.id]
        );
        return done(null, newUser.rows[0]);
      }

      // User exists
      return done(null, userResult.rows[0]);
    } catch (error) {
      return done(error, null);
    }
  }
));
passport.serializeUser((user, done) => {
    done(null, req.session.user = user.id); // Serialize the user's ID
  });
passport.deserializeUser(async (id, done) => {
  try {
    const userResult = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    if (userResult.rows.length === 0) {
      return done(new Error("User not found"), null);
    }
    done(null, userResult.rows[0]); // Pass the user object
  } catch (err) {
    done(err, null);
  }
});

// تمرير رسائل الفلاش
app.use((req, res, next) => {
    res.locals.success = req.flash('success');
    res.locals.error = req.flash('error');
    next();
});
app.get("/auth/google", passport.authenticate("google", { scope: ["email", "profile"] }));

app.get(
  "/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/profile");
  }
);
app.get("/profile", (req, res) => {
    // Use req.user which contains the full user object after deserialization
    const userId = req.user.id; 
  
    db.query("SELECT * FROM users WHERE id = $1", [userId], (err, result) => {
      if (err) {
        console.error("Error fetching user data:", err);
        return res.status(500).send("Internal Server Error");
      }
  
      const user = result.rows[0];
      res.render("profile.ejs", { user });
    });
  });
  
app.post("/update/user", (req, res) => {
    const { username, email } = req.body;
    db.query("UPDATE users SET username = $1, email = $2 WHERE id = $3", [username, email, req.session.user]);
    res.redirect("/profile");
})
// المسارات
app.get("/", (req, res) => {
    res.render('welcome.ejs', { user: req.session.user });
});

app.get("/register", isLoggedIn, (req, res) => {
    res.render('auth/register.ejs');
});

app.post("/register", async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.query("INSERT INTO users (username, email, password) VALUES($1, $2, $3)", [username, email, hashedPassword]);
        req.flash('success', 'Registration successful. Please login.');
        res.redirect('/login');
    } catch (error) {
        req.flash('error', error.message);
        res.redirect('/register');
    }
});

app.get("/login", isLoggedIn,(req, res) => {
    res.render('auth/login.ejs');
});
app.post("/login",  async(req, res) =>  {
    const username = req.body.username;
    const password = req.body.password;
    const user = await db.query("SELECT * FROM users WHERE username = $1",[username]);
    const hashedpass = user.rows[0].password;
    const isMatch = await bcrypt.compare(password, hashedpass)
    if(isMatch){
      req.user.id = user.rows[0].id;
      req.flash('success', 'Welcome to your account ' + user.rows[0].name)
      res.redirect("/");
    }else{
      res.send("Invalid credentials");
    }
  });
app.post("/logout", (req, res) => {
    req.session.destroy((err) => {
        res.redirect('/login');
    });
})

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
