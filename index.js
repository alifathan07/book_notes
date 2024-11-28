import express from 'express';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import session from 'express-session';
import flash from 'connect-flash';
import passport from 'passport';
import LocalStrategy from 'passport-local';
import pg from "pg";
import { Strategy as GoogleStrategy } from "passport-google-oauth2";
import multer from "multer";
import fs from 'fs';
import path from "path";
import { fileURLToPath } from 'url';
import axios from 'axios';
import { isReadable } from 'stream';
import dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

const app = express();
const port = 3000;
const __filename = fileURLToPath(import.meta.url); // get the resolved path to the file
const __dirname = path.dirname(__filename); // get the name of the directory
const folderPath = path.join(__dirname, "public/uploads/images");

// Setup templates and static folder
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/', express.static(path.join(__dirname, 'public')));

if (!fs.existsSync(folderPath)) {
    fs.mkdirSync(folderPath, { recursive: true });
}

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, folderPath);
    },
    filename: function (req, file, cb) {
        const extname = path.extname(file.originalname).toLowerCase();
        console.log(extname);
        const validExtensions = ['.jpeg', '.png', '.jpg'];

        if (validExtensions.includes(extname)) {
            cb(null, Date.now() + extname); // Add unique timestamp to the file name
        } else {
            cb(new Error('Invalid file type'), false); // Reject invalid file types
        }
    }
});
const upload = multer({
    storage: storage,
    fileFilter: storage[0]
});

// Setup sessions
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET, // Use session secret from .env
    resave: false,
    saveUninitialized: false
}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

// Setup database connection
const db = new pg.Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT
});
db.connect();

// Define a middleware to check if the user is logged in
const isLoggedIn = (req, res, next) => {
    if (req.session.user) {
        return res.redirect('/'); // User is logged in, redirect to home
    }
    next(); // User is not logged in, proceed to the next route
};

// Passport Local Strategy for user login
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

// Google OAuth Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/google/callback",
    passReqToCallback: true
},
async (request, accessToken, refreshToken, profile, done) => {
    try {
        let userResult = await db.query("SELECT * FROM users WHERE google_id = $1", [profile.id]);
        
        if (userResult.rows.length === 0) {
            const newUser = await db.query(
                "INSERT INTO users (username, email, google_id) VALUES ($1, $2, $3) RETURNING *",
                [profile.displayName, profile.emails[0].value, profile.id]
            );
            return done(null, newUser.rows[0]);
        }

        return done(null, userResult.rows[0]);
    } catch (error) {
        return done(error, null);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id); // Serialize the user's ID
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

// Profile route
app.get("/profile", async (req, res) => {
    try {
        let user;
        if (req.user) {
            user = req.user;
        } else if (req.session.user) {
            const result = await db.query("SELECT * FROM users WHERE id = $1", [req.session.user]);
            user = result.rows[0];
        }

        if (user) {
            req.flash('success', 'Welcome to your profile!');
            res.render("profile.ejs", { messages: req.flash(), user: user });
        } else {
            res.redirect("/login");
        }
    } catch (err) {
        console.error("Error fetching profile: ", err);
        res.status(500).send("Internal Server Error");
    }
});

// Flash messages
app.use((req, res, next) => {
    res.locals.success = req.flash('success');
    res.locals.error = req.flash('error');
    next();
});

// Google OAuth routes
app.get("/auth/google", passport.authenticate("google", { scope: ["email", "profile"] }));

app.get(
    "/google/callback",
    passport.authenticate("google", { failureRedirect: "/login" }),
    (req, res) => {
        res.redirect("/profile");
    }
);

// Start the server


app.get("/book", async (req, res) => {
   
        if (req.user || req.session.user) {
    
            try {
                const result = await db.query("SELECT * FROM books");
                res.render("books.ejs", { books: result.rows ,user: req.user || req.session.user});
            } catch (error) {
                console.error("Error fetching books: ", error.message);
                res.status(500).send("An error occurred while fetching books.");
            }
        } else {
            res.redirect("/login");
        }
   
});
app.get("/book/:id", async (req, res) => {
    if (req.user || req.session.user) {
        const bookId = req.params.id; // Get the book ID from the URL parameter
        try {
            const checkfavorite = await db.query("SELECT * FROM favorites WHERE user_id = $1 AND book_id = $2", [req.user ? req.user.id : req.session.user, bookId]);
            // checkreadlater
            const checkreadlater = await db.query("SELECT * FROM readlater WHERE user_id = $1 AND book_id = $2", [req.user ? req.user.id : req.session.user, bookId]);

            // Query for the book details with the associated user (if any)
            const result = await db.query(
                `SELECT books.*, users.username 
                 FROM books 
                 LEFT JOIN users ON users.id = books.user_id 
                 WHERE books.id = $1`,
                [bookId]
            );
            const resu = await db.query("SELECT * FROM notes WHERE book_id = $1 AND user_id = $2", [bookId , req.user ? req.user.id : req.session.user]);
            const notes = resu.rows;
            const book = result.rows[0]; // Get the first row of the result
            
            // Check if the book exists
            if (!book) {
                // No book with the given ID exists
                return res.status(404).send("Book not found");
            }

            // Render the book details page
            res.render("bookdetails.ejs", { book, notes, isFavorite: checkfavorite.rows.length > 0, isReadlater: checkreadlater.rows.length > 0, user: req.user || req.session.user });

        } catch (err) {
            console.error(err.message);
            res.status(500).send("Server error");
        }
    } else {
        // Redirect to login if the user is not authenticated
        res.redirect('/login');
    }
});


app.post("/add-note", async (req, res) => {
    try {
        const bookId = req.body.bookId
        const note = req.body.noteContent
        const userId = req.user
            ? req.user.id // For Google OAuth users
            : req.session.user; // For session-authenticated users
        console.log(userId + " " + bookId + " " + note);
        const add = await db.query("INSERT INTO notes (user_id, book_id, note) VALUES ($1, $2, $3)", [userId, bookId, note]);
        console.log(add);
        res.redirect(`/book/${bookId}`);
    } catch (error) {
        console.error(error.message);
    }
});
app.post("/delete-note", async (req, res) => {
    try {
        const bookId = req.body.bookId
        const noteId = req.body.noteId
        const userId = req.user
            ? req.user.id // For Google OAuth users
            : req.session.user; // For session-authenticated users
        console.log(userId + " " + bookId + " " + noteId);
        const deleteNote = await db.query("DELETE FROM notes WHERE user_id = $1 AND book_id = $2 AND id = $3", [userId, bookId, noteId]);
        console.log(deleteNote);
        res.redirect(`/book/${bookId}`);
    } catch (error) {
        console.error(error.message);
    }
})
app.get("/create/book", async (req, res) => {
    res.render("createBook.ejs", {user: req.user || req.session.user});
});
app.post("/create/book",upload.single("cover_url"), async (req, res) => {
    const { title, author, type } = req.body;
    try {
        const cover_url = req.file;
            // Ensure user_id is properly assigned based on the condition
    let userId;
    if (req.user) {
        const select = await db.query("SELECT * FROM users WHERE google_id = $1", [req.user.google_id]);
        userId = select.rows[0].id;
    } else {
        // Handle the case where user_id is not req.user (if needed)
        userId = req.session.user; // Or any default value
    }

    // Insert the data into the database
    await db.query(
        "INSERT INTO books (title, author, type, cover_url, user_id) VALUES ($1, $2, $3, $4, $5)", 
        [title, author, type, cover_url.filename, userId]
    );

        res.redirect("/book");
    } catch (error) {
        console.log(error.message);
        res.status(500).send("An error occurred while creating the book.");
    }
});

app.post("/update/user", upload.single("image"), (req, res) => {
    const { username, email, password } = req.body; // Extract data from the form
    const uploadedFile = req.file ? req.file.filename : null; // Get uploaded file, if any

    // Determine the authenticated user
    const userId = req.user
        ? req.user.id // For Google OAuth users
        : req.session.user; // For session-authenticated users

    if (!userId) {
        req.flash("error", "User not authenticated.");
        return res.redirect("/profile");
    }

    // Ensure required fields are provided
    if (!username || !email) {
        req.flash("error", "Username and email are required.");
        return res.redirect("/profile");
    }

    // Construct the database query and values
    const updateQuery = `
        UPDATE users
        SET username = $1, email = $2, image = COALESCE($3, image)
        WHERE id = $4
    `;
    const queryValues = [username, email, uploadedFile, userId];

    // Execute the query
    db.query(updateQuery, queryValues, (err) => {
        if (err) {
            console.error("Error updating user:", err);
            req.flash("error", "Error updating user profile.");
            return res.redirect("/profile");
        }

        req.flash("success", "Profile updated successfully.");
        res.redirect("/profile");
    });
});

app.post("/add/favorite", async(req, res) => {
    const bookId = req.body.bookid;
    const userId = req.user
        ? req.user.id // For Google OAuth users
        : req.session.user; // For session-authenticated users
    await db.query("INSERT INTO favorites (user_id, book_id) VALUES ($1, $2)", [userId, bookId]);
    res.redirect(`/book/${bookId}`);    
});
app.post("/add/readlater", async(req, res) => {
    const bookId = req.body.bookid;
    const userId = req.user
        ? req.user.id // For Google OAuth users
        : req.session.user; // For session-authenticated users
    await db.query("INSERT INTO readlater (user_id, book_id) VALUES ($1, $2)", [userId, bookId]);
    res.redirect(`/book/${bookId}`);    
});
app.post("/remove/favorite", async(req, res) => {   
    const bookId = req.body.bookid;
    const userId = req.user
        ? req.user.id // For Google OAuth users
        : req.session.user; // For session-authenticated users
    await db.query("DELETE FROM favorites WHERE user_id = $1 AND book_id = $2", [userId, bookId]);
    res.redirect(`/book/${bookId}`);    
});
app.post("/remove/readlater", async(req, res) => {   
    const bookId = req.body.bookid;
    const userId = req.user
        ? req.user.id // For Google OAuth users
        : req.session.user; // For session-authenticated users
    await db.query("DELETE FROM readlater WHERE user_id = $1 AND book_id = $2", [userId, bookId]);
    res.redirect(`/book/${bookId}`);    
});
app.get("/readlater/:userId", async (req, res) => {
    const userId = req.params.userId;
    const result = await db.query("SELECT books.* FROM readlater JOIN books ON readlater.book_id = books.id WHERE readlater.user_id = $1", [userId]);
    const books = result.rows;
    res.render("readlater.ejs", { books, user: req.user || req.session.user });
});

app.get("/favorites/:userId", async (req, res) => {
    const userId = req.params.userId;
    const result = await db.query("SELECT books.* FROM favorites JOIN books ON favorites.book_id = books.id WHERE favorites.user_id = $1", [userId]);
    const books = result.rows;
    res.render("favorite.ejs", { books, user: req.user || req.session.user });
});

// المسارات
app.get("/", (req, res) => {
    res.render('welcome.ejs', { user: req.session.user || req.user });
});

app.get("/register", isLoggedIn, (req, res) => {
    res.render('auth/register.ejs');
});

app.post("/register", upload.single("image"), async (req, res) => {
    const { username, email, password, image } = req.body;
    try {
        const image = req.file;
        if (!image) {
            return res.status(400).send("No file uploaded.");
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.query("INSERT INTO users (username, email, password, image) VALUES($1, $2, $3, $4)", [username, email, hashedPassword, image.filename]);

        req.flash('success', 'Registration successful. Please login.');
        res.redirect('/login');
    } catch (error) {
        req.flash('error', error.message);
        res.redirect('/register');
    }
});

app.get("/login", isLoggedIn,(req, res) => {
    res.render('auth/login.ejs' , {messages: req.flash()});
});
app.post("/login",  async(req, res) =>  {
    const username = req.body.username;
    const password = req.body.password;
    const user = await db.query("SELECT * FROM users WHERE username = $1",[username]);
    if(user.rows.length === 0){
        req.flash('error', 'Sorry username or password not found!');
        res.redirect('/login');
    }else{
        const hashedpass = user.rows[0].password;
        console.log(hashedpass)
        const isMatch = await bcrypt.compare(password, hashedpass)
        if(isMatch){
            req.session.user = user.rows[0].id;
            req.flash('success', 'Welcome to your account ' + user.rows[0].name)
            res.redirect("/profile");
        }else{
            res.send("Invalid credentials");
        }
    }
    
  });
app.post("/logout", (req, res) => {
    req.session.destroy((err) => {
        res.redirect('/login');
    });
})

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
// إعداد قاعدة البيانات

});
