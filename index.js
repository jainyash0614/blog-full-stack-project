import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv";
import cookieParser from 'cookie-parser';
import cors from 'cors';


const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie : {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 1000 * 60 * 60 * 24,
    },
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(passport.initialize());
app.use(cors({
  origin: 'http://localhost:5173', // React app's URL
  credentials: true
}));

app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ message: 'Unauthorized' });
};

const isAuthor = async (req, res, next) => {
  const postId = req.params.id;
  const userId = req.user.id;

  try {
    const result = await db.query(
      'SELECT * FROM blog_posts WHERE id = $1 AND author_id = $2',
      [postId, userId]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({ message: 'You do not have permission to modify this post' });
    }

    next();
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/blog", (req, res) => {
     //console.log(req.user.email);
  if (req.isAuthenticated()) {
    res.render("blog.ejs");
  } else {
    res.redirect("/login");
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/blog",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      req.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/blog");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post('/api/posts', isAuthenticated, async (req, res) => {
  const { title, content } = req.body;
  const authorId = req.user.id;

  try {
    const result = await db.query(
      'INSERT INTO blog_posts (title, content, author_id) VALUES ($1, $2, $3) RETURNING *',
      [title, content, authorId]
    );
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ message: 'Error creating post' });
  }
});

app.get('/api/posts',isAuthenticated, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT blog_posts.*, users.email as author_email FROM blog_posts JOIN users ON blog_posts.author_id = users.id'
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching posts' });
  }
});

app.get('/api/posts/:id',isAuthenticated, async (req, res) => {
  const postId = req.params.id;

  try {
    const result = await db.query(
      'SELECT blog_posts.*, users.email as author_email FROM blog_posts JOIN users ON blog_posts.author_id = users.id WHERE blog_posts.id = $1',
      [postId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Post not found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching post' });
  }
});

app.put('/api/posts/:id', isAuthenticated, isAuthor, async (req, res) => {
  const postId = req.params.id;
  const { title, content } = req.body;

  try {
    const result = await db.query(
      'UPDATE blog_posts SET title = $1, content = $2 WHERE id = $3 RETURNING *',
      [title, content, postId]
    );
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ message: 'Error updating post' });
  }
});

app.delete('/api/posts/:id', isAuthenticated, isAuthor, async (req, res) => {
  const postId = req.params.id;

  try {
    await db.query('DELETE FROM blog_posts WHERE id = $1', [postId]);
    res.json({ message: 'Post deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting post' });
  }
});




passport.use(
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            //Error with password check
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              //Passed password check
              return cb(null, user);
            } else {
              //Did not pass password check
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
