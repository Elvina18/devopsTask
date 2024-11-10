const express = require('express');
const session = require('express-session');
const flash = require('express-flash');
const bcrypt = require('bcrypt');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const { body, validationResult } = require('express-validator');

require('dotenv').config();
const app = express();
const port = 3000;

const conn = mysql.createConnection({
  host: process.env.HOSTNAME,
  user: process.env.USER,
  password: process.env.PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use('/public', express.static(__dirname + '/public'));
app.set('view engine', 'ejs');

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    name: 'Sessionid',
    resave: false,
    saveUninitialized: true,
    cookie: {
      expires: new Date(Date.now() + 2 * 60 * 60 * 1000), // Set to expire in 2 hours
    },
  })
);

app.use(flash());

const requireLogin = (req, res, next) => {
  if (!req.session.user) {
    req.flash('error', 'Please log in to access this page.');
    return res.redirect('/login');
  }
  next();
};

// Routes
app.get('/', requireLogin, (req, res) => {
  try {
    //console.log(req.session.userId);
    const rows = conn.query('SELECT * FROM recipes where user_id = ?', [req.session.userId], (err, results, fields) => {
      res.render('index', { user: req.session.user, recipes: results });
    });
    
  } catch (error) {
    console.error(error);
    //console.log('errr');
    res.status(500).send('Internal Server Error');
  }
});

app.get('/login', (req, res) => {
  res.render('login', { message: req.flash('error') });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  //console.log(req.body)
  try {
    const rows = conn.query('SELECT * FROM users WHERE username = ?', [username], async (err, results, fields) => {
      
      if(results.length > 0){
        //console.log(results);
        const passwordMatch = await bcrypt.compare(password, results[0].password);
        if (passwordMatch) {
          req.session.userId = results[0].id;
          req.session.user = results[0].username;
          
          console.log('OKAY');
          return res.redirect('/');

        } else {
          req.flash('error', 'Invalid username or password.');
          return res.redirect('/login');
        }
      }
      else{
        req.flash('error', 'Invalid username or password.');
        return res.redirect('/login');
      }
    });

    
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/register', (req, res) => {
  res.render('register', { message: req.flash('error') });
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
      if(err) {
        console.log(err);
      }
      else {
        res.redirect('/login');
      }
    })
})

app.post(
    '/register',
    [
      // Validation using express-validator
      body('username').notEmpty().trim().escape().isLength({ min: 3 }).withMessage('Username must be at least 3 characters long.'),
      body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long.')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/)
      .withMessage('Password must include at least one lowercase letter, one uppercase letter, one number, and one special character')
    ],
    async (req, res) => {
      const { username, password } = req.body;
  
      // Check for validation errors
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        const errorMessages = errors.array().map(error => error.msg);
        req.flash('error', errorMessages);
        return res.redirect('/register');
      }
  
      try {
        conn.query('SELECT * FROM users WHERE username = ?', [username], async (err, results, fields) => {
          if (results.length > 0) {
            req.flash('error', 'Username is already taken.');
            return res.redirect('/register');
          } else {
            // Hash the password
            const hashedPassword = await bcrypt.hash(password, 10);
      
            // Insert the new user into the database
            conn.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err, result) => {
              if (err) {
                // Handle insertion error
                req.flash('error', 'Error registering user.');
                return res.redirect('/register');
              }
      
              req.flash('success', 'Registration successful. Please log in.');
              return res.redirect('/login');
            });
          }
        });
      } catch (error) {
        // Handle general error
        console.error('Error:', error);
        req.flash('error', 'Something went wrong.');
        return res.redirect('/register');
      }      
    }
  );

app.get('/admin', requireLogin, (req, res) => {
  const username = req.session.user;
  if (username !== 'admin'){
    return res.status(403).send('Permission denied');
  }
  else{
    conn.query('SELECT * FROM users WHERE username != ?', ["admin"], (err, users) => {
      if(err){
        console.error(err);
        return res.status(500).send('Internal Server Error');
      }
      res.render('admin', {users});
    });
  }
});

app.post('/delete-user/:userId', async (req, res) => {
  //Checking admin privileges
  const username = req.session.user;
  if (username !== 'admin'){
    return res.status(403).send('Permission denied');
  }
  const userId = req.params.userId;
  conn.query('DELETE FROM users WHERE id = ?', [userId], (err, result) => {
    if(err){
      console.error(err);
      return res.status(500).send('Internal Server Error');
    }
    res.redirect('/admin');
  })
});

// CRUD Operations for Recipes

// Create a new recipe
app.get('/recipes/new', requireLogin, (req, res) => {
  res.render('newRecipe', {message: 'message'});
});

app.post('/recipes', requireLogin, async (req, res) => {
  const { recipeName, ingredients } = req.body;
  
  try {
    conn.query('INSERT INTO recipes (recipe_name, ingredients, user_id) VALUES (?, ?, ?)', [recipeName, ingredients, req.session.userId], (err, results, fields) => {
      req.flash('success', 'Recipe added successfully.');
      res.redirect('/');
    });
    
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});

// Edit a recipe


app.get('/recipes/edit/:id', requireLogin,  (req, res) => {
  const recipeId = req.params.id;
  //console.log(recipeId);
  try {
    const rows = conn.query('SELECT * FROM recipes WHERE id = ? and user_id = ?', [recipeId, req.session.userId], (err, results, fields) => {
      if (results.length > 0) {
        res.render('editRecipe', {  message: 'Welcome', recipe: results[0] });
    }
    else {
      req.flash('error', 'Recipe not found.');
      res.redirect('/');
    }
  });
    
    
} 
   catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/recipes/edit/:id', requireLogin, (req, res) => {
  const recipeId = req.params.id;
  
  const { recipeName, ingredients } = req.body;
  //console.log(req);
  //console.log(req);
  try {
    
    conn.query('UPDATE recipes SET recipe_name = ?, ingredients = ? WHERE id = ?', [recipeName, ingredients, recipeId], (err, results, fields) => {
        req.flash('success', 'Recipe updated successfully.');
        res.redirect('/');
    });
    
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});

// Delete a recipe
app.get('/recipes/delete/:id', requireLogin, async (req, res) => {
  const recipeId = req.params.id;

  try {
    conn.query('DELETE FROM recipes WHERE id = ? ', [recipeId]);
    req.flash('success', 'Recipe deleted successfully.');
    res.redirect('/');
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
