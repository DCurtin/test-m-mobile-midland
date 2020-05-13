var bcrypt = require('bcrypt'),
  uuid = require('node-uuid'),
  validator = require('validator');

var user_cache = {};
var register_callback = null;

function encryptPassword(password, callback) {
  bcrypt.genSalt(10, function(err, salt) {
    if (err) {
      return callback(err);
    }
    bcrypt.hash(password, salt, function(err, hash) {
      return callback(err, hash);
    });
  });
}

function comparePassword(password, hash, callback) {
  console.log("Comparing ", password, " to hash ", hash);
  bcrypt.compare(password, hash, function(err, match) {
    if (err) {
      return callback(err);
    } else {
      return callback(null, match);
    }
  });
}

module.exports = function(models) {
  function clean_user(user) {
    delete user['crypted_password'];
    return user;
  }

  function register(req, res, next) {
    var user = req.body;

    if (!validator.isEmail(user.email)) {
      return res.status(400).send("Invalid email address");
    }
    if (!validator.isLength(user.name, 3)) {
      return res.status(400).send("Name must be at least 3 characters");
    }
    if (!validator.isLength(user.password, 3)) {
      return res.status(400).send("Password must be at least 3 characters");
    }


    console.log("Registering ", user);
    new models.User({
      email: user.email
    }).fetch().then(function(model) {
      if (model) {
        return next(Error("That email is already registered"));
      } else {
        encryptPassword(user.password, function(err, hash) {
          if (err) return next(err);

          user.token = uuid.v4();
          user.crypted_password = hash;

          delete user['password'];
          delete user['password2'];

          new models.User(user).save().then(function(model) {
            if (register_callback) {
              register_callback(model);
            }
            res.json(clean_user(model.attributes));

          }).catch(next);
        });
      }
    });
  }

  function sfAuth(req, res, next) {
    var data = req.body;
    var queryCode = req.query.code;
    var queryState = req.query.state;

    var clientId='3MVG9ahGHqp.k2_wp5KNZXDK5mBqaJaRv6ss6l7gQkGLZfriwyGa_1aRXE88g0W5oT9rwlJQ31ieo52ucBrJm';
    var clientSec='ACD35B3FC6AC4F4F1EF425489C36013EFD91F0831D3C24D6C889CF02C34EF88A';
    var redirUrl= 'https://test-m-mobile-midland.herokuapp.com/sfauth';
    var url  = 'https://test.salesforce.com/services/oauth2/token'+'?grant_type=authorization_code&code='+ queryCode+'&client_id='+clientId+'&client_secret='+clientSec+'&redirect_uri='+redirUrl+'&state=token';
    var rp  = require('request-promise');
    //res.redirect(url);
    //res.json('test');
    rp(url).then( function(result){
      //res.json('test2');
      var data = JSON.parse(result);
      var idParts = data.id.split('/');
      var sfId = idParts[idParts.length - 1];
      console.log(idParts);
      console.log(sfId);
      new models.sfUser({ sfid: sfId +''}).fetch().then(function(model){
        console.log(model.email)
        res.json(model);
      });
      
    }).catch(function(err) {
      res.status(500).send(err.message);
    });

    /*var options ={
      method: 'POST',
      uri: 'https://test.salesforce.com/services/oauth2/token'+'?grant_type=authorization_code&code='+ queryCode+'&client_id='+clientId+'&client_secret='+clientSec+'&redirect_uri='+redirUrl+'&state=token',
      headers: {
        'Content-type': 'application/x-www-form-urlencoded',
      }
    };
    rp(options).then(function(response)
    {
      res.json('test');

    });*/

  }

  function login(req, res, next) {

    var url = 'https://test.salesforce.com/services/oauth2/authorize?response_type=token&client_id=3MVG9ahGHqp.k2_wp5KNZXDK5mBqaJaRv6ss6l7gQkGLZfriwyGa_1aRXE88g0W5oT9rwlJQ31ieo52ucBrJm&redirect_uri=https://test-m-mobile-midland.herokuapp.com/sfauth'
    //var x = new XMLHttpRequest();
    //x.open(GET,url);

    //res.send(url);
    res.redirect(301,url);
    //res.end();
    /*
    var user = req.body;

    new models.User({
      email: user.email
    }).fetch().then(function(model) {
      if (!model) {
        return res.status(401).send("Invalid credentials");
      }

      console.log("Compare user ", user, " to model ", model.attributes);

      comparePassword(user.password, model.get("crypted_password"), function(err, match) {
        if (err) {
          console.log(err);
          return res.status(401).send("Invalid Credentials");
        }
        if (match) {
          model.token = uuid.v4();

          model.save().then(function(model) {
            res.json(clean_user(model.attributes));

          }).catch(next);

        } else {
          // Passwords don't match
          return res.status(401).send("Invalid Credentials");
        }
      });
    });*/
  }

  function on_register(callback) {
    register_callback = callback;
  }

  function authenticate(req, res, next) {
    var token = req.headers['authorization'];
    if (token) {
      token = token.split(' ')[1];
    } else {
      token = req.query.token;
      delete req.query.token;
    }

    if (token in user_cache) {
      req.user = user_cache[token];
      next();
    } else {
      new models.User({
        token: token
      }).fetch().then(function(model) {
        if (model) {
          user_cache[token] = model;
          req.user = model;
          return next();
        } else {
          console.log("Invalid token, returning 401");
          return res.status(401).send("Invalid token");
        }
      });
    }
  }

  function clear_leaders(req, res, next) {
    user_cache = {};
    return models.clear_leaders(req, res, next);
  }

  function require_admin(req, res, next) {
    if (!req.user.get('is_admin')) {
      res.status(401).send("Unauthorized");
    } else {
      return next();
    }
  }

  return {
    register: register,
    sfAuth: sfAuth,
    login: login,
    require_admin: require_admin,
    on_register: on_register,
    authenticate: authenticate,
    clear_leaders: clear_leaders
  }
}