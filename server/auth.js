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

  function getAccounts(req, res, next){
    var dedRepId = req.body.id;
    console.log(dedRepId);

    models.account.query(function(qb){
      qb.where('dedicated_rep__c' , '=' , dedRepId);
    }).fetchAll().then(function(accountList){
      res.json(accountList);  
    })
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
    console.log('authing on server');
    var dataBody = req.body;
    var code = dataBody.token;

    var clientId = '3MVG9ahGHqp.k2_wp5KNZXDK5mBqaJaRv6ss6l7gQkGLZfriwyGa_1aRXE88g0W5oT9rwlJQ31ieo52ucBrJm';
    var clientSec = process.env.App_Secret;
    var redirUrl= 'https://test-m-mobile-midland.herokuapp.com/sfauth';
    var url  = 'https://test.salesforce.com/services/oauth2/token'+'?grant_type=authorization_code&code='+ code+'&client_id='+clientId+'&client_secret='+clientSec+'&redirect_uri='+redirUrl+'&state=token';
    var rp  = require('request-promise');
    //res.redirect(url);
    //res.json('test');
    rp(url).then( function(result){
      //res.json('test2');
      var data = JSON.parse(result);
      var sfIdParts = data.id.split('/');
      var sfId = sfIdParts[sfIdParts.length - 1];

      //res.json({access_token: data.access_token, id: data.id});
      console.log('res: ' + result);
      
      new models.sfUser({ sfid: sfId}).fetch().then(function(returnSfUser){
        console.log(returnSfUser.get('name'));
        res.json( {'id':sfId,
        'name': returnSfUser.get('name'),
        'email': returnSfUser.get('email'),
        'token': data.access_token});

        //console.log(returnSfUser.attributes.email)
        //returnSfUser.set_title('test title');
        /*new models.account({dedicated_rep__c: sfId}).fetchAll().then(function(returnedAccount){
          console.log(JSON.stringify(returnedAccount));
          var updateAccount = returnedAccount[Math.floor(Math.random() * (returnedAccount.length -1))];
          updateAccount.set_phone('7698893954');
          res.body = returnedAccount;
        });*/
      });
      //res.redirect('#/test');
      
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
    console.log('test');
    res.end();
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

  function generate_transaction(req, res, next){
    var data = req.body;
    new models.transaction(data).save().then(function(result){
      res.json(result);
    });
  }

  function uploadFile(req, res, next){
    var Base64Binary = {
      _keyStr : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",

      /* will return a  Uint8Array type */
      decodeArrayBuffer: function(input) {
        var bytes = (input.length/4) * 3;
        var ab = new ArrayBuffer(bytes);
        this.decode(input, ab);

        return ab;
      },
    
      removePaddingChars: function(input){
        var lkey = this._keyStr.indexOf(input.charAt(input.length - 1));
        if(lkey == 64){
          return input.substring(0,input.length - 1);
        }
        return input;
      },
    
      decode: function (input, arrayBuffer) {
        //get last chars to see if are valid
        input = this.removePaddingChars(input);
        input = this.removePaddingChars(input);
      
        var bytes = parseInt((input.length / 4) * 3, 10);

        var uarray;
        var chr1, chr2, chr3;
        var enc1, enc2, enc3, enc4;
        var i = 0;
        var j = 0;

        if (arrayBuffer)
          uarray = new Uint8Array(arrayBuffer);
        else
          uarray = new Uint8Array(bytes);

        input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");

        for (i=0; i<bytes; i+=3) {	
          //get the 3 octects in 4 ascii chars
          enc1 = this._keyStr.indexOf(input.charAt(j++));
          enc2 = this._keyStr.indexOf(input.charAt(j++));
          enc3 = this._keyStr.indexOf(input.charAt(j++));
          enc4 = this._keyStr.indexOf(input.charAt(j++));
        
          chr1 = (enc1 << 2) | (enc2 >> 4);
          chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
          chr3 = ((enc3 & 3) << 6) | enc4;
        
          uarray[i] = chr1;			
          if (enc3 != 64) uarray[i+1] = chr2;
          if (enc4 != 64) uarray[i+2] = chr3;
        }
      
        return uarray;	
      }
    }
    
    var formidable = require('formidable');
    var form = new formidable.IncomingForm();
    form.parse(req, function(err, fields, files){
      const fs = require('fs')
      fs.readFile(files.file.path, function(err, data){

        //var base64EncodedBinary = Base64Binary.decodeArrayBuffer(data);//data.toString('Base64');
        var value = new Uint8Array(str2ab(data.toString('base64')));
        
        //var buffer = str2ab(data.toString('base64'));
        
        //console.log(new Uint8Array(data.toString('Base64')))
        //console.log(data);
        //console.log(data.toString('base64'));
        //console.log( value);
        //console.log(typeof value);
        //console.log(new Buffer(value));
        //console.log(new Buffer(str2ab(data.toString('base64'))));
        //console.log(new Buffer(str2ab(data.toString('base64'))));
        console.log(new Buffer(data.toString('base64')));
        console.log(new Buffer(data, 'base64'));
        //console.log(new Buffer(data));
        //console.log(data.toString('base64'));
        
        new models.contentVersion({   versiondata: new Buffer('test1234', 'base64'),
                                  pathonclient: files.file.path,
                                  title:'uploaded file.png',
                                  //fileextension: 'png',
                                  filetype: 'PNG',
                                  //sharingprivacy: 'N',
                                  //sharingoption: 'A',
                                  firstpublishlocationid: '001g000002HVCgbAAH'}).save();
        })
      //console.log(fields);
      //console.log(req.body)
    })
    //console.log(req.body.file)
    //console.log(Object.keys(req))
  }

  function str2ab(str) {
    var buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
    var bufView = new Uint16Array(buf);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  }

  function getFile(req, res, next){
    //var StringDecoder  = require('string_decoder');
    var Base64Binary = {
        _keyStr : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",

        /* will return a  Uint8Array type */
        decodeArrayBuffer: function(input) {
          var bytes = (input.length/4) * 3;
          var ab = new ArrayBuffer(bytes);
          this.decode(input, ab);

          return ab;
        },
      
        removePaddingChars: function(input){
          var lkey = this._keyStr.indexOf(input.charAt(input.length - 1));
          if(lkey == 64){
            return input.substring(0,input.length - 1);
          }
          return input;
        },
      
        decode: function (input, arrayBuffer) {
          //get last chars to see if are valid
          input = this.removePaddingChars(input);
          input = this.removePaddingChars(input);
        
          var bytes = parseInt((input.length / 4) * 3, 10);

          var uarray;
          var chr1, chr2, chr3;
          var enc1, enc2, enc3, enc4;
          var i = 0;
          var j = 0;

          if (arrayBuffer)
            uarray = new Uint8Array(arrayBuffer);
          else
            uarray = new Uint8Array(bytes);

          input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");

          for (i=0; i<bytes; i+=3) {	
            //get the 3 octects in 4 ascii chars
            enc1 = this._keyStr.indexOf(input.charAt(j++));
            enc2 = this._keyStr.indexOf(input.charAt(j++));
            enc3 = this._keyStr.indexOf(input.charAt(j++));
            enc4 = this._keyStr.indexOf(input.charAt(j++));
          
            chr1 = (enc1 << 2) | (enc2 >> 4);
            chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
            chr3 = ((enc3 & 3) << 6) | enc4;
          
            uarray[i] = chr1;			
            if (enc3 != 64) uarray[i+1] = chr2;
            if (enc4 != 64) uarray[i+2] = chr3;
          }
        
          return uarray;	
        }
      }

    var givenSfid = req.param('sfid');
    console.log('file sfid: ' + givenSfid);
    //console.log(req.body);
    //var decoder = new StringDecoder('windows-1252')  
    
    models.contentVersion.query(function(qb) {
      qb.where('sfid', '=', givenSfid)
    }).fetch().then(function(result){
      //var utf8 = require('utf8')
      //base64String = decoder.decode(new Uint8Array($result.versiondata));
      console.log(result.get('versiondata'));
      console.log(result.get('versiondata').toString('utf-8'));
      console.log(typeof result.get('versiondata'));
      //console.log(result.get('versiondata').toString());
      base64String = result.get('versiondata').toString('utf-8');
      //console.log(base64String)
      base64Array = Base64Binary.decodeArrayBuffer(base64String);
      //console.log(base64Array);
      //console.log(base64Array)
      //decodedString = (new Buffer(new Uint8Array(base64Array))).toString('ascii');
      //console.log(decodedString)
      //textBlob = new Blob([decodedString], {type: 'application/pdf'});
      res.status(200).send(new Buffer(new Uint8Array(base64Array)));
      //res.json();  
    })
    /*new models.contentVersion().fetchOne().then(function(result){
      res.json(result);
    });*/
  }

  return {
    getAccounts: getAccounts,
    register: register,
    sfAuth: sfAuth,
    login: login,
    require_admin: require_admin,
    on_register: on_register,
    authenticate: authenticate,
    clear_leaders: clear_leaders,
    generate_transaction: generate_transaction,
    getFile: getFile,
    uploadFile: uploadFile
  }
}