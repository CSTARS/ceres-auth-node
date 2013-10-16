var users = [];
var token = "";
var authServerUrl = "";
var rootUrl = "";
var appName = "";
var redirectPage = "";

var GoogleStrategy = require('passport-google').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var TwitterStrategy = require('passport-twitter').Strategy;
var CeresStrategy = require('passport-local').Strategy;
var request = require('request');

exports.init = function(express, passport, config) {    
	token = config.auth.token;
	authServerUrl = config.auth.centralAuthServer;
	appName = config.auth.appName;
	redirectPage = config.auth.loginRedirectPage ? config.auth.loginRedirectPage : "";
	rootUrl = "http://"+config.server.host;
	if( config.server.remoteport && config.server.remoteport != "80" ) rootUrl += ":"+config.server.remoteport;
	
	passport.serializeUser(function(user, done) {
		  done(null, user.username);
	});

	passport.deserializeUser(function(id, done) {
	  if( users[id] ) return done(null, users[id]);
	  done({error:true,message:"not logged in"})
	});
	
	express.use(requireLogin);
}

exports.setEndpoints = function(express, passport, config) {
    express.get('/rest/isLoggedIn', function(req, res){
        if( req.user ) {
            res.send({
                status : true,
                user   : req.user
            })
            return;
        }
        
        res.send({status:false});
    });

    express.post('/rest/createAccount', function(req, res){
        
        var email = req.query.username;
        var password = req.query.password;

        _createCeresUser(username, password, function(err, resp){
            if( err ) return res.send(err);
            res.send(resp);
        });
    });
    
    _setupCeresAuth(express, passport);
    _setupGoogleAuth(express, passport);
    if( config.auth.twitter ) _setupFacebookAuth(express, passport, config);
    if( config.auth.facebook ) _setupTwitterAuth(express, passport, config);
}

//require login for admins
function requireLogin(req, res, next) {
    if( req.path != "/admin.html" && !req.path.match(/\/rest\/admin.*/) ) {
        next();
        return;
    }
    
    if ( req.user ) {
        if( req.user.roles && (req.user.roles.indexOf("admin") > -1) ) {
            next(); // allow the next route to run
        } else {
            res.send(401);
        }
    } else {
        // require the user to log in
        res.redirect("/login.html"); // or render a form, etc.
    }
}


//access auth server and see if user has account
function getCentralAuthUser(user, done) {
	var url = authServerUrl+"/rest/getUser?app="+appName+"&username="+user.email+"&token="+token;
	if( user.password ) url += "&password="+user.password;
	
	request({url:url,json:true}, function (error, response, body) {
		if( error ) console.log(error);
		//else console.log(response);
		
	  if (!error && response.statusCode == 200 && !body.error) {
		  	users[user.email] = body;
			
			done(null, body);
	  } else {
		  done("access denied for: "+user.email);
	  }
    });
}


function _setupCeresAuth(express, passport) {
	passport.use(new CeresStrategy(
	  function(username, password, done) {
		  
		  getCentralAuthUser({
			  user : username,
			  password : password
		  }, done);
		
	  }
	));
	
	express.post('/auth/ceres', passport.authenticate('local', { successRedirect: '/'+redirectPage,
        failureRedirect: '/login' }));
}


function _setupTwitterAuth(express, passport, config) {
	passport.use(new TwitterStrategy({
	    consumerKey: config.auth.twitter.consumerKey,
	    consumerSecret: config.auth.twitter.consumerSecret,
	    callbackURL: rootUrl+"/auth/twitter/callback"
	  },
	  function(token, tokenSecret, profile, done) {
			
			var user = {
				identifier : profile.id+"",
				email      : profile.username+"@twitter.com",
				name       : profile.displayName,
				provider   : 'Twitter'
			};
			
			getCentralAuthUser(user, done);
	  }
	));
	
	express.get('/auth/twitter', passport.authenticate('twitter'));

	express.get('/auth/twitter/callback', passport.authenticate('twitter', { successRedirect: '/'+redirectPage,
	                                     	failureRedirect: '/login' }));
}

function _setupFacebookAuth(express, passport, config) {

	passport.use(new FacebookStrategy({
		clientID: config.auth.facebook.clientID,
		clientSecret: config.auth.facebook.clientSecret,
	    callbackURL: rootUrl+"/auth/facebook/callback"
	  },
	  function(accessToken, refreshToken, profile, done) {
		  
			var user = {
				identifier : profile.profileUrl,
				email      : profile.username+"@facebook.com",
				name       : profile.displayName,
				provider   : 'Facebook'
			};
			
			getCentralAuthUser(user, done);
	  }
	));
	
	express.get('/auth/facebook', passport.authenticate('facebook'));

	express.get('/auth/facebook/callback', passport.authenticate('facebook', { successRedirect: '/'+redirectPage,
	                                      failureRedirect: '/login.html' }));
}

function _setupGoogleAuth(express, passport) {
	// setup google auth
	passport.use(new GoogleStrategy({
	    returnURL: rootUrl+'/auth/google/return',
	    realm: rootUrl
	  },
	  function(identifier, profile, done) {
		
		var user = {
			identifier : identifier,
			email      : profile.emails[0].value,
			name       : profile.displayName,
			provider   : 'Google'
		};
		
		getCentralAuthUser(user, done);
	  }
	));
	
	
	express.get('/auth/google', passport.authenticate('google'));
	
	express.get('/auth/google/return',  
			passport.authenticate('google', { successRedirect: '/'+redirectPage,
			                       					 failureRedirect: '/login.html' }));
}

function _loginCeresUser(username, password, callback) {
	request(authServerUrl+"/rest/getCeresUser?app="+appName+"&token="+token+
				"&username="+username+"&password="+password, callback);
}

function _createCeresUser(username, password, callback) {
	// query app engine to verify cookie
	request(authServerUrl+"/rest/addCeresUser?app="+appName+"&token="+token+
				"&username="+username+"&password="+password, callback);
}
