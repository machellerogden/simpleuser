(function(){

    var _ = require('underscore'),
        bcrypt = require('bcrypt');

    function SimpleUser(config){

        // Reference the constructor
        var simpleUser = this;

        this.root = __dirname;

        // Set defaults
        var defaults = {
            'collection': undefined,
            'messageTemplate': __dirname + '/views/message',
            'loginTemplate': __dirname + '/views/login',
            'signupTemplate': __dirname + '/views/signup',
            'errorTemplate': __dirname + '/views/error'
        };

        // Collection is required
        if (_.has(config, 'collection')) {
            // extend constructor with filtered and defaulted config
            _.extend(this, _.defaults(_.pick(config, _.keys(defaults)), defaults));
            if (this.messageTemplate === defaults.messageTemplate) {
                console.info('[SimpleUser] Using default templates. Default templates require Jade template engine. Define custom templates to use a different template engine.');
            }
        } else {
            // no collection in config - throwing error
            throw new Error('SimpleUser Error: Must pass in a mongo database collection');
        }

        // Load user record
        this.loadUser = function(req, res, next){
            var email = false,
                users = simpleUser.collection;
            if (req.session.email) {
                email = req.session.email;
                users.findOne({ email: email }, function (err, result) {
                    if (result) {
                        req.user = simpleUser.cleanUid(result); // store user for later routes
                        next();
                    } else {
                        req.user = false;
                        next();
                    }
                });
            }
        };

        // Converts `_id` (ObjectId) to `uid` (String) and then removes `_id`
        this.cleanUid = function(record){
            if(_.isObject(record) && _.has(record,'_id')) {
                record.uid = record._id.toString(); // ObjectId to String
                delete record._id; // remove ObjectId
            }
            return record || {};
        };

        // Removes users email and password from session data
        this.logoutUser = function(req, res, next){
            if(_.isObject(req.session)){
                delete req.session.email;
                delete req.session.password;
            }
            next();
        };

        // Save user record
        this.saveUser = function(req, res, next){

            var user = {},
                users = simpleUser.collection;

            // don't let the browser pull this response from cache
            if (!res.getHeader('Cache-Control')){
                res.setHeader('Cache-Control', 'no-cache');
            }

            if (req.user) {
                simpleUser.userAlreadyExists(req, res);
            } else {
                var salt = bcrypt.genSaltSync(10);
                var hash = bcrypt.hashSync(req.session.password, salt);
                user = { "email" : req.session.email, "password" : hash, "role" : "user" };
                users.save(user, function(err, val){
                    if (!err) {
                        users.findOne({ email : user.email }, function (err, result) {
                            if (!err) {
                                req.user = simpleUser.cleanUid(result); // store user for later routes
                                next();
                            } else {
                                simpleUser.saveError(req, res);
                            }
                        });
                    } else {
                        simpleUser.saveError(req, res);
                    }
                });
            }
        };

        // Authenticate user
        this.authenticateUser = function(req, res, next){

            // don't let the browser pull this response from cache
            if (!res.getHeader('Cache-Control')) {
                res.setHeader('Cache-Control', 'no-cache');
            }

            if (req.user) {
                bcrypt.compare(req.session.password, req.user.password, function (err, authresult) {
                    if (authresult) {
                        // authorized, proceed to next
                        next();
                    } else {
                        // user credentials do not authenticate, sending 401
                        simpleUser.wrongLogin(req, res);
                    }
                });
            } else {
                // user does not exist, sending 401
                simpleUser.unauthorized(req, res);
            }
        };

        // Set login to session if present
        this.setSession = function(req, res, next){
            req.session = req.session || {};
            // try to find login in body
            if (req.body.email && req.body.password) {
                req.session.email = req.body.email;
                req.session.password = req.body.password;

            // try to find login in query
            } else if (req.query.email && req.query.password) {
                req.session.email = req.query.email;
                req.session.password = req.query.password;

            // try to find login in params
            } else if (req.params.email && req.params.password) {
                req.session.email = req.params.email;
                req.session.password = req.params.password;
            } 
            next();
        };

        // Check session for login
        this.checkSession = function(req, res, next){
            // is login in session?
            if (req.session.email && req.session.password) {
               next();
            // login not present
            } else {
                // don't let the browser pull this response from cache
                if (!res.getHeader('Cache-Control')) {
                    res.setHeader('Cache-Control', 'no-cache');
                }
                // send 401
                simpleUser.unauthorized(req, res);
            }
        };

        // Unauthorized
        this.unauthorized = function(req, res){
            res.status(401);
            if (req.accepts('html')) {
                res.render(simpleUser.errorTemplate, { title: 'Unauthorized', msg: 'You are not authorized to access this resource.', redirect: req.url });
            } else if (req.accepts('json')) {
              res.json({
                  status: 'Unauthorized',
                  code: 401,
                  msg: 'You are not authorized to access this resource.',
                  success: false,
                  redirect: req.url
              });
            }
        };

        // Wrong login
        this.wrongLogin = function(req, res){
            res.status(401);
            if (req.accepts('html')) {
                res.render(simpleUser.loginTemplate, { title: 'Unauthorized', msg: 'The login you supplied does not authenticate.', redirect: req.url });
            } else if (req.accepts('json')) {
              res.json({
                  status: 'Unauthorized',
                  code: 401,
                  msg: 'The login you supplied does not authenticate.',
                  success: false,
                  redirect: req.url
              });
            }
        };

        // Authenticated
        this.authenticated = function(req, res){
            if (req.accepts('html')) {
                res.render(simpleUser.messageTemplate, { title: 'Authenticated', msg: 'You are now logged in', redirect: req.url });
            } else if (req.accepts('json')) {
                res.json({
                    status: 'OK',
                    code: 200,
                    msg: 'Authenticated',
                    success: true,
                    redirect: req.url,
                    data: {
                        uid: req.user.uid
                    }
                });
            }
        };

        // User already exists
        this.userAlreadyExists = function(req, res){
            res.status(403);
            if (req.accepts('html')) {
                res.render(simpleUser.errorTemplate, { title: 'Forbidden', msg: 'User already exists', redirect: req.url });
            } else if (req.accepts('json')) {
                res.json({
                    status: 'Forbidden',
                    code: '403',
                    msg: 'User already exists',
                    success: false,
                    redirect: req.url
                });
            }
        };

        // Save error
        this.saveError = function(req, res){
            res.status(500);
            if (req.accepts('html')) {
                res.render(simpleUser.errorTemplate, { title: 'Server Error', msg: 'Sorry! Something went wrong while saving you account. Please contact support if you have any further trouble.' });
            } else if (req.accepts('json')) {
                res.json({
                    status: 'Server Error',
                    code: 500,
                    msg: 'Sorry! Something went wrong while saving you account. Please contact support if you have any further trouble.'
                });
            }
        };

        // Saved
        this.saved = function(req, res){
            if (req.accepts('html')) {
                res.render(simpleUser.messageTemplate, { title: 'All set!', msg: 'User saved', redirect: req.url });
            } else if (req.accepts('json')) {
                res.json({
                    status: 'OK',
                    code: 200,
                    msg: 'User saved',
                    success: true,
                    redirect: req.url,
                    data: {
                        uid: req.user.uid
                    }
                });
            }
        };

        // Logged out
        this.loggedOut = function(req, res){
            if (req.accepts('html')) {
                res.render(simpleUser.loginTemplate, { title: 'Logged Out', msg: 'You are now logged out', redirect: req.url });
            } else if (req.accepts('json')) {
                res.json({
                    status: 'Logged Out',
                    code: 200,
                    msg: 'You are now logged out',
                    success: true,
                    redirect: req.url
                });
            }
        };

        this.redirectOr = function(req, res, next){
            if (req.body.redirect && req.body.redirect !== req.url) {
                res.redirect(req.body.redirect);
            } else {
                next();
            }
        };

        // User must have login - middleware stack
        this.mustHaveLogin = [ this.setSession, this.checkSession, this.loadUser ];

        // Protect resource - middleware stack
        this.authenticate = [ this.setSession, this.checkSession, this.loadUser, this.authenticateUser ];

        // Save user - middleware stack
        this.save = [ this.setSession, this.checkSession, this.saveUser ];

        // Logout user alias
        this.logout = this.logoutUser;

    }

    module.exports = function(collection) {
        return new SimpleUser(collection);
    };

}());
