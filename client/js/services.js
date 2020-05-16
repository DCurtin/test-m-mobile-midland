angular.module('starter.services', [])

.factory('SocketIO', function() {
  return io()
})

.factory('Question', function($resource) {
  return $resource('/resource/questions/:questionId', null, {
    'activate': {
      method: 'POST',
      url: '/resource/questions/:questionId/activate'
    },
    'next': {
      method: 'POST',
      url: '/resource/questions/:questionId/next'
    }
  });
})

.factory('Answer', function($resource) {
  return $resource('/resource/answers/:answerId', null, {
    'leaders': {
      method: 'GET',
      url: '/resource/leaders',
      isArray: true
    },
    'truncate': {
      method: 'DELETE',
      url: '/resource/leaders'
    }
  });
})

.factory('AuthenticationService', function() {
  var auth = {
    isAuthenticated: false,
    isAdmin: false
  }

  return auth;
})

.factory('TokenInterceptor', function($q, $window, $location, AuthenticationService) {
  return {
    request: function(config) {
      config.headers = config.headers || {};
      if ($window.localStorage.token) {
        config.headers.Authorization = 'Bearer ' + $window.localStorage.token;
      }
      return config;
    },

    requestError: function(rejection) {
      return $q.reject(rejection);
    },

    /* Set Authentication.isAuthenticated to true if 200 received */
    response: function(response) {
      if (response != null && response.status == 200 && $window.localStorage.token && !AuthenticationService.isAuthenticated) {
        AuthenticationService.isAuthenticated = true;
      }
      return response || $q.when(response);
    },

    /* Revoke client authentication if 401 is received */
    responseError: function(rejection) {
      if (rejection != null && rejection.status === 401 && ($window.localStorage.token || AuthenticationService.isAuthenticated)) {
        delete $window.localStorage.token;
        AuthenticationService.isAuthenticated = false;
        $location.path("/login");
      }

      return $q.reject(rejection);
    }
  };
})

.factory('RegistrationService', function($window, $http, $ionicPopup, $rootScope, AuthenticationService) {
  return { 
    sfAuth: function() {
      var arguments = {token: $window.location.href.split('?')[1].split('#')[0].split('=')[1]};

      console.log('authing');
      console.log($window.location.href);
      return $http.post('/sfAuth',arguments).then( function(result){
        var value = result.data;
        console.log('user ' + value);
        $rootScope.user = value;
        AuthenticationService.isAuthenticated = true;
        $window.sessionStorage.name = value.name;
        $window.sessionStorage.email = value.email;
        $window.localStorage.token = value.token;
        //$window.history.replaceState({}, document.title, "/" + "#/sfAuth");
        //this.router.navigate["/test"];
        //$window.location.hash =''
        //this.location.href = 'https://' + this.location.host + '/#/test'
       // this.location.replace();
      }).catch(function(err){
        console.log('error: ' + JSON.stringify(err));
      })
    },

    uploadFile: function(file){
      const reader = new FileReader();
      
      reader.addEventListener("load", ()=>{
        //console.log(reader.result);
        var fd = new FormData();
        fd.append('file', reader.result);
        $http.post('/uplloadFile', fd, {
          transformRequest: angular.identity,
          headers: {'Content-Type': undefined}
        });
      }, false)


      reader.readAsArrayBuffer(file);
      //console.log($rootScope.uploadedFile)


    },

    login: function() {
      var url = 'https://test.salesforce.com/services/oauth2/authorize?response_type=code&client_id=3MVG9ahGHqp.k2_wp5KNZXDK5mBqaJaRv6ss6l7gQkGLZfriwyGa_1aRXE88g0W5oT9rwlJQ31ieo52ucBrJm&redirect_uri=https://test-m-mobile-midland.herokuapp.com/#/sfauth&state=init&prompt=login'
      $window.location.href = url
      /*return $http.post(url).then(function(result){
        console.log(result);
      }).catch(function(err){
        console.log('error');
      });*/

    },

    logout: function() {
      delete $window.localStorage.token;
    },

    register: function(user) {
      return $http.post('/register', user).then(function(result) {
        $rootScope.user = result.data;
        AuthenticationService.isAuthenticated = true;
        $window.sessionStorage.name     = result.data.name;
        $window.sessionStorage.is_admin = result.data.is_admin;
        $window.localStorage.token      = result.data.token;
        console.log(result.data);
      }).catch(function(err) {
        $ionicPopup.alert({
          title: 'Failed',
          content: err.data
        });
      });
    },

    getAccounts: function(){
      var user = $rootScope.user;
      console.log(user.id);
      return $http.post('/getAccounts',user).then(function(result){
        console.log(JSON.stringify(result));
        return result;
      })
    },

    createTrans: function(account){
      var transaction = {
        paybable_to_from__c:'test 123',
        recordtypeid :'01230000000Ne2TAAS',
        account__c: account.sfid,
        assigned_to__c: account.dedicated_rep__c
      };
      return $http.post('/createTrans', transaction).then(function(result){
        console.log(result);
        return result;
      })
    },

    getFile: function(fileId){
      var data = {
        sfid:fileId
      }
      return $http.post('/getContentVersion', data).then(function(result){
        return result;
      });
    }

    
  }
})

.factory('UserResponse', function() {
  var storageKey = 'userResponses';

  var localGet = function() {
    var ret = localStorage.getItem(storageKey);
    if (ret === null) {
      ret = {};
    } else {
      ret = JSON.parse(ret);
    }
    return ret;
  };

  var localSet = function(val) {
    localStorage.setItem(storageKey, JSON.stringify(val));
  };

  return {
    set: function(key, value) {
      var answers = localGet();
      answers[key] = value;
      localSet(answers);
    },

    get: function(key) {
      var answers = localGet();
      return answers[key];
    },

    reset: function() {
      localStorage.removeItem(storageKey);
    }
  };
})