angular.module('starter.controllers', [])

.controller('AppCtrl', function($scope, $location, RegistrationService) {
  $scope.logout = function() {
    RegistrationService.logout();
    $location.path("/login");
  }
  $scope.timeleft = '0 secs';
})


.controller('QuizCtrl', function($scope, $ionicPopup, $ionicLoading, SocketIO, Question, Answer, 
                                 AuthenticationService, RegistrationService, UserResponse) {
  $scope.q = {};
  $scope.q.answers = ['one', 'two', 'three'];
  $scope.answer = null;
  $scope.show_leaders = false;
  $scope.correct_answer = null;
  $scope.answerIndex = false;
  $scope.is_admin = AuthenticationService.isAdmin;
  
  $scope.hasAnswered = function() {
    // Has the user answered the current question already?
    return UserResponse.get($scope.q.id) !== undefined;
  };

  $scope.userAnswerCorrect = function(index) {
    // Is this the index of the user's response, and is it the right answer
    index = index + 1;
    return UserResponse.get($scope.q.id) === index && index === $scope.q.answer_index;
  };

  $scope.userAnswerWrong = function(index) {
    // Is this the index of the user's response, and is it the wrong answer
    index = index + 1;
    return UserResponse.get($scope.q.id) === index && index !== $scope.q.answer_index;
  };

  $scope.isCorrectAnswer = function(index) {
    // Is this the index of the correct answer
    index = index + 1;
    return index === $scope.q.answer_index;
  };

  $scope.saveChoice = function(index) {
    UserResponse.set($scope.q.id, index + 1);
    var a = new Answer({
      question_id: $scope.q.id,
      user_id: '1',
      answer_index: index + 1
    });
    a.$save(function() {
      // Right answer
      $scope.q.answer_index = index + 1;
      $scope.answerIndex = true;
      showLeaders();
    }, function(q) {
      // Wrong answer
      $scope.q.answer_index = q.data.answer_index;
      $scope.answerIndex = true;
      showLeaders();
    });
  };

  Question.query({
    show: true,
    select: ['question', 'answers']
  }, function(rows) {
    $scope.q = rows[0];
    $scope.answerIndex = true;
    check_start();
  });

  function check_start() {
    if ($scope.q.question == 'end') {
      showLeaders();
    }
  }

  SocketIO.on('questions', function(msg) {
    $scope.answerIndex = false;
    $scope.correct_answer = null;

    msg = JSON.parse(msg);

    if (msg.question === 'start') {
      UserResponse.reset();
      return;
    } else if (msg.question === 'end') {
      showLeaders();
      $scope.timer = 1;
      UserResponse.reset();
      return;
    }

    $scope.timer = 3;
    $ionicLoading.show({
      template: 'Next question in 3 seconds...'
    });

    var timer = setInterval(function() {
      $scope.timer--;
      $ionicLoading.show({
        template: 'Next question in ' + $scope.timer + ' seconds...'
      });

      if ($scope.timer <= 0) {
        clearInterval(timer);
        if (msg.question != 'end') {
          hideLeaders();
        }
        $ionicLoading.hide();
        $scope.q = msg;
        check_start();
        $scope.$apply();
      }
    }, 1000);
  });

  SocketIO.on('answer', function(msg) {
    var packet = JSON.parse(msg);
    $scope.correct_answer = packet;
  });

  $scope.$on('$destroy', function(event) {
    SocketIO.removeAllListeners('questions');
    SocketIO.removeAllListeners('answer');
  });

  function showLeaders() {
    $scope.show_leaders = true;
    $scope.leaders = Answer.leaders();
  }

  function hideLeaders() {
    $scope.show_leaders = false;
  }
})

.controller('RegisterCtrl', function($scope, $location, RegistrationService) {
  $scope.user = {
    name: '',
    email: '',
    password: '',
    password2: ''
  };

  $scope.$parent.logout_text = 'Logout';

  $scope.register = function() {
    RegistrationService.register($scope.user).then(function() {
      $location.path("/");
    })
  }
})

.controller('LoginCtrl', function($scope, $location, RegistrationService) {


  $scope.$parent.logout_text = 'Register';

  $scope.login = function() {
    RegistrationService.login();
  }

  $scope.facebookLogin = function() {
    console.log('test');

    FingerprintAuth.isAvailable(function (result) {

      console.log("FingerprintAuth available: " + JSON.stringify(result));
      
      // If has fingerprint device and has fingerprints registered
      if (result.isAvailable == true && result.hasEnrolledFingerprints == true) {
  
          // Check the docs to know more about the encryptConfig object :)
          var encryptConfig = {
              clientId: "myAppName",
              username: "currentUser",
              password: "currentUserPassword",
              maxAttempts: 5,
              locale: "en_US",
              dialogTitle: "Hey dude, your finger",
              dialogMessage: "Put your finger on the device",
              dialogHint: "No one will steal your identity, promised"
          }; // See config object for required parameters
  
          // Set config and success callback
          FingerprintAuth.encrypt(encryptConfig, function(_fingerResult){
              console.log("successCallback(): " + JSON.stringify(_fingerResult));
              if (_fingerResult.withFingerprint) {
                  console.log("Successfully encrypted credentials.");
                  console.log("Encrypted credentials: " + result.token);  
              } else if (_fingerResult.withBackup) {
                  console.log("Authenticated with backup password");
              }
          // Error callback
          }, function(err){
                  if (err === "Cancelled") {
                  console.log("FingerprintAuth Dialog Cancelled!");
              } else {
                  console.log("FingerprintAuth Error: " + err);
              }
          });
      }}, function (message) {
        console.log("isAvailableError(): " + message);
    });
  }

})

.controller('TestCtrl', function($scope, $ionicPopup, $location, $sce, RegistrationService){
  console.log('test');
  var user = $scope.user;
  $scope.getAccounts = function(){
    console.log('getting accounts');
    RegistrationService.getAccounts().then(function(result){
      $scope.accountList = result.data
      console.log(result.data);
    });
  }

  $scope.createTrans = function(index){
    var account = $scope.accountList[index];
    console.log(index);
    console.log(account);
    RegistrationService.createTrans(account).then(function(){
        var alertPopup = $ionicPopup.alert({
          title: 'Transaction Created',
          template: 'It will be given a name and salesforce id on sync.'
        });
      
        alertPopup.then(function(res) {
          console.log('Thank you for not eating my delicious ice cream cone');
        });
    });
  }

  $scope.getRandomFile = function(){
    RegistrationService.getFile("068g0000001dkgqAAA").then(function(resultFile){
      var decoder = new TextDecoder('windows-1252')  
      //var decoder = new TextDecoder();
      var base64String;
      var decodedString;
      var reader = new FileReader();
      var textBlob;
      var fileurl;
      var xhr = new XMLHttpRequest();
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

      reader.addEventListener("load", ()=>{
        window.open(reader.result);
        $scope.content = $sce.trustAsResourceUrl(reader.result)
      }, false)


      console.log(resultFile);
      $file = resultFile.data

      console.log($file.versiondata);
      base64String = decoder.decode(new Uint8Array($file.versiondata));
      console.log(base64String);
      //decodedString = atob(base64String);
      base64Array = Base64Binary.decodeArrayBuffer(base64String);
      decodedString = decoder.decode(base64Array);
      //decodedString = new Buffer(base64String, 'base64').toString('ascii');
      console.log(decodedString);

      textBlob = new Blob([decodedString], {type: 'application/pdf'});

      xhr.open('GET', './api/exportdoc/report_'+id, true);
      xhr.responseType = 'arraybuffer';
      xhr.onload = function(e) {
         if (this.status == 200) {
            var blob=new Blob([this.textBlob], {type:"application/pdf"});
            var link=document.createElement('a');
            link.href=window.URL.createObjectURL(blob);
            link.download="Report_"+new Date()+".pdf";
            link.click();
         }
      };
    xhr.send();

      //reader.readAsDataURL(textBlob);
      //fileurl = URL.createObjectURL(textBlob);

      //window.open($sce.trustAsResourceUrl(fileurl));
      //$scope.content = $sce.trustAsResourceUrl(fileurl)

      //$window.show()
    });
  }
  
})

.controller('SfAuthCtrl', function($scope, $location, RegistrationService){
  console.log('test authing');
  $scope.accountList = undefined;
  RegistrationService.sfAuth().then(function(){
    $location.path('/test');
    window.history.pushState({}, document.title, "/" + "#/sfAuth");
    //$location.replaceState('test');
    //this.location.href = 'https://' + this.location.host + '/#/test'
  });
})

.controller('LeadersCtrl', function($scope, SocketIO, Answer) {
  $scope.leaders = Answer.leaders();

  SocketIO.on('answer', function(msg) {
    $scope.leaders = Answer.leaders();
  });

  $scope.$on('$destroy', function(event) {
    SocketIO.removeAllListeners('answer');
  });

})

.controller('HomeCtrl', function($scope, $location) {

})