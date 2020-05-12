angular.module('starter.controllers', [])

.controller('AppCtrl', function($scope, $location, RegistrationService) {
  $scope.logout = function() {
    RegistrationService.logout();
    $location.path("/register");
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